/* Versioned file operations for authenticated NASFS sessions. */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging/log.h"
#include "network/session_internal.h"

#define MAX_PENDING_PUT_WRITES 4u

typedef struct {
  uv_fs_t req;
  uv_buf_t buf;
  client_session_t* session;
  uint64_t storage_sequence;
} file_request_t;

static void finish_put(client_session_t* session);
static int submit_checkpoint(client_session_t* session);

static void close_active(client_session_t* session) {
  nasfs_file_service_t* files = &session->files;
  if (files->active_fd >= 0) {
    uv_fs_t request;
    int rc = uv_fs_close(NULL, &request, files->active_fd, NULL);
    uv_fs_req_cleanup(&request);
    files->active_fd = -1;
    if (rc < 0) log_all(LOG_WARNING, "File close failed: %s", uv_strerror(rc));
  }
  if (!files->resumable || files->finalized)
    nasfs_version_discard(files->store, files->staging);
  files->staging[0] = '\0';
  nasfs_version_release(files->store, files->reserved);
  files->reserved = 0;
  files->resumable = 0;
}

int nasfs_file_service_close(client_session_t* session) {
  if (session->files.pending_fs) return 0;
  if (session->files.put_draining) {
    finish_put(session);
    return 0;
  }
  if (submit_checkpoint(session)) return 0;
  close_active(session);
  return 1;
}

int nasfs_file_service_draining(const client_session_t* session) {
  return session->files.put_draining || session->files.busy ||
         session->files.checkpoint_pending;
}

int nasfs_file_service_at_capacity(const client_session_t* session) {
  return session->files.pending_fs >= MAX_PENDING_PUT_WRITES;
}

static void abort_transfer(client_session_t* session) {
  session_close((uv_handle_t*)&session->handle);
}

static void send_error(client_session_t* session, const char* message) {
  session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t*)message,
                     strlen(message), 1);
}

static void io_finished(client_session_t* session) {
  nasfs_file_service_t* files = &session->files;
  files->pending_fs--;
  if (session->state == SESSION_STATE_ERROR) {
    session_finish_close(session);
    return;
  }
  if (!files->pending_fs) {
    if (files->put_draining) {
      finish_put(session);
    } else if (files->checkpoint_pending && !submit_checkpoint(session)) {
      abort_transfer(session);
      return;
    }
  }
  if (session->state != SESSION_STATE_ERROR &&
      !nasfs_file_service_draining(session))
    process_session_frames(session);
  session_resume_read(session);
}

typedef struct {
  uv_work_t req;
  client_session_t* session;
  int status;
} checkpoint_request_t;

static void run_checkpoint(uv_work_t* req) {
  checkpoint_request_t* work = req->data;
  nasfs_file_service_t* files = &work->session->files;
  work->status = nasfs_version_checkpoint(files->store, &files->attempt,
                                          files->active_fd, files->sequence);
}

static void on_checkpoint(uv_work_t* req, int status) {
  checkpoint_request_t* work = req->data;
  client_session_t* session = work->session;
  nasfs_file_service_t* files = &session->files;
  int rc = status < 0 ? status : work->status;
  free(work);
  files->checkpoint_pending = 0;
  if (rc == 0) {
    files->durable_sequence = files->sequence;
    files->checkpoint_bytes = 0;
    files->checkpoint_at = uv_now(session->handle.loop);
  } else {
    files->write_failed = 1;
    log_all(LOG_WARNING, "PUT checkpoint failed: %s", uv_strerror(rc));
    abort_transfer(session);
  }
  io_finished(session);
}

/* Only complete writes may advance the journal. Reading stays paused until
 * the worker has synchronized the staging fd and committed the position. */
static int submit_checkpoint(client_session_t* session) {
  nasfs_file_service_t* files = &session->files;
  if (!files->resumable || files->active_fd < 0 || files->write_failed ||
      files->sequence == files->durable_sequence || files->put_draining)
    return 0;
  files->checkpoint_pending = 1;
  if (files->pending_fs) return 1;

  checkpoint_request_t* work = malloc(sizeof(*work));
  int rc = UV_ENOMEM;
  if (work) {
    work->session = session;
    work->req.data = work;
    rc = uv_queue_work(session->handle.loop, &work->req, run_checkpoint,
                       on_checkpoint);
    if (!rc) {
      files->pending_fs++;
      return 1;
    }
    free(work);
  }
  files->checkpoint_pending = 0;
  files->write_failed = 1;
  log_all(LOG_WARNING, "Cannot start PUT checkpoint: %s", uv_strerror(rc));
  return 0;
}

void nasfs_file_service_on_clock(client_session_t* session) {
  nasfs_file_service_t* files = &session->files;
  if (session->state == SESSION_STATE_RECEIVING_FILE && files->resumable &&
      !files->checkpoint_pending &&
      uv_now(session->handle.loop) - files->checkpoint_at >= 1000 &&
      files->sequence != files->durable_sequence && !submit_checkpoint(session))
    abort_transfer(session);
}

static void free_request(file_request_t* req) {
  uv_fs_req_cleanup(&req->req);
  free(req->buf.base);
  free(req);
}

static file_request_t* make_request(client_session_t* session, unsigned size) {
  file_request_t* req = malloc(sizeof(*req));
  if (req) {
    req->buf = uv_buf_init(malloc(size), size);
    if (req->buf.base) {
      req->session = session;
      req->req.data = req;
      return req;
    }
    free(req);
  }
  abort_transfer(session);
  return NULL;
}

static void on_put_write(uv_fs_t* req) {
  file_request_t* ctx = req->data;
  client_session_t* session = ctx->session;
  if (req->result < 0 || (size_t)req->result != ctx->buf.len) {
    session->files.put_draining = 0;
    session->files.write_failed = 1;
    log_all(LOG_ERROR, "PUT: Write failed: %s",
            req->result < 0 ? uv_strerror((int)req->result) : "short write");
    abort_transfer(session);
  }
  free_request(ctx);
  io_finished(session);
}

static void put_data(client_session_t* session, const nasfs_frame_t* frame) {
  nasfs_file_service_t* files = &session->files;
  int64_t offset;
  uint32_t length;
  if (session->state != SESSION_STATE_RECEIVING_FILE || files->active_fd < 0 ||
      !files->has_expected ||
      nasfs_version_is_parity(&files->header, files->sequence) !=
          (frame->type == NASFS_CMD_PUT_PARITY) ||
      nasfs_version_record(&files->header, files->sequence, &offset, &length) <
          0 ||
      files->expected.seq_num != files->sequence ||
      files->expected.size != length || frame->payload_len != length) {
    abort_transfer(session);
    return;
  }
  uint8_t digest[32];
  if (nasfs_version_hash_block(files->header.hash, frame->payload, length,
                               digest) != 0 ||
      sodium_memcmp(digest, files->expected.hash, sizeof(digest)) != 0) {
    send_error(session, "Hash verification failed");
    abort_transfer(session);
    return;
  }
  file_request_t* ctx = make_request(session, length + NASFS_BLOCK_META_SIZE);
  if (!ctx) return;
  protocol_encode_block_meta((uint8_t*)ctx->buf.base, &files->expected);
  memcpy(ctx->buf.base + NASFS_BLOCK_META_SIZE, frame->payload, length);
  int rc = uv_fs_write(session->handle.loop, &ctx->req, files->active_fd,
                       &ctx->buf, 1, offset, on_put_write);
  if (rc < 0) {
    free_request(ctx);
    abort_transfer(session);
    return;
  }
  nasfs_version_index_add(&files->index, &files->expected);
  files->pending_fs++;
  files->sequence++;
  files->has_expected = 0;
  if (files->resumable) {
    files->checkpoint_bytes += ctx->buf.len;
    if (files->checkpoint_bytes >= 16u * 1024u * 1024u ||
        uv_now(session->handle.loop) - files->checkpoint_at >= 1000)
      submit_checkpoint(session);
  }
}

typedef struct {
  uv_work_t req;
  client_session_t* session;
  int status;
} publish_request_t;

static void publish_version(uv_work_t* req) {
  publish_request_t* work = req->data;
  nasfs_file_service_t* files = &work->session->files;
  uint8_t prefix[NASFS_VERSION_DATA_OFFSET];
  nasfs_version_encode(prefix, &files->header);
  memcpy(prefix + NASFS_VERSION_HEADER_SIZE, files->proof,
         sizeof(files->proof));

  uv_fs_t write_req;
  uv_buf_t bytes = uv_buf_init((char*)prefix, sizeof(prefix));
  int rc = uv_fs_write(NULL, &write_req, files->active_fd, &bytes, 1, 0, NULL);
  uv_fs_req_cleanup(&write_req);
  if (rc == (int)sizeof(prefix)) {
    rc = uv_fs_fsync(NULL, &write_req, files->active_fd, NULL);
    uv_fs_req_cleanup(&write_req);
  } else if (rc >= 0) {
    rc = UV_EIO;
  }
  if (!rc) {
    rc = nasfs_version_publish(files->store, files->staging, files->name,
                               &files->header, files->proof + 32,
                               nasfs_version_file_size(&files->header),
                               files->resumable ? &files->attempt : NULL);
    if (!files->resumable) files->reserved = 0;
    files->finalized = rc == 0 || rc == UV_EEXIST || rc == UV_ENOSPC;
  }
  int closed = uv_fs_close(NULL, &write_req, files->active_fd, NULL);
  uv_fs_req_cleanup(&write_req);
  if (closed < 0)
    log_all(LOG_WARNING, "File close failed: %s", uv_strerror(closed));
  work->status = rc;
}

static void put_result(client_session_t* session, int result) {
  session->files.put_draining = 0;
  close_active(session);
  if (session->state == SESSION_STATE_ERROR) {
    session_finish_close(session);
    return;
  }
  session->state = SESSION_STATE_AUTHENTICATED;
  uint8_t status = NASFS_PUT_PUBLICATION_FAILED;
  if (result == 0) status = NASFS_PUT_PUBLISHED;
  if (result == UV_EEXIST) status = NASFS_PUT_CONFLICT;
  if (result == UV_ENOSPC) status = NASFS_PUT_QUOTA;
  if (result == UV_EAGAIN) status = NASFS_PUT_UNCERTAIN;
  if (result < 0)
    log_all(LOG_WARNING, "PUT: Publication failed: %s", uv_strerror(result));
  session_send_frame(session, NASFS_CMD_PUT_RESULT, &status, sizeof(status), 1);
}

static void on_published(uv_work_t* req, int status) {
  publish_request_t* work = req->data;
  client_session_t* session = work->session;
  int result = status < 0 ? status : work->status;
  free(work);
  if (status == 0) session->files.active_fd = -1;
  session->files.pending_fs--;
  int closing = session->state == SESSION_STATE_ERROR;
  put_result(session, result);
  if (!closing && session->state != SESSION_STATE_ERROR)
    process_session_frames(session);
}

static void finish_put(client_session_t* session) {
  publish_request_t* work = malloc(sizeof(*work));
  if (!work) {
    put_result(session, UV_ENOMEM);
    return;
  }
  work->session = session;
  work->req.data = work;
  int rc = uv_queue_work(session->handle.loop, &work->req, publish_version,
                         on_published);
  if (rc < 0) {
    free(work);
    put_result(session, rc);
    return;
  }
  session->files.pending_fs++;
}

static void put_done(client_session_t* session, const nasfs_frame_t* frame) {
  nasfs_file_service_t* files = &session->files;
  if (session->state != SESSION_STATE_RECEIVING_FILE || files->active_fd < 0 ||
      files->has_expected || frame->payload_len != NASFS_VERSION_PROOF_SIZE ||
      files->sequence != nasfs_version_record_count(&files->header) ||
      (files->resumable &&
       sodium_memcmp(frame->payload + 32, files->attempt.digest, 32) != 0)) {
    abort_transfer(session);
    return;
  }
  uint8_t root[32];
  nasfs_version_index_final(&files->index, root);
  if (sodium_memcmp(root, frame->payload, sizeof(root)) != 0 ||
      nasfs_version_verify(&files->header, frame->payload,
                           files->trusted_author) < 0) {
    uint8_t status = NASFS_PUT_PUBLICATION_FAILED;
    session_send_frame(session, NASFS_CMD_PUT_RESULT, &status, sizeof(status),
                       1);
    abort_transfer(session);
    return;
  }
  memcpy(files->proof, frame->payload, sizeof(files->proof));
  files->put_draining = 1;
  if (!files->pending_fs) finish_put(session);
}

static void on_get_read(uv_fs_t* req) {
  file_request_t* ctx = req->data;
  client_session_t* session = ctx->session;
  nasfs_file_service_t* files = &session->files;
  if (session->state != SESSION_STATE_ERROR) {
    const uint8_t* row = (const uint8_t*)ctx->buf.base;
    nasfs_block_meta_t meta;
    int64_t offset;
    uint32_t length;
    if (req->result < 0 || (size_t)req->result != ctx->buf.len ||
        nasfs_version_record(&files->header, ctx->storage_sequence, &offset,
                             &length) < 0 ||
        protocol_decode_block_meta(row, NASFS_BLOCK_META_SIZE, &meta) < 0 ||
        meta.seq_num != ctx->storage_sequence || meta.size != length) {
      abort_transfer(session);
    } else if (files->send_index) {
      files->sequence++;
      session_send_frame(session, NASFS_CMD_GET_INDEX, row,
                         NASFS_BLOCK_META_SIZE, 1);
    } else if (files->repairing) {
      files->repair_pos++;
      session_send_frame(session, NASFS_CMD_GET_REPAIR_DATA, row, ctx->buf.len,
                         0);
    } else {
      files->sequence++;
      files->waiting_ack = files->header.ecc != NASFS_ECC_OFF;
      session_send_frame(session, NASFS_CMD_GET_BLOCK_META, row,
                         NASFS_BLOCK_META_SIZE, 1);
      session_send_frame(session, NASFS_CMD_GET_DATA,
                         row + NASFS_BLOCK_META_SIZE, length, 0);
    }
  }
  free_request(ctx);
  io_finished(session);
}

void nasfs_file_service_get_next(client_session_t* session) {
  nasfs_file_service_t* files = &session->files;
  if (session->state != SESSION_STATE_SENDING_FILE || files->active_fd < 0)
    return;
  if (files->send_index &&
      files->sequence == nasfs_version_record_count(&files->header)) {
    files->send_index = 0;
    files->sequence = files->first;
  }
  if (files->repairing && files->repair_pos == files->repair_end) {
    files->repairing = 0;
    session_send_frame(session, NASFS_CMD_GET_REPAIR_DONE, NULL, 0, 1);
    return;
  }
  if (files->waiting_ack && !files->repairing) return;
  if (!files->send_index && !files->repairing &&
      files->sequence == files->end) {
    session->state = SESSION_STATE_AUTHENTICATED;
    close_active(session);
    session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0, 1);
    return;
  }
  uint64_t sequence = files->send_index  ? files->sequence
                      : files->repairing ? files->repair_pos
                                         : nasfs_version_data_sequence(
                                               &files->header, files->sequence);
  int64_t offset;
  uint32_t length;
  if (nasfs_version_record(&files->header, sequence, &offset, &length) < 0) {
    abort_transfer(session);
    return;
  }
  file_request_t* ctx = make_request(
      session, NASFS_BLOCK_META_SIZE + (files->send_index ? 0 : length));
  if (!ctx) return;
  ctx->storage_sequence = sequence;
  int rc = uv_fs_read(session->handle.loop, &ctx->req, files->active_fd,
                      &ctx->buf, 1, offset, on_get_read);
  if (rc < 0) {
    free_request(ctx);
    abort_transfer(session);
    return;
  }
  files->pending_fs++;
}

static void advance_get(client_session_t* session, const nasfs_frame_t* frame) {
  nasfs_file_service_t* files = &session->files;
  if (session->state != SESSION_STATE_SENDING_FILE || !files->waiting_ack ||
      files->repairing || frame->payload_len != 0) {
    abort_transfer(session);
    return;
  }
  if (frame->type == NASFS_CMD_GET_ADVANCE) {
    files->waiting_ack = 0;
    files->repair_sent = 0;
  } else {
    uint64_t start;
    unsigned data, parity;
    if (files->repair_sent || files->sequence == 0 ||
        nasfs_version_group(&files->header, files->sequence - 1, &start, &data,
                            &parity) < 0) {
      abort_transfer(session);
      return;
    }
    files->repair_pos = nasfs_version_data_sequence(&files->header, start);
    files->repair_end = files->repair_pos + data + parity;
    files->repairing = 1;
    files->repair_sent = 1;
  }
  nasfs_file_service_get_next(session);
}

typedef struct {
  uv_work_t req;
  client_session_t* session;
  nasfs_cmd_type_t command;
  uint64_t start;
  uint64_t length;
  int result;
  int saved_result;
  uint8_t bytes[NASFS_VERSION_DATA_OFFSET];
} open_request_t;

static void open_object(uv_work_t* req) {
  open_request_t* work = req->data;
  nasfs_file_service_t* files = &work->session->files;
  switch (work->command) {
    case NASFS_CMD_PUT_REQ: {
      int64_t size = nasfs_version_file_size(&files->header);
      int rc = nasfs_version_reserve(files->store, size);
      if (rc == 0) {
        files->reserved = size;
        rc = nasfs_version_stage(files->store, files->staging);
      }
      work->result = rc;
      break;
    }
    case NASFS_CMD_PUT_RESUME:
      work->result = nasfs_version_attempt_open(
          files->store, &files->attempt, &files->header, files->name,
          files->staging, &files->sequence, &work->saved_result, &files->index);
      break;
    case NASFS_CMD_GET_REQ: {
      int fd =
          nasfs_version_open(files->store, files->header.id, files->version);
      if (fd < 0) {
        work->result = fd;
        return;
      }
      uv_fs_t read_req;
      uv_buf_t buffer = uv_buf_init((char*)work->bytes, sizeof(work->bytes));
      int rc = uv_fs_read(NULL, &read_req, fd, &buffer, 1, 0, NULL);
      uv_fs_req_cleanup(&read_req);
      if (rc != (int)sizeof(work->bytes)) {
        close(fd);
        work->result = UV_EIO;
      } else {
        work->result = fd;
      }
      break;
    }
    case NASFS_CMD_RESOLVE:
      work->result = nasfs_version_resolve(files->store, files->name,
                                           work->bytes, work->bytes + 16);
      break;
    case NASFS_CMD_COLLECT:
      work->result = nasfs_version_collect(files->store);
      break;
    default:
      work->result = UV_EINVAL;
      break;
  }
}

static void start_get(client_session_t* session, const open_request_t* work) {
  nasfs_file_service_t* files = &session->files;
  nasfs_version_header_t header;
  if (nasfs_version_decode(&header, work->bytes, NASFS_VERSION_HEADER_SIZE) <
          0 ||
      sodium_memcmp(header.id, files->header.id, sizeof(header.id)) != 0 ||
      sodium_memcmp(work->bytes + NASFS_VERSION_HEADER_SIZE + 32,
                    files->version, sizeof(files->version)) != 0) {
    send_error(session, "Unsupported transfer format or invalid version");
    close_active(session);
    return;
  }
  uint64_t start = work->start, length = work->length;
  if (start > header.size ||
      (length != UINT64_MAX && length > header.size - start)) {
    send_error(session, "Invalid version range");
    close_active(session);
    return;
  }
  if (length == UINT64_MAX) length = header.size - start;
  files->header = header;
  files->first = start == header.size ? nasfs_version_block_count(&header)
                                      : start / header.block_size;
  files->end = files->first;
  if (length) {
    uint64_t end = start + length;
    files->end = end / header.block_size + (end % header.block_size != 0);
  }
  files->waiting_ack = 0;
  files->repairing = 0;
  files->repair_sent = 0;
  files->send_index = nasfs_version_record_count(&header) &&
                      (files->force_index || start != 0 ||
                       length != header.size || header.ecc != NASFS_ECC_OFF);
  files->sequence = files->send_index ? 0 : files->first;
  session->state = SESSION_STATE_SENDING_FILE;
  session_send_frame(session, NASFS_CMD_GET_ACK, work->bytes,
                     sizeof(work->bytes), 1);
  nasfs_file_service_get_next(session);
}

static void on_opened(uv_work_t* req, int status) {
  open_request_t* work = req->data;
  client_session_t* session = work->session;
  nasfs_file_service_t* files = &session->files;
  int rc = status < 0 ? status : work->result;
  files->busy = 0;
  int uploading = work->command == NASFS_CMD_PUT_REQ ||
                  work->command == NASFS_CMD_PUT_RESUME;
  if ((uploading || work->command == NASFS_CMD_GET_REQ) && rc >= 0)
    files->active_fd = rc;
  if (session->state != SESSION_STATE_ERROR) {
    if (work->command == NASFS_CMD_RESOLVE && (rc == 0 || rc == UV_ENOENT)) {
      session_send_frame(session, NASFS_CMD_RESOLVED, work->bytes,
                         rc == 0 ? 48 : 0, 1);
    } else if (work->command == NASFS_CMD_PUT_RESUME && rc == UV_EALREADY) {
      files->staging[0] = '\0';
      int saved = work->saved_result;
      put_result(session, saved == 1 ? 0 : saved == 2 ? UV_EEXIST : UV_ENOSPC);
    } else if (rc < 0 && uploading) {
      if (rc == UV_EACCES || rc == UV_EBUSY || rc == UV_ETIMEDOUT) {
        send_error(session, "Upload attempt unavailable for this session");
      } else {
        put_result(session, rc);
      }
    } else if (rc < 0) {
      send_error(session,
                 rc == UV_ENOENT ? "Version unavailable" : uv_strerror(rc));
    } else if (uploading) {
      files->has_expected = 0;
      files->write_failed = 0;
      files->durable_sequence = files->sequence;
      files->checkpoint_at = uv_now(session->handle.loop);
      files->checkpoint_bytes = 0;
      if (!files->resumable) nasfs_version_index_init(&files->index);
      session->state = SESSION_STATE_RECEIVING_FILE;
      uint8_t checkpoint[8];
      protocol_store_u64(checkpoint, files->sequence);
      session_send_frame(session, NASFS_CMD_PUT_ACK, checkpoint,
                         files->resumable ? sizeof(checkpoint) : 0, 1);
    } else if (work->command == NASFS_CMD_GET_REQ) {
      start_get(session, work);
    } else {
      session_send_frame(session, NASFS_CMD_COLLECTED, NULL, 0, 1);
    }
  }
  free(work);
  io_finished(session);
}

static void submit_open(client_session_t* session, nasfs_cmd_type_t command,
                        uint64_t start, uint64_t length) {
  open_request_t* work = malloc(sizeof(*work));
  if (!work) {
    abort_transfer(session);
    return;
  }
  work->session = session;
  work->command = command;
  work->start = start;
  work->length = length;
  work->saved_result = 0;
  work->req.data = work;
  int rc =
      uv_queue_work(session->handle.loop, &work->req, open_object, on_opened);
  if (rc < 0) {
    log_all(LOG_ERROR, "Open request submission failed: %s", uv_strerror(rc));
    free(work);
    abort_transfer(session);
    return;
  }
  session->files.pending_fs++;
  session->files.busy = 1;
}

void nasfs_file_service_dispatch(client_session_t* session,
                                 nasfs_frame_t frame) {
  nasfs_file_service_t* files = &session->files;
  if (!files->access.subject) {
    abort_transfer(session);
    return;
  }

  if (frame.type == NASFS_CMD_GET_ADVANCE ||
      frame.type == NASFS_CMD_GET_REPAIR) {
    advance_get(session, &frame);
    return;
  }
  if (frame.type == NASFS_CMD_PUT_DATA || frame.type == NASFS_CMD_PUT_PARITY) {
    put_data(session, &frame);
    return;
  }
  if (frame.type == NASFS_CMD_PUT_DONE) {
    put_done(session, &frame);
    return;
  }
  if (frame.type == NASFS_CMD_PUT_BLOCK_META) {
    if (session->state != SESSION_STATE_RECEIVING_FILE || files->has_expected ||
        protocol_decode_block_meta(frame.payload, frame.payload_len,
                                   &files->expected) < 0) {
      abort_transfer(session);
    } else {
      files->has_expected = 1;
    }
    return;
  }
  if (session->state != SESSION_STATE_AUTHENTICATED) {
    abort_transfer(session);
    return;
  }

  uint64_t start = 0, length = 0;
  switch (frame.type) {
    case NASFS_CMD_RESOLVE:
      if (nasfs_storage_parse_name(frame.payload, frame.payload_len,
                                   files->name) < 0) {
        send_error(session, "Invalid file name");
        return;
      }
      break;
    case NASFS_CMD_PUT_RESUME:
    case NASFS_CMD_PUT_REQ: {
      files->resumable = frame.type == NASFS_CMD_PUT_RESUME;
      files->finalized = 0;
      files->sequence = 0;
      files->write_failed = 0;
      files->checkpoint_pending = 0;
      size_t prefix = files->resumable ? 64 : 0;
      const size_t name_offset = prefix + 1 + NASFS_VERSION_HEADER_SIZE;
      if (frame.payload_len <= name_offset ||
          (frame.payload[prefix] != NASFS_VERSION_REQUEST &&
           frame.payload[prefix] != NASFS_VERSION_EXCLUSIVE) ||
          nasfs_version_decode(&files->header, frame.payload + prefix + 1,
                               NASFS_VERSION_HEADER_SIZE) < 0) {
        send_error(session, "Unsupported transfer format");
        return;
      }
      if (nasfs_storage_parse_name(frame.payload + name_offset,
                                   frame.payload_len - name_offset,
                                   files->name) < 0) {
        send_error(session, "Invalid file name");
        return;
      }
      if (frame.payload[prefix] == NASFS_VERSION_EXCLUSIVE &&
          !sodium_is_zero(files->header.parent, sizeof(files->header.parent))) {
        send_error(session, "Create-only upload requires an unused name");
        return;
      }
      if (files->resumable) {
        memcpy(files->attempt.token, frame.payload, 32);
        memcpy(files->attempt.digest, frame.payload + 32, 32);
        memcpy(files->attempt.scope, files->access.scope, 32);
      }
      break;
    }
    case NASFS_CMD_GET_REQ:
      if (frame.payload_len != NASFS_VERSION_GET_SIZE ||
          (frame.payload[0] != NASFS_VERSION_REQUEST &&
           frame.payload[0] != NASFS_VERSION_GET_INDEXED)) {
        send_error(session, "Unsupported transfer format");
        return;
      }
      files->force_index = frame.payload[0] == NASFS_VERSION_GET_INDEXED;
      memcpy(files->header.id, frame.payload + 1, 16);
      memcpy(files->version, frame.payload + 17, 32);
      start = protocol_load_u64(frame.payload + 49);
      length = protocol_load_u64(frame.payload + 57);
      break;
    case NASFS_CMD_COLLECT:
      if (frame.payload_len != 0) {
        abort_transfer(session);
        return;
      }
      break;
    default:
      abort_transfer(session);
      return;
  }
  submit_open(session, frame.type, start, length);
}
