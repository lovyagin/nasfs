/* File operations for authenticated NASFS sessions. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config/config.h"
#include "logging/log.h"
#include "network/session_internal.h"

#define MAX_PENDING_PUT_WRITES 4
#define IO_CHUNK_SIZE ((size_t)global_config.block_size)
/* Encrypted file header: [8 bytes native-endian size][16 bytes salt]
 * [cipher plus record-length flag][hash]. Marked files store a big-endian
 * uint32_t ciphertext length before each record. */
#define FILE_HEADER_SIZE NASFS_FILE_METADATA_SIZE
#define MAX_RECORD_SIZE (4194304 + NASFS_CIPHER_OVERHEAD)
#define NASFS_CIPHER_OVERHEAD \
  16 /* MAC tag bytes — true for all supported ciphers */
typedef struct {
  uv_fs_t req;
  uv_buf_t buf;
  client_session_t* session;
} nasfs_fs_ctx_t;

static int close_active_file(client_session_t* session) {
  if (session->files.active_fd == -1) return 0;

  uv_fs_t req;
  int rc =
      uv_fs_close(session->handle.loop, &req, session->files.active_fd, NULL);
  uv_fs_req_cleanup(&req);
  session->files.active_fd = -1;
  if (rc < 0) {
    log_all(LOG_ERROR, "File close failed: %s", uv_strerror(rc));
  }
  return rc;
}

static void discard_upload(client_session_t* session) {
  if (!session->files.upload_temp_name[0]) return;
  int rc = nasfs_storage_discard_upload(session->files.storage,
                                        session->files.upload_temp_name);
  if (rc < 0) {
    log_all(LOG_ERROR, "PUT: Temporary file cleanup failed: %s",
            uv_strerror(rc));
  }
  session->files.upload_temp_name[0] = '\0';
}

static void finish_put(client_session_t* session);

int nasfs_file_service_close(client_session_t* session) {
  if (session->files.pending_fs != 0) return 0;
  if (session->files.put_draining) {
    finish_put(session);
    return 0;
  }
  close_active_file(session);
  discard_upload(session);
  return 1;
}

int nasfs_file_service_draining(const client_session_t* session) {
  return session->files.put_draining;
}

int nasfs_file_service_at_capacity(const client_session_t* session) {
  return session->files.pending_fs >= MAX_PENDING_PUT_WRITES;
}

static void release_fs_request(nasfs_fs_ctx_t* ctx) {
  uv_fs_req_cleanup(&ctx->req);
  free(ctx->buf.base);
  free(ctx);
}

static void complete_publication(client_session_t* session, int result) {
  session->files.put_draining = 0;
  if (result < 0) {
    log_all(LOG_ERROR, "PUT: Publication failed: %s", uv_strerror(result));
    close_active_file(session);
    discard_upload(session);
  } else {
    session->files.upload_temp_name[0] = '\0';
    log_all(LOG_INFO, "Upload complete.");
  }

  if (session->state == SESSION_STATE_ERROR) {
    session_finish_close(session);
    return;
  }
  uint8_t status =
      result == 0 ? NASFS_PUT_PUBLISHED : NASFS_PUT_PUBLICATION_FAILED;
  session->state = SESSION_STATE_AUTHENTICATED;
  session_send_frame(session, NASFS_CMD_PUT_RESULT, &status, sizeof(status), 1);
}

typedef struct {
  uv_work_t req;
  client_session_t* session;
  uv_file fd;
  int result;
  int close_result;
} nasfs_publish_ctx_t;

static void publish_upload(uv_work_t* req) {
  nasfs_publish_ctx_t* ctx = req->data;
  // These upload fields stay immutable until on_upload_published().
  const client_session_t* session = ctx->session;
  uint8_t trailer[sizeof(uint32_t) + NASFS_MANIFEST_SIZE] = {0};
  memcpy(trailer + sizeof(uint32_t), session->files.upload_manifest,
         NASFS_MANIFEST_SIZE);
  uv_fs_t request;
  uv_buf_t buf = uv_buf_init((char*)trailer, sizeof(trailer));
  int written = uv_fs_write(NULL, &request, ctx->fd, &buf, 1,
                            (int64_t)session->files.file_offset, NULL);
  uv_fs_req_cleanup(&request);
  ctx->close_result = uv_fs_close(NULL, &request, ctx->fd, NULL);
  uv_fs_req_cleanup(&request);
  int rc = ctx->close_result;
  if (rc == 0 && written != (int)sizeof(trailer)) rc = UV_EIO;
  if (rc == 0) {
    rc = nasfs_storage_publish_upload(
        session->files.storage, session->files.upload_temp_name,
        session->files.upload_name, session->files.upload_exclusive);
  }
  ctx->result = rc;
}

static void on_upload_published(uv_work_t* req, int status) {
  nasfs_publish_ctx_t* ctx = req->data;
  client_session_t* session = ctx->session;
  int result = status < 0 ? status : ctx->result;
  if (status < 0) {
    session->files.active_fd = ctx->fd;
  } else if (ctx->close_result < 0) {
    log_all(LOG_ERROR, "File close failed: %s", uv_strerror(ctx->close_result));
  }
  free(ctx);
  session->files.pending_fs--;
  int closing = session->state == SESSION_STATE_ERROR;
  complete_publication(session, result);
  if (!closing && session->state != SESSION_STATE_ERROR)
    process_session_frames(session);
}

static void finish_put(client_session_t* session) {
  nasfs_publish_ctx_t* ctx = malloc(sizeof(*ctx));
  if (!ctx) {
    complete_publication(session, UV_ENOMEM);
    return;
  }
  ctx->session = session;
  ctx->fd = session->files.active_fd;
  ctx->req.data = ctx;
  int rc = uv_queue_work(session->handle.loop, &ctx->req, publish_upload,
                         on_upload_published);
  if (rc < 0) {
    free(ctx);
    complete_publication(session, rc);
    return;
  }
  session->files.active_fd = -1;
  session->files.pending_fs++;
}

static void finish_file_request(client_session_t* session) {
  session->files.pending_fs--;
  if (session->state == SESSION_STATE_ERROR) {
    session_finish_close(session);
    return;
  }
  if (session->files.put_draining && session->files.pending_fs == 0) {
    finish_put(session);
    if (session->state == SESSION_STATE_ERROR) return;
    process_session_frames(session);
  }
  session_resume_read(session);
}

static void finish_fs_request(nasfs_fs_ctx_t* ctx) {
  client_session_t* session = ctx->session;
  release_fs_request(ctx);
  finish_file_request(session);
}

static void fs_submission_failed(nasfs_fs_ctx_t* ctx, int rc) {
  client_session_t* session = ctx->session;
  log_all(LOG_ERROR, "File request submission failed: %s", uv_strerror(rc));
  release_fs_request(ctx);
  session_close((uv_handle_t*)&session->handle);
}

static void on_put_fs_write(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = req->data;
  client_session_t* session = ctx->session;
  if (req->result < 0 || (size_t)req->result != ctx->buf.len) {
    session->files.put_draining = 0;
    log_all(LOG_ERROR, "PUT: Write failed: %s",
            req->result < 0 ? uv_strerror((int)req->result) : "short write");
    session_close((uv_handle_t*)&session->handle);
  }
  finish_fs_request(ctx);
}

static void on_put_fs_open(client_session_t* session, int result,
                           int header_result) {
  if (result < 0) {
    log_all(LOG_ERROR, "PUT: Open failed: %s", uv_strerror((int)result));
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t*)"Open failed",
                       11, 1);
  } else {
    session->files.active_fd = (uv_file)result;
    if (session->files.file_encryption_enabled) {
      const size_t header_size = FILE_HEADER_SIZE + NASFS_OWNER_SLOT_V1_SIZE;
      if (header_result != (int)header_size) {
        log_all(LOG_ERROR, "PUT: Header write failed: wrote %d bytes",
                header_result);
        session->state = SESSION_STATE_AUTHENTICATED;
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Header write failed", 19, 1);
        close_active_file(session);
        discard_upload(session);
        return;
      }
      session->files.file_offset = header_size;
      protocol_manifest_init(
          &session->files.manifest, session->files.upload_name,
          session->files.expected_plaintext_size, session->files.file_salt,
          session->files.file_cipher_algo | NASFS_FILE_CIPHER_PORTABLE,
          session->files.file_hash_algo);
      protocol_manifest_owner_slot(&session->files.manifest,
                                   session->files.owner_slot,
                                   sizeof(session->files.owner_slot));
    } else {
      session->files.file_offset = 0;
    }
    session_send_frame(session, NASFS_CMD_PUT_ACK, NULL, 0, 1);
  }
}

static void on_get_fs_read(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = (nasfs_fs_ctx_t*)req->data;
  client_session_t* session = ctx->session;

  if (session->state == SESSION_STATE_ERROR) {
    finish_fs_request(ctx);
    return;
  }

  if (req->result < 0) {
    log_all(LOG_ERROR, "GET: Read failed: %s", uv_strerror((int)req->result));
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t*)"Read failed",
                       11, 1);
    close_active_file(session);

  } else if (session->files.has_record_lengths &&
             (size_t)req->result != ctx->buf.len) {
    log_all(LOG_ERROR, "GET: Truncated encrypted record.");
    session_close((uv_handle_t*)&session->handle);
  } else if (req->result == 0) {  // EOF
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0, 1);
    close_active_file(session);
  } else {
    size_t bytes = req->result;
    session->files.file_offset += bytes;
    if (session->files.file_encryption_enabled) {
      nasfs_block_meta_t meta;
      meta.seq_num = session->files.server_block_seq;
      meta.size = bytes;
      memset(meta.hash, 0, sizeof(meta.hash));
      size_t hash_out_len = 0;
      if (crypto_engine_hash((nasfs_hash_algo_t)session->files.file_hash_algo,
                             (const uint8_t*)ctx->buf.base, bytes, meta.hash,
                             &hash_out_len) != 0) {
        log_all(LOG_ERROR, "GET: Hash computation failed.");
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Hash calculation failed", 23, 1);
        session_close((uv_handle_t*)&session->handle);
        finish_fs_request(ctx);
        return;
      }
      uint8_t encoded_meta[NASFS_BLOCK_META_SIZE];
      protocol_encode_block_meta(encoded_meta, &meta);
      session_send_frame(session, NASFS_CMD_GET_BLOCK_META, encoded_meta,
                         sizeof(encoded_meta), 1);
      session->files.server_block_seq++;
    }
    session_send_frame(session, NASFS_CMD_GET_DATA, (uint8_t*)ctx->buf.base,
                       bytes, 0);
  }

  finish_fs_request(ctx);
}

static void submit_get_read(client_session_t* session, size_t length,
                            uv_fs_cb callback);

static void on_get_manifest(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = req->data;
  client_session_t* session = ctx->session;
  if (session->state != SESSION_STATE_ERROR) {
    if (req->result == NASFS_MANIFEST_SIZE) {
      session->state = SESSION_STATE_AUTHENTICATED;
      session_send_frame(session, NASFS_CMD_GET_DONE, (uint8_t*)ctx->buf.base,
                         NASFS_MANIFEST_SIZE, 1);
      close_active_file(session);
    } else {
      session_close((uv_handle_t*)&session->handle);
    }
  }
  finish_fs_request(ctx);
}

static void on_get_record_length(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = req->data;
  client_session_t* session = ctx->session;
  uint32_t wire_length;
  if (session->state == SESSION_STATE_ERROR) {
    finish_fs_request(ctx);
    return;
  }
  if (req->result == 0 && !session->files.has_manifest) {
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0, 1);
    close_active_file(session);
  } else if (req->result != (int)sizeof(wire_length)) {
    session_close((uv_handle_t*)&session->handle);
  } else {
    memcpy(&wire_length, ctx->buf.base, sizeof(wire_length));
    size_t length = ntohl(wire_length);
    if (length == 0 && session->files.has_manifest &&
        session->files.file_offset <=
            INT64_MAX - sizeof(wire_length) - (NASFS_MANIFEST_SIZE + 1)) {
      session->files.file_offset += sizeof(wire_length);
      submit_get_read(session, NASFS_MANIFEST_SIZE + 1, on_get_manifest);
    } else if (length > NASFS_CIPHER_OVERHEAD && length <= MAX_RECORD_SIZE &&
               session->files.file_offset <=
                   INT64_MAX - sizeof(wire_length) - length) {
      session->files.file_offset += sizeof(wire_length);
      submit_get_read(session, length, on_get_fs_read);
    } else {
      session_close((uv_handle_t*)&session->handle);
    }
  }
  finish_fs_request(ctx);
}

void nasfs_file_service_get_next(client_session_t* session) {
  if (session->state != SESSION_STATE_SENDING_FILE ||
      session->files.active_fd == -1)
    return;
  if (session->files.has_record_lengths) {
    submit_get_read(session, sizeof(uint32_t), on_get_record_length);
  } else {
    size_t length = IO_CHUNK_SIZE;
    if (session->files.file_encryption_enabled) length += NASFS_CIPHER_OVERHEAD;
    submit_get_read(session, length, on_get_fs_read);
  }
}

static void submit_get_read(client_session_t* session, size_t length,
                            uv_fs_cb callback) {
  nasfs_fs_ctx_t* ctx = malloc(sizeof(*ctx));
  if (!ctx) {
    session_close((uv_handle_t*)&session->handle);
    return;
  }
  ctx->buf = uv_buf_init(malloc(length), length);
  if (!ctx->buf.base) {
    free(ctx);
    session_close((uv_handle_t*)&session->handle);
    return;
  }
  ctx->session = session;
  ctx->req.data = ctx;
  int rc = uv_fs_read(session->handle.loop, &ctx->req, session->files.active_fd,
                      &ctx->buf, 1, session->files.file_offset, callback);
  if (rc < 0) {
    fs_submission_failed(ctx, rc);
    return;
  }
  session->files.pending_fs++;
}

static void on_get_fs_open(client_session_t* session, int result,
                           const uint8_t* file_header, int header_result,
                           int slot_result) {
  if (result < 0) {
    log_all(LOG_ERROR, "GET: Open failed: %s", uv_strerror((int)result));
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_ERROR,
                       (const uint8_t*)"File not found", 14, 1);
  } else {
    session->files.active_fd = (uv_file)result;
    session->files.has_record_lengths = 0;
    session->files.has_manifest = 0;
    if (session->files.file_encryption_enabled) {
      if (header_result != FILE_HEADER_SIZE) {
        log_all(LOG_ERROR, "GET: Header read failed: read %d bytes",
                header_result);
        session->state = SESSION_STATE_AUTHENTICATED;
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Header read failed", 18, 1);

        close_active_file(session);
        return;
      }
      session->files.file_offset = FILE_HEADER_SIZE;
      uint8_t disk_cipher =
          file_header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES];
      session->files.has_record_lengths =
          (disk_cipher & NASFS_FILE_RECORD_LENGTHS) != 0;
      session->files.has_manifest = (disk_cipher & NASFS_FILE_MANIFEST) != 0;
      int has_slot = (disk_cipher & NASFS_FILE_OWNER_SLOT_V1) != 0;
      uint8_t portable = disk_cipher & NASFS_FILE_CIPHER_PORTABLE;
      session->files.file_cipher_algo =
          disk_cipher &
          ~(NASFS_FILE_RECORD_LENGTHS | NASFS_FILE_MANIFEST |
            NASFS_FILE_OWNER_SLOT_V1 | NASFS_FILE_CIPHER_PORTABLE);
      if ((session->files.has_manifest && !session->files.has_record_lengths) ||
          (has_slot && !session->files.has_manifest) ||
          (portable && !has_slot)) {
        session_close((uv_handle_t*)&session->handle);
        return;
      }
      session->files.file_hash_algo =
          file_header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES + 1];
      if (session->files.file_cipher_algo > NASFS_CIPHER_AES_256_GCM ||
          session->files.file_hash_algo > NASFS_HASH_CRC32) {
        log_all(LOG_ERROR, "GET: Invalid container algorithms.");
        session_close((uv_handle_t*)&session->handle);
        return;
      }

      /* GET_ACK: [16 salt][8 size][1 cipher_algo][1 hash_algo] */
      uint8_t ack_payload[FILE_HEADER_SIZE + NASFS_OWNER_SLOT_V1_SIZE];
      size_t ack_size = FILE_HEADER_SIZE;
      if (has_slot) {
        if (slot_result != NASFS_OWNER_SLOT_V1_SIZE) {
          session_close((uv_handle_t*)&session->handle);
          return;
        }
        memcpy(ack_payload + FILE_HEADER_SIZE, file_header + FILE_HEADER_SIZE,
               NASFS_OWNER_SLOT_V1_SIZE);
        ack_size += NASFS_OWNER_SLOT_V1_SIZE;
        session->files.file_offset = ack_size;
      }
      memcpy(ack_payload, file_header + sizeof(uint64_t),
             crypto_pwhash_SALTBYTES);
      uint64_t plaintext_size;
      if (portable)
        plaintext_size = protocol_load_u64(file_header);
      else
        memcpy(&plaintext_size, file_header, sizeof(plaintext_size));
      protocol_store_u64(ack_payload + crypto_pwhash_SALTBYTES, plaintext_size);
      ack_payload[crypto_pwhash_SALTBYTES + sizeof(uint64_t)] =
          session->files.file_cipher_algo | portable;
      ack_payload[crypto_pwhash_SALTBYTES + sizeof(uint64_t) + 1] =
          session->files.file_hash_algo;
      session_send_frame(session, NASFS_CMD_GET_ACK, ack_payload, ack_size, 1);
    } else {
      session->files.file_offset = 0;
      session_send_frame(session, NASFS_CMD_GET_ACK, NULL, 0, 1);
    }
    nasfs_file_service_get_next(session);
  }
}

typedef struct {
  uv_work_t req;
  client_session_t* session;
  char name[NASFS_STORAGE_NAME_MAX + 1];
  char temp_name[NASFS_UPLOAD_TEMP_SIZE];
  int uploading;
  int result;
  int header_result;
  int slot_result;
  uint8_t header[FILE_HEADER_SIZE + NASFS_OWNER_SLOT_V1_SIZE];
} nasfs_open_ctx_t;

static void open_storage_object(uv_work_t* req) {
  nasfs_open_ctx_t* ctx = req->data;
  ctx->result =
      ctx->uploading
          ? nasfs_storage_begin_upload(ctx->session->files.storage,
                                       ctx->temp_name)
          : nasfs_storage_open_object(ctx->session->files.storage, ctx->name);
  if (ctx->result < 0 || !ctx->session->files.file_encryption_enabled) return;

  uv_fs_t request;
  if (ctx->uploading) {
    uv_buf_t buf = uv_buf_init((char*)ctx->header, sizeof(ctx->header));
    ctx->header_result =
        uv_fs_write(NULL, &request, ctx->result, &buf, 1, 0, NULL);
    uv_fs_req_cleanup(&request);
    return;
  }

  uv_buf_t buf = uv_buf_init((char*)ctx->header, FILE_HEADER_SIZE);
  ctx->header_result =
      uv_fs_read(NULL, &request, ctx->result, &buf, 1, 0, NULL);
  uv_fs_req_cleanup(&request);
  if (ctx->header_result == FILE_HEADER_SIZE &&
      (ctx->header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES] &
       NASFS_FILE_OWNER_SLOT_V1)) {
    buf = uv_buf_init((char*)ctx->header + FILE_HEADER_SIZE,
                      NASFS_OWNER_SLOT_V1_SIZE);
    ctx->slot_result = uv_fs_read(NULL, &request, ctx->result, &buf, 1,
                                  FILE_HEADER_SIZE, NULL);
    uv_fs_req_cleanup(&request);
  }
}

static void on_storage_opened(uv_work_t* req, int status) {
  nasfs_open_ctx_t* ctx = req->data;
  client_session_t* session = ctx->session;
  int result = status < 0 ? status : ctx->result;
  if (ctx->uploading && result >= 0) {
    snprintf(session->files.upload_name, sizeof(session->files.upload_name),
             "%s", ctx->name);
    snprintf(session->files.upload_temp_name,
             sizeof(session->files.upload_temp_name), "%s", ctx->temp_name);
  }
  if (session->state == SESSION_STATE_ERROR) {
    if (result >= 0) session->files.active_fd = result;
  } else if (ctx->uploading) {
    on_put_fs_open(session, result, ctx->header_result);
  } else {
    on_get_fs_open(session, result, ctx->header, ctx->header_result,
                   ctx->slot_result);
  }
  free(ctx);
  finish_file_request(session);
}

static void submit_file_open(client_session_t* session, const uint8_t* name,
                             size_t length, int uploading) {
  nasfs_open_ctx_t* ctx = calloc(1, sizeof(*ctx));
  if (!ctx) {
    session_close((uv_handle_t*)&session->handle);
    return;
  }
  if (nasfs_storage_parse_name(name, length, ctx->name) < 0) {
    free(ctx);
    log_all(LOG_WARNING, "Rejected invalid storage object name.");
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_ERROR,
                       (const uint8_t*)"Invalid file name",
                       sizeof("Invalid file name") - 1, 1);

    return;
  }
  ctx->session = session;
  ctx->uploading = uploading;
  if (uploading && session->files.file_encryption_enabled) {
    uint8_t* header = ctx->header;
    protocol_store_u64(header, session->files.expected_plaintext_size);
    memcpy(header + sizeof(uint64_t), session->files.file_salt,
           crypto_pwhash_SALTBYTES);
    header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES] =
        session->files.file_cipher_algo | NASFS_FILE_RECORD_LENGTHS |
        NASFS_FILE_MANIFEST | NASFS_FILE_OWNER_SLOT_V1 |
        NASFS_FILE_CIPHER_PORTABLE;
    header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES + 1] =
        session->files.file_hash_algo;
    memcpy(header + FILE_HEADER_SIZE, session->files.owner_slot,
           sizeof(session->files.owner_slot));
  }
  ctx->req.data = ctx;
  int rc = uv_queue_work(session->handle.loop, &ctx->req, open_storage_object,
                         on_storage_opened);
  if (rc < 0) {
    free(ctx);
    log_all(LOG_ERROR, "Open request submission failed: %s", uv_strerror(rc));
    session_close((uv_handle_t*)&session->handle);
    return;
  }
  session->files.pending_fs++;
}

void nasfs_file_service_dispatch(client_session_t* session,
                                 nasfs_frame_t plain_frame) {
  if (!session->files.access.subject) {
    session_close((uv_handle_t*)&session->handle);
    return;
  }

  switch (plain_frame.type) {
    case NASFS_CMD_PUT_REQ: {
      if (session->state != SESSION_STATE_AUTHENTICATED) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      const size_t name_offset =
          1 + FILE_HEADER_SIZE + NASFS_OWNER_SLOT_V1_SIZE;
      if (plain_frame.payload_len <= name_offset ||
          (plain_frame.payload[0] != NASFS_FILE_REQUEST_PORTABLE &&
           plain_frame.payload[0] != NASFS_PUT_REQUEST_EXCLUSIVE)) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      session->files.upload_exclusive =
          plain_frame.payload[0] == NASFS_PUT_REQUEST_EXCLUSIVE;
      session->files.upload_plaintext_bytes = 0;
      memcpy(session->files.file_salt, plain_frame.payload + 1,
             crypto_pwhash_SALTBYTES);
      session->files.expected_plaintext_size =
          protocol_load_u64(plain_frame.payload + 1 + crypto_pwhash_SALTBYTES);
      uint8_t req_cipher =
          plain_frame.payload[1 + crypto_pwhash_SALTBYTES + sizeof(uint64_t)];
      uint8_t req_hash =
          plain_frame
              .payload[1 + crypto_pwhash_SALTBYTES + sizeof(uint64_t) + 1];
      if (req_cipher > NASFS_CIPHER_AES_256_GCM ||
          req_hash > NASFS_HASH_CRC32) {
        log_all(LOG_ERROR, "PUT: Unknown cipher or hash algo requested.");
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Unknown crypto algo", 19, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      session->files.file_cipher_algo = req_cipher;
      session->files.file_hash_algo = req_hash;
      memcpy(session->files.owner_slot,
             plain_frame.payload + 1 + FILE_HEADER_SIZE,
             sizeof(session->files.owner_slot));
      session->files.file_encryption_enabled = 1;
      session->files.has_pending_block_meta = 0;
      session->files.server_block_seq = 0;

      session->state = SESSION_STATE_RECEIVING_FILE;
      submit_file_open(session, plain_frame.payload + name_offset,
                       plain_frame.payload_len - name_offset, 1);
      break;
    }

    case NASFS_CMD_PUT_BLOCK_META: {
      if (session->state == SESSION_STATE_RECEIVING_FILE &&
          session->files.active_fd != -1 &&
          !session->files.has_pending_block_meta) {
        nasfs_block_meta_t meta;
        if (protocol_decode_block_meta(plain_frame.payload,
                                       plain_frame.payload_len, &meta) < 0) {
          log_all(LOG_ERROR, "PUT: Received invalid block meta payload size.");
          session_send_frame(session, NASFS_CMD_ERROR,
                             (const uint8_t*)"Invalid block meta", 18, 1);
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        session->files.expected_block_seq = meta.seq_num;
        session->files.expected_block_size = meta.size;
        memcpy(session->files.expected_block_hash, meta.hash, 32);
        session->files.has_pending_block_meta = 1;
      } else {
        session_close((uv_handle_t*)&session->handle);
      }
      break;
    }

    case NASFS_CMD_PUT_DATA: {  // Unencrypted
      if (session->state == SESSION_STATE_RECEIVING_FILE &&
          session->files.active_fd != -1) {
        if (session->files.file_encryption_enabled) {
          if (!session->files.has_pending_block_meta) {
            log_all(LOG_ERROR, "PUT: Received data block without metadata.");
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Data block without metadata",
                               27, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          if (plain_frame.payload_len != session->files.expected_block_size) {
            log_all(
                LOG_ERROR,
                "PUT: Received data block size mismatch. Expected %u, got %zu.",
                session->files.expected_block_size, plain_frame.payload_len);
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Block size mismatch", 19, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          if (session->files.expected_block_seq !=
              session->files.server_block_seq) {
            log_all(LOG_ERROR,
                    "PUT: Sequence number mismatch. Expected %llu, got %llu.",
                    (unsigned long long)session->files.server_block_seq,
                    (unsigned long long)session->files.expected_block_seq);
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Sequence mismatch", 17, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }

          uint8_t computed_hash[32] = {0};
          size_t computed_hash_len = 0;
          if (crypto_engine_hash(
                  (nasfs_hash_algo_t)session->files.file_hash_algo,
                  plain_frame.payload, plain_frame.payload_len, computed_hash,
                  &computed_hash_len) != 0) {
            log_all(LOG_ERROR, "PUT: Hash computation failed.");
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Hash failed", 11, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }

          if (sodium_memcmp(computed_hash, session->files.expected_block_hash,
                            32) != 0) {
            log_all(LOG_ERROR, "PUT: Hash verification failed for block %llu.",
                    (unsigned long long)session->files.server_block_seq);
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Hash verification failed", 24,
                               1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }

          session->files.has_pending_block_meta = 0;
          session->files.server_block_seq++;
        }

        size_t prefix_size =
            session->files.file_encryption_enabled ? sizeof(uint32_t) : 0;
        size_t write_size = prefix_size + plain_frame.payload_len;
        if (write_size > INT64_MAX - session->files.file_offset) {
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        if (session->files.file_encryption_enabled) {
          if (plain_frame.payload_len <= NASFS_CIPHER_OVERHEAD ||
              plain_frame.payload_len > MAX_RECORD_SIZE) {
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          uint64_t plaintext_bytes =
              plain_frame.payload_len - NASFS_CIPHER_OVERHEAD;
          if (plaintext_bytes > session->files.expected_plaintext_size -
                                    session->files.upload_plaintext_bytes) {
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          session->files.upload_plaintext_bytes += plaintext_bytes;
          protocol_manifest_record(&session->files.manifest,
                                   plain_frame.payload,
                                   plain_frame.payload_len);
        }

        nasfs_fs_ctx_t* ctx = malloc(sizeof(*ctx));
        if (!ctx) {
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        ctx->buf = uv_buf_init(malloc(write_size), write_size);
        if (!ctx->buf.base) {
          free(ctx);
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        if (prefix_size != 0) {
          uint32_t length = htonl((uint32_t)plain_frame.payload_len);
          memcpy(ctx->buf.base, &length, sizeof(length));
        }
        memcpy(ctx->buf.base + prefix_size, plain_frame.payload,
               plain_frame.payload_len);
        ctx->req.data = ctx;
        ctx->session = session;
        int rc = uv_fs_write(
            session->handle.loop, &ctx->req, session->files.active_fd,
            &ctx->buf, 1, (int64_t)session->files.file_offset, on_put_fs_write);
        if (rc < 0) {
          fs_submission_failed(ctx, rc);
          break;
        }
        session->files.pending_fs++;
        session->files.file_offset += write_size;
      } else {
        session_close((uv_handle_t*)&session->handle);
      }
      break;
    }

    case NASFS_CMD_PUT_DONE:
      if (session->state == SESSION_STATE_RECEIVING_FILE &&
          session->files.active_fd != -1) {
        if (plain_frame.payload_len != NASFS_MANIFEST_SIZE ||
            session->files.has_pending_block_meta ||
            session->files.upload_plaintext_bytes !=
                session->files.expected_plaintext_size ||
            session->files.file_offset >
                INT64_MAX - sizeof(uint32_t) - NASFS_MANIFEST_SIZE) {
          log_all(LOG_ERROR, "PUT: Incomplete upload.");
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        if (protocol_manifest_verify(&session->files.manifest,
                                     plain_frame.payload,
                                     session->files.trusted_author) != 0) {
          uint8_t status = NASFS_PUT_PUBLICATION_FAILED;
          log_all(LOG_WARNING, "PUT: Manifest verification failed.");
          session_send_frame(session, NASFS_CMD_PUT_RESULT, &status,
                             sizeof(status), 1);
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        memcpy(session->files.upload_manifest, plain_frame.payload,
               NASFS_MANIFEST_SIZE);
        session->files.put_draining = 1;
        if (session->files.pending_fs == 0) finish_put(session);
      } else {
        session_close((uv_handle_t*)&session->handle);
      }
      break;

    case NASFS_CMD_GET_REQ: {
      if (session->state != SESSION_STATE_AUTHENTICATED) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      if (plain_frame.payload_len <= 1 ||
          plain_frame.payload[0] != NASFS_FILE_REQUEST_PORTABLE) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      session->files.file_encryption_enabled = 1;
      session->files.has_pending_block_meta = 0;
      session->files.server_block_seq = 0;

      session->state = SESSION_STATE_SENDING_FILE;
      submit_file_open(session, plain_frame.payload + 1,
                       plain_frame.payload_len - 1, 0);
      break;
    }
    default:
      session_close((uv_handle_t*)&session->handle);
      break;
  }
}
