/**
 * @file session.c
 * @brief Server-side session management with PQC handshake and encrypted
 * channel.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file implements the complete lifecycle for a client connection,
 * including the post-quantum key exchange (PQC KEX) handshake,
 * protocol frame dispatching, and asynchronous file I/O operations.
 * Control commands are encrypted using libsodium's secretstream API,
 * while bulk data is transferred unencrypted for performance.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <oqs/oqs.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "config/config.h"
#include "crypto_engine.h"
#include "handshake.h"
#include "logging/log.h"
#include "network/session.h"
#include "pake.h"

#define INITIAL_RECV_BUFFER_SIZE 16384
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024)
#define MAX_PENDING_PUT_WRITES 4

static uint8_t server_signing_key[crypto_sign_SECRETKEYBYTES];

static uint8_t trusted_author[crypto_sign_PUBLICKEYBYTES];

int session_load_identity(const char* seed_path, const char* author_path) {
  if (nasfs_handshake_read_key(author_path, trusted_author, 0) < 0) return -1;
  uint8_t seed[crypto_sign_SEEDBYTES];
  uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
  if (nasfs_handshake_read_key(seed_path, seed, 1) < 0) return -1;
  int result = crypto_sign_seed_keypair(public_key, server_signing_key, seed);
  sodium_memzero(seed, sizeof(seed));
  return result;
}

static size_t live_sessions;
#define IO_CHUNK_SIZE ((size_t)global_config.block_size)
/* Encrypted file header: [8 bytes native-endian size][16 bytes salt]
 * [cipher plus record-length flag][hash]. Marked files store a big-endian
 * uint32_t ciphertext length before each record. */
#define FILE_HEADER_SIZE NASFS_FILE_METADATA_SIZE
#define FILE_HEADER_RECORD_LENGTHS 0x80u
#define FILE_HEADER_MANIFEST 0x40u
#define FILE_HEADER_OWNER_SLOT_V1 0x20u
#define MAX_RECORD_SIZE (4194304 + NASFS_CIPHER_OVERHEAD)
#define NASFS_CIPHER_OVERHEAD \
  16 /* MAC tag bytes — true for all supported ciphers */
/* --- Context Structs for Async Operations --- */
typedef struct {
  uv_write_t req;
  uv_buf_t buf;
  nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

typedef struct {
  uv_fs_t req;
  uv_buf_t buf;
  client_session_t* session;
} nasfs_fs_ctx_t;

/* --- Forward Declarations --- */
static void session_on_read(uv_stream_t* stream, ssize_t nread,
                            const uv_buf_t* buf);
static void session_alloc_buffer(uv_handle_t* handle, size_t suggested_size,
                                 uv_buf_t* buf);
static void on_socket_write_done(uv_write_t* req, int status);
static int session_send_frame(client_session_t* session, nasfs_cmd_type_t type,
                              const uint8_t* payload, size_t payload_len,
                              int encrypt);
static void do_get_next_chunk(client_session_t* session);
static void process_session_frames(client_session_t* session);
static void session_alloc_buffer(uv_handle_t* handle, size_t suggested_size,
                                 uv_buf_t* buf);
static void session_on_read(uv_stream_t* stream, ssize_t nread,
                            const uv_buf_t* buf);
static void session_dispatch_frame(client_session_t* session,
                                   nasfs_frame_t* frame);
static int method_requires_password(const char* method) {
  return strcmp(method, NASFS_AUTH_METHOD_PASSWORD) == 0 ||
         strcmp(method, NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY) == 0;
}

static int method_requires_publickey(const char* method) {
  return strcmp(method, NASFS_AUTH_METHOD_PUBLICKEY) == 0 ||
         strcmp(method, NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY) == 0;
}

static int authorized_key_matches(const char* path, const char* alg,
                                  const uint8_t* public_key,
                                  size_t public_key_len) {
  FILE* file;
  char line[8192];

  if (!path || !alg || !public_key) {
    return 0;
  }

  file = fopen(path, "r");
  if (!file) {
    return 0;
  }

  while (fgets(line, sizeof(line), file)) {
    char* key_alg;
    char* key_hex;
    uint8_t* decoded;
    size_t decoded_len = 0;
    int match;

    if (line[0] == '#' || line[0] == '\n') {
      continue;
    }

    key_alg = strtok(line, " \t\r\n");
    key_hex = strtok(NULL, " \t\r\n");
    if (!key_alg || !key_hex || strcmp(key_alg, alg) != 0) {
      continue;
    }

    decoded = nasfs_hex_decode(key_hex, &decoded_len);
    if (!decoded) {
      continue;
    }

    match = decoded_len == public_key_len &&
            memcmp(decoded, public_key, public_key_len) == 0;
    free(decoded);
    if (match) {
      fclose(file);
      return 1;
    }
  }

  fclose(file);
  return 0;
}

static int verify_publickey_auth(client_session_t* session,
                                 const nasfs_auth_payload_t* auth) {
  OQS_SIG* sig;
  uint8_t* message;
  size_t message_len = 0;
  int ok = 0;

  if (!auth->sig_algorithm || !auth->public_key || !auth->signature ||
      !nasfs_handshake_offer_contains(global_config.pubkey_auth_algorithms,
                                      auth->sig_algorithm) ||
      !OQS_SIG_alg_is_enabled(auth->sig_algorithm) ||
      !authorized_key_matches(global_config.authorized_keys_file,
                              auth->sig_algorithm, auth->public_key,
                              auth->public_key_len)) {
    return 0;
  }

  sig = OQS_SIG_new(auth->sig_algorithm);
  if (!sig || auth->public_key_len != sig->length_public_key) {
    if (sig) {
      OQS_SIG_free(sig);
    }
    return 0;
  }

  message = nasfs_auth_build_message(
      auth->method, auth->username, session->auth_context,
      sizeof(session->auth_context), &message_len);
  if (message) {
    ok = OQS_SIG_verify(sig, message, message_len, auth->signature,
                        auth->signature_len, auth->public_key) == OQS_SUCCESS;
    free(message);
  }

  OQS_SIG_free(sig);
  return ok;
}

static uint8_t server_auth_password_hash[32];
static int server_auth_password_hash_initialized = 0;
static pthread_mutex_t server_auth_lock = PTHREAD_MUTEX_INITIALIZER;

static int verify_auth_payload(client_session_t* session,
                               const nasfs_auth_payload_t* auth) {
  if (!auth || !auth->method || !auth->username ||
      !nasfs_handshake_offer_contains(global_config.auth_methods,
                                      auth->method)) {
    return 0;
  }

  if (method_requires_password(auth->method)) {
    if (!auth->password || !global_config.auth_password) {
      return 0;
    }

    pthread_mutex_lock(&server_auth_lock);
    if (!server_auth_password_hash_initialized) {
      uint8_t auth_salt[crypto_pwhash_SALTBYTES];
      // Static domain salt for authentication (same as client)
      memset(auth_salt, 0x55, sizeof(auth_salt));

      if (crypto_pwhash(
              server_auth_password_hash, sizeof(server_auth_password_hash),
              global_config.auth_password, strlen(global_config.auth_password),
              auth_salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
              crypto_pwhash_MEMLIMIT_INTERACTIVE,
              crypto_pwhash_ALG_ARGON2ID13) != 0) {
        pthread_mutex_unlock(&server_auth_lock);
        return 0;
      }
      server_auth_password_hash_initialized = 1;
    }
    pthread_mutex_unlock(&server_auth_lock);

    // Compute the session-bound fast and secure proof: BLAKE2b(shared_secret,
    // key=server_auth_password_hash)
    uint8_t expected_proof[32];
    if (crypto_generichash(expected_proof, sizeof(expected_proof),
                           session->auth_context, sizeof(session->auth_context),
                           server_auth_password_hash,
                           sizeof(server_auth_password_hash)) != 0) {
      return 0;
    }
    char* expected_hex =
        nasfs_hex_encode(expected_proof, sizeof(expected_proof));
    if (!expected_hex) {
      return 0;
    }
    if (strlen(auth->password) != 64) {
      free(expected_hex);
      return 0;
    }
    int rc = sodium_memcmp(auth->password, expected_hex, 64);
    free(expected_hex);
    if (rc != 0) {
      return 0;
    }
  }

  if (method_requires_publickey(auth->method) &&
      !verify_publickey_auth(session, auth)) {
    return 0;
  }

  if (strcmp(auth->method, NASFS_AUTH_METHOD_PAKE) == 0) {
    if (!session->pake_hello_received || !auth->password) {
      return 0;
    }
    /* proof = BLAKE2b(K_pake || "client") sent as hex */
    uint8_t K[32];
    if (pake_server_derive_key(session->pake_w, session->pake_y,
                               session->pake_X, K) != 0) {
      return 0;
    }
    uint8_t expected_proof[32];
    const uint8_t tag[] = "client";
    if (crypto_generichash(expected_proof, sizeof(expected_proof), K, sizeof(K),
                           tag, sizeof(tag) - 1) != 0) {
      return 0;
    }
    char* expected_hex =
        nasfs_hex_encode(expected_proof, sizeof(expected_proof));
    if (!expected_hex) return 0;
    if (strlen(auth->password) != 64) {
      free(expected_hex);
      return 0;
    }
    int rc = sodium_memcmp(auth->password, expected_hex, 64);
    free(expected_hex);
    return rc == 0;
  }

  return method_requires_password(auth->method) ||
         method_requires_publickey(auth->method);
}

/**
 * @brief Selects the first mutually supported and enabled KEX algorithm.
 *
 * The client preference order wins, while the server configuration constrains
 * the admissible algorithms.
 *
 * @param client_kex_list Client-supplied KEX preference list.
 * @param server_kex_list Server-configured KEX allow-list.
 * @return Newly allocated selected KEX identifier, or NULL if none match.
 */
static char* select_kex_algorithm(const char* client_kex_list,
                                  const char* server_kex_list) {
  const char* cursor;

  if (!client_kex_list || !server_kex_list) {
    return NULL;
  }

  cursor = client_kex_list;
  while (*cursor != '\0') {
    const char* start = cursor;
    const char* end;
    size_t len;
    char* candidate;

    while (*start != '\0' && isspace((unsigned char)*start)) {
      start++;
    }

    end = start;
    while (*end != '\0' && *end != ',') {
      end++;
    }

    while (end > start && isspace((unsigned char)end[-1])) {
      end--;
    }

    len = (size_t)(end - start);
    if (len > 0) {
      candidate = malloc(len + 1);
      if (!candidate) {
        return NULL;
      }
      memcpy(candidate, start, len);
      candidate[len] = '\0';

      if (nasfs_handshake_offer_contains(server_kex_list, candidate) &&
          nasfs_handshake_profile(candidate) != 0 &&
          OQS_KEM_alg_is_enabled(candidate)) {
        return candidate;
      }
      free(candidate);
    }

    cursor = (*end == ',') ? end + 1 : end;
  }

  return NULL;
}

/**
 * @brief Selects the first mutually supported control-channel cipher.
 *
 * @param client_cipher_list Client-supplied cipher preference list.
 * @param server_cipher_list Server-configured cipher allow-list.
 * @return Newly allocated selected cipher identifier, or NULL if none match.
 */
static char* select_cipher_algorithm(const char* client_cipher_list,
                                     const char* server_cipher_list) {
  if (nasfs_handshake_offer_contains(client_cipher_list,
                                     NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) &&
      nasfs_handshake_offer_contains(server_cipher_list,
                                     NASFS_CONTROL_CIPHER_XCHACHA20POLY1305)) {
    return strdup(NASFS_CONTROL_CIPHER_XCHACHA20POLY1305);
  }

  return NULL;
}

/* --- Core Session Lifecycle --- */

static void session_free(client_session_t* session) {
  if (!session) return;
  if (session->recv_buffer) free(session->recv_buffer);
  if (session->kem_secret_key) {
    sodium_memzero(session->kem_secret_key, session->kem->length_secret_key);
    free(session->kem_secret_key);
  }
  if (session->kem) OQS_KEM_free(session->kem);
  sodium_memzero(session->auth_context, sizeof(session->auth_context));
  if (session->shared_secret) sodium_free(session->shared_secret);
  if (session->kex_algorithm) free(session->kex_algorithm);
  if (session->cipher_algorithm) free(session->cipher_algorithm);
  free(session);
  live_sessions--;
  log_all(LOG_DEBUG, "Session resources deallocated.");
}

static int close_active_file(client_session_t* session) {
  if (session->active_fd == -1) return 0;

  uv_fs_t req;
  int rc = uv_fs_close(session->handle.loop, &req, session->active_fd, NULL);
  uv_fs_req_cleanup(&req);
  session->active_fd = -1;
  if (rc < 0) {
    log_all(LOG_ERROR, "File close failed: %s", uv_strerror(rc));
  }
  return rc;
}

static void discard_upload(client_session_t* session) {
  if (!session->upload_temp_name[0]) return;
  int rc =
      nasfs_storage_discard_upload(session->storage, session->upload_temp_name);
  if (rc < 0) {
    log_all(LOG_ERROR, "PUT: Temporary file cleanup failed: %s",
            uv_strerror(rc));
  }
  session->upload_temp_name[0] = '\0';
}

static void finish_put(client_session_t* session);

static void finish_session_close(client_session_t* session) {
  if (session->pending_fs != 0) return;
  if (session->put_draining) {
    finish_put(session);
    return;
  }
  close_active_file(session);
  discard_upload(session);
  if (session->handle_closed) session_free(session);
}

static void on_session_handle_closed(uv_handle_t* handle) {
  client_session_t* session = handle->data;
  session->handle_closed = 1;
  finish_session_close(session);
}

void session_close(uv_handle_t* handle) {
  client_session_t* session = handle->data;
  if (!session || session->state == SESSION_STATE_ERROR) return;

  session->state = SESSION_STATE_ERROR;
  log_all(LOG_INFO, "Closing session for client.");
  uv_close(handle, on_session_handle_closed);
  finish_session_close(session);
}

void session_expire_idle(uv_handle_t* handle, void* listener) {
  if (handle->type != UV_TCP || handle == listener || uv_is_closing(handle))
    return;
  client_session_t* session = handle->data;
  if (uv_now(handle->loop) - session->last_activity >=
      (uint64_t)global_config.client_timeout * 1000u) {
    log_all(LOG_WARNING, "Session idle timeout.");
    session_close(handle);
  }
}

/* --- Protocol & Crypto Implementation --- */

static int session_send_frame(client_session_t* session, nasfs_cmd_type_t type,
                              const uint8_t* payload, size_t payload_len,
                              int encrypt) {
  if (session->state == SESSION_STATE_ERROR) return UV_ECANCELED;
  int rc = UV_ENOMEM;
  uint8_t* payload_to_pack = (uint8_t*)payload;
  size_t payload_to_pack_len = payload_len;
  uint8_t* encrypted_payload = NULL;

  if (encrypt && session->is_secure) {
    payload_to_pack_len =
        payload_len + crypto_secretstream_xchacha20poly1305_ABYTES;
    encrypted_payload = malloc(payload_to_pack_len);
    if (!encrypted_payload) goto fail;

    uint8_t command = (uint8_t)type;
    if (crypto_secretstream_xchacha20poly1305_push(
            &session->send_crypto_state, encrypted_payload, NULL, payload,
            payload_len, &command, sizeof(command),
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
      free(encrypted_payload);
      rc = UV_EPROTO;
      goto fail;
    }
    payload_to_pack = encrypted_payload;
  }

  size_t frame_size;
  uint8_t* frame_data = protocol_pack_frame(type, payload_to_pack,
                                            payload_to_pack_len, &frame_size);
  if (encrypted_payload) free(encrypted_payload);
  if (!frame_data) goto fail;

  nasfs_write_ctx_t* ctx = malloc(sizeof(nasfs_write_ctx_t));
  if (!ctx) {
    free(frame_data);
    goto fail;
  }

  ctx->buf = uv_buf_init((char*)frame_data, frame_size);
  ctx->type = type;
  rc = uv_write(&ctx->req, (uv_stream_t*)&session->handle, &ctx->buf, 1,
                on_socket_write_done);
  if (rc == 0) return 0;
  free(frame_data);
  free(ctx);
fail:
  log_all(LOG_ERROR, "Frame submission failed: %s", uv_strerror(rc));
  session_close((uv_handle_t*)&session->handle);
  return rc;
}

/* --- File I/O Callbacks --- */
static void release_fs_request(nasfs_fs_ctx_t* ctx) {
  uv_fs_req_cleanup(&ctx->req);
  free(ctx->buf.base);
  free(ctx);
}

static void complete_publication(client_session_t* session, int result) {
  session->put_draining = 0;
  if (result < 0) {
    log_all(LOG_ERROR, "PUT: Publication failed: %s", uv_strerror(result));
    close_active_file(session);
    discard_upload(session);
  } else {
    session->upload_temp_name[0] = '\0';
    log_all(LOG_INFO, "Upload complete.");
  }

  if (session->state == SESSION_STATE_ERROR) {
    finish_session_close(session);
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
  memcpy(trailer + sizeof(uint32_t), session->upload_manifest,
         NASFS_MANIFEST_SIZE);
  uv_fs_t request;
  uv_buf_t buf = uv_buf_init((char*)trailer, sizeof(trailer));
  int written = uv_fs_write(NULL, &request, ctx->fd, &buf, 1,
                            (int64_t)session->file_offset, NULL);
  uv_fs_req_cleanup(&request);
  ctx->close_result = uv_fs_close(NULL, &request, ctx->fd, NULL);
  uv_fs_req_cleanup(&request);
  int rc = ctx->close_result;
  if (rc == 0 && written != (int)sizeof(trailer)) rc = UV_EIO;
  if (rc == 0) {
    rc = nasfs_storage_publish_upload(
        session->storage, session->upload_temp_name, session->upload_name);
  }
  ctx->result = rc;
}

static void on_upload_published(uv_work_t* req, int status) {
  nasfs_publish_ctx_t* ctx = req->data;
  client_session_t* session = ctx->session;
  int result = status < 0 ? status : ctx->result;
  if (status < 0) {
    session->active_fd = ctx->fd;
  } else if (ctx->close_result < 0) {
    log_all(LOG_ERROR, "File close failed: %s", uv_strerror(ctx->close_result));
  }
  free(ctx);
  session->pending_fs--;
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
  ctx->fd = session->active_fd;
  ctx->req.data = ctx;
  int rc = uv_queue_work(session->handle.loop, &ctx->req, publish_upload,
                         on_upload_published);
  if (rc < 0) {
    free(ctx);
    complete_publication(session, rc);
    return;
  }
  session->active_fd = -1;
  session->pending_fs++;
}

static void finish_file_request(client_session_t* session) {
  session->pending_fs--;
  if (session->state == SESSION_STATE_ERROR) {
    finish_session_close(session);
    return;
  }
  if (session->put_draining && session->pending_fs == 0) {
    finish_put(session);
    if (session->state == SESSION_STATE_ERROR) return;
    process_session_frames(session);
  }
  if (session->read_paused && session->state != SESSION_STATE_ERROR) {
    process_session_frames(session);
    if (session->state != SESSION_STATE_ERROR &&
        session->pending_fs < MAX_PENDING_PUT_WRITES) {
      session->read_paused = 0;
      if (uv_read_start((uv_stream_t*)&session->handle, session_alloc_buffer,
                        session_on_read) < 0) {
        session_close((uv_handle_t*)&session->handle);
      }
    }
  }
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
    session->put_draining = 0;
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
    session->active_fd = (uv_file)result;
    if (session->file_encryption_enabled) {
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
      session->file_offset = header_size;
      protocol_manifest_init(&session->manifest, session->upload_name,
                             session->expected_plaintext_size,
                             session->file_salt, session->file_cipher_algo,
                             session->file_hash_algo);
      protocol_manifest_owner_slot(&session->manifest, session->owner_slot,
                                   sizeof(session->owner_slot));
    } else {
      session->file_offset = 0;
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

  } else if (session->has_record_lengths &&
             (size_t)req->result != ctx->buf.len) {
    log_all(LOG_ERROR, "GET: Truncated encrypted record.");
    session_close((uv_handle_t*)&session->handle);
  } else if (req->result == 0) {  // EOF
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0, 1);
    close_active_file(session);
  } else {
    size_t bytes = req->result;
    session->file_offset += bytes;
    if (session->file_encryption_enabled) {
      nasfs_block_meta_t meta;
      meta.seq_num = session->server_block_seq;
      meta.size = bytes;
      memset(meta.hash, 0, sizeof(meta.hash));
      size_t hash_out_len = 0;
      if (crypto_engine_hash((nasfs_hash_algo_t)session->file_hash_algo,
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
      session->server_block_seq++;
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
  if (req->result == 0 && !session->has_manifest) {
    session->state = SESSION_STATE_AUTHENTICATED;
    session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0, 1);
    close_active_file(session);
  } else if (req->result != (int)sizeof(wire_length)) {
    session_close((uv_handle_t*)&session->handle);
  } else {
    memcpy(&wire_length, ctx->buf.base, sizeof(wire_length));
    size_t length = ntohl(wire_length);
    if (length == 0 && session->has_manifest &&
        session->file_offset <=
            INT64_MAX - sizeof(wire_length) - (NASFS_MANIFEST_SIZE + 1)) {
      session->file_offset += sizeof(wire_length);
      submit_get_read(session, NASFS_MANIFEST_SIZE + 1, on_get_manifest);
    } else if (length > NASFS_CIPHER_OVERHEAD && length <= MAX_RECORD_SIZE &&
               session->file_offset <=
                   INT64_MAX - sizeof(wire_length) - length) {
      session->file_offset += sizeof(wire_length);
      submit_get_read(session, length, on_get_fs_read);
    } else {
      session_close((uv_handle_t*)&session->handle);
    }
  }
  finish_fs_request(ctx);
}

static void do_get_next_chunk(client_session_t* session) {
  if (session->state != SESSION_STATE_SENDING_FILE || session->active_fd == -1)
    return;
  if (session->has_record_lengths) {
    submit_get_read(session, sizeof(uint32_t), on_get_record_length);
  } else {
    size_t length = IO_CHUNK_SIZE;
    if (session->file_encryption_enabled) length += NASFS_CIPHER_OVERHEAD;
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
  int rc = uv_fs_read(session->handle.loop, &ctx->req, session->active_fd,
                      &ctx->buf, 1, session->file_offset, callback);
  if (rc < 0) {
    fs_submission_failed(ctx, rc);
    return;
  }
  session->pending_fs++;
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
    session->active_fd = (uv_file)result;
    session->has_record_lengths = 0;
    session->has_manifest = 0;
    if (session->file_encryption_enabled) {
      if (header_result != FILE_HEADER_SIZE) {
        log_all(LOG_ERROR, "GET: Header read failed: read %d bytes",
                header_result);
        session->state = SESSION_STATE_AUTHENTICATED;
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Header read failed", 18, 1);

        close_active_file(session);
        return;
      }
      session->file_offset = FILE_HEADER_SIZE;
      uint8_t disk_cipher =
          file_header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES];
      session->has_record_lengths =
          (disk_cipher & FILE_HEADER_RECORD_LENGTHS) != 0;
      session->has_manifest = (disk_cipher & FILE_HEADER_MANIFEST) != 0;
      int has_slot = (disk_cipher & FILE_HEADER_OWNER_SLOT_V1) != 0;
      session->file_cipher_algo =
          disk_cipher & ~(FILE_HEADER_RECORD_LENGTHS | FILE_HEADER_MANIFEST |
                          FILE_HEADER_OWNER_SLOT_V1);
      if ((session->has_manifest && !session->has_record_lengths) ||
          (has_slot && !session->has_manifest)) {
        session_close((uv_handle_t*)&session->handle);
        return;
      }
      session->file_hash_algo =
          file_header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES + 1];
      if (session->file_cipher_algo > NASFS_CIPHER_AES_256_GCM ||
          session->file_hash_algo > NASFS_HASH_CRC32) {
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
        session->file_offset = ack_size;
      }
      memcpy(ack_payload, file_header + sizeof(uint64_t),
             crypto_pwhash_SALTBYTES);
      memcpy(ack_payload + crypto_pwhash_SALTBYTES, file_header,
             sizeof(uint64_t));
      ack_payload[crypto_pwhash_SALTBYTES + sizeof(uint64_t)] =
          session->file_cipher_algo;
      ack_payload[crypto_pwhash_SALTBYTES + sizeof(uint64_t) + 1] =
          session->file_hash_algo;
      session_send_frame(session, NASFS_CMD_GET_ACK, ack_payload, ack_size, 1);
    } else {
      session->file_offset = 0;
      session_send_frame(session, NASFS_CMD_GET_ACK, NULL, 0, 1);
    }
    do_get_next_chunk(session);
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
          ? nasfs_storage_begin_upload(ctx->session->storage, ctx->temp_name)
          : nasfs_storage_open_object(ctx->session->storage, ctx->name);
  if (ctx->result < 0 || !ctx->session->file_encryption_enabled) return;

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
       FILE_HEADER_OWNER_SLOT_V1)) {
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
    snprintf(session->upload_name, sizeof(session->upload_name), "%s",
             ctx->name);
    snprintf(session->upload_temp_name, sizeof(session->upload_temp_name), "%s",
             ctx->temp_name);
  }
  if (session->state == SESSION_STATE_ERROR) {
    if (result >= 0) session->active_fd = result;
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
  if (uploading && session->file_encryption_enabled) {
    uint8_t* header = ctx->header;
    memcpy(header, &session->expected_plaintext_size, sizeof(uint64_t));
    memcpy(header + sizeof(uint64_t), session->file_salt,
           crypto_pwhash_SALTBYTES);
    header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES] =
        session->file_cipher_algo | FILE_HEADER_RECORD_LENGTHS |
        FILE_HEADER_MANIFEST | FILE_HEADER_OWNER_SLOT_V1;
    header[sizeof(uint64_t) + crypto_pwhash_SALTBYTES + 1] =
        session->file_hash_algo;
    memcpy(header + FILE_HEADER_SIZE, session->owner_slot,
           sizeof(session->owner_slot));
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
  session->pending_fs++;
}

/* --- Main Dispatcher & Network Callbacks --- */

static void session_dispatch_frame(client_session_t* session,
                                   nasfs_frame_t* frame) {
  /* Handle unencrypted handshake commands */
  if (!session->is_secure) {
    switch (frame->type) {
      case NASFS_CMD_HELLO:
        if (session->state != SESSION_STATE_NEW) {
          session_close((uv_handle_t*)&session->handle);
          return;
        }
        {
          char* client_kex_list = NULL;
          char* client_cipher_list = NULL;
          uint8_t* pk = NULL;
          uint8_t* selection_payload = NULL;
          size_t selection_payload_len = 0;

          if (frame->payload_len <= NASFS_HANDSHAKE_NONCE ||
              nasfs_handshake_unpack_client_hello(
                  frame->payload + NASFS_HANDSHAKE_NONCE,
                  frame->payload_len - NASFS_HANDSHAKE_NONCE, &client_kex_list,
                  &client_cipher_list) != 0) {
            session_close((uv_handle_t*)&session->handle);
            return;
          }

          session->kex_algorithm = select_kex_algorithm(
              client_kex_list, global_config.kex_algorithms);
          session->cipher_algorithm = select_cipher_algorithm(
              client_cipher_list, global_config.cipher_algorithms);
          free(client_kex_list);
          free(client_cipher_list);

          if (!session->kex_algorithm || !session->cipher_algorithm) {
            log_all(LOG_WARNING,
                    "Handshake failed: no compatible algorithm suite.");
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"No compatible KEX/cipher suite",
                               strlen("No compatible KEX/cipher suite"), 0);
            session_close((uv_handle_t*)&session->handle);
            return;
          }

          session->kem = OQS_KEM_new(session->kex_algorithm);
          if (!session->kem) {
            session_close((uv_handle_t*)&session->handle);
            return;
          }

          pk = malloc(session->kem->length_public_key);
          session->kem_secret_key = malloc(session->kem->length_secret_key);
          if (!pk || !session->kem_secret_key ||
              OQS_KEM_keypair(session->kem, pk, session->kem_secret_key) !=
                  OQS_SUCCESS) {
            free(pk);
            session_close((uv_handle_t*)&session->handle);
            return;
          }

          selection_payload = nasfs_handshake_pack_server_selection(
              session->kex_algorithm, session->cipher_algorithm, pk,
              session->kem->length_public_key, &selection_payload_len);
          free(pk);
          if (!selection_payload) {
            session_close((uv_handle_t*)&session->handle);
            return;
          }

          uint8_t* signed_selection = realloc(
              selection_payload, selection_payload_len + 1 + crypto_sign_BYTES);
          if (!signed_selection) {
            free(selection_payload);
            session_close((uv_handle_t*)&session->handle);
            return;
          }
          selection_payload = signed_selection;
          selection_payload[selection_payload_len++] =
              nasfs_handshake_profile(session->kex_algorithm);
          uint8_t hello_hash[32];
          nasfs_handshake_hash(hello_hash, frame->payload, frame->payload_len);
          nasfs_handshake_transcript(session->handshake_transcript, hello_hash,
                                     selection_payload, selection_payload_len);
          if (crypto_sign_detached(selection_payload + selection_payload_len,
                                   NULL, session->handshake_transcript, 32,
                                   server_signing_key) != 0) {
            free(selection_payload);
            session_close((uv_handle_t*)&session->handle);
            return;
          }
          selection_payload_len += crypto_sign_BYTES;

          session->state = SESSION_STATE_HANDSHAKE;
          session_send_frame(session, NASFS_CMD_PQC_PUBLIC_KEY,
                             selection_payload, selection_payload_len, 0);
          free(selection_payload);
          log_all(LOG_INFO, "Negotiated KEX: %s; control cipher: %s",
                  session->kex_algorithm, session->cipher_algorithm);
        }
        return;

      case NASFS_CMD_PQC_CIPHERTEXT:
        if (session->state != SESSION_STATE_HANDSHAKE) {
          session_close((uv_handle_t*)&session->handle);
          return;
        }
        if (frame->payload_len !=
            session->kem->length_ciphertext +
                crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
          session_close((uv_handle_t*)&session->handle);
          return;
        }

        session->shared_secret =
            sodium_malloc(session->kem->length_shared_secret);
        session->shared_secret_len = session->kem->length_shared_secret;
        if (!session->shared_secret ||
            OQS_KEM_decaps(session->kem, session->shared_secret, frame->payload,
                           session->kem_secret_key) != OQS_SUCCESS) {
          session_close((uv_handle_t*)&session->handle);
          return;
        }

        {
          const uint8_t* client_header =
              frame->payload + session->kem->length_ciphertext;
          uint8_t ready[crypto_secretstream_xchacha20poly1305_HEADERBYTES + 32];
          uint8_t key[32], ciphertext_hash[32];
          nasfs_handshake_hash(ciphertext_hash, frame->payload,
                               frame->payload_len);
          int rc =
              nasfs_handshake_key(
                  key, session->shared_secret, session->shared_secret_len,
                  session->handshake_transcript, NASFS_KEY_CLIENT_CONTROL) ||
              crypto_secretstream_xchacha20poly1305_init_pull(
                  &session->recv_crypto_state, client_header, key) ||
              nasfs_handshake_key(
                  key, session->shared_secret, session->shared_secret_len,
                  session->handshake_transcript, NASFS_KEY_SERVER_CONTROL) ||
              crypto_secretstream_xchacha20poly1305_init_push(
                  &session->send_crypto_state, ready, key) ||
              nasfs_handshake_key(
                  key, session->shared_secret, session->shared_secret_len,
                  session->handshake_transcript, NASFS_KEY_SERVER_FINISHED) ||
              nasfs_handshake_finished(
                  ready + crypto_secretstream_xchacha20poly1305_HEADERBYTES,
                  key, ciphertext_hash, ready,
                  crypto_secretstream_xchacha20poly1305_HEADERBYTES) ||
              nasfs_handshake_key(session->auth_context, session->shared_secret,
                                  session->shared_secret_len,
                                  session->handshake_transcript,
                                  NASFS_KEY_CLIENT_AUTH);
          sodium_memzero(key, sizeof(key));
          if (rc != 0) {
            session_close((uv_handle_t*)&session->handle);
            return;
          }

          log_all(LOG_INFO, "PQC Handshake successful. Channel is now secure.");
          session->is_secure = 1;
          session->state = SESSION_STATE_AUTHENTICATING;
          sodium_free(session->shared_secret);
          session->shared_secret = NULL;
          sodium_memzero(session->kem_secret_key,
                         session->kem->length_secret_key);
          OQS_KEM_free(session->kem);
          session->kem = NULL;
          free(session->kem_secret_key);
          session->kem_secret_key = NULL;
          session_send_frame(session, NASFS_CMD_READY, ready, sizeof(ready), 0);
        }
        return;

      default:
        session_close((uv_handle_t*)&session->handle);
        return;
    }
  }

  /* Handle encrypted and unencrypted commands post-handshake */
  unsigned long long decrypted_len;
  nasfs_frame_t plain_frame = *frame;
  unsigned char* decrypted_payload = NULL;

  if (frame->type >= 0x10 && frame->type < 0x20) {  // Encrypted command range
    decrypted_payload = malloc(frame->payload_len);
    if (!decrypted_payload) {
      session_close((uv_handle_t*)&session->handle);
      return;
    }
    uint8_t command = (uint8_t)frame->type;
    uint8_t tag;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &session->recv_crypto_state, decrypted_payload, &decrypted_len,
            &tag, frame->payload, frame->payload_len, &command,
            sizeof(command)) != 0 ||
        tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
      free(decrypted_payload);
      log_all(LOG_ERROR, "Corrupted encrypted frame received. Closing.");
      session_close((uv_handle_t*)&session->handle);
      return;
    }
    plain_frame.payload = decrypted_payload;
    plain_frame.payload_len = decrypted_len;
  }

  switch (plain_frame.type) {
    case NASFS_CMD_PAKE_HELLO: {
      /* Payload: [u8 ulen][username][X(32)] */
      if (session->state != SESSION_STATE_AUTHENTICATING ||
          session->pake_hello_received ||
          plain_frame.payload_len < 2 + crypto_core_ristretto255_BYTES) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Bad PAKE_HELLO", 14, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      if (!nasfs_handshake_offer_contains(global_config.auth_methods,
                                          NASFS_AUTH_METHOD_PAKE)) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"PAKE not enabled", 16, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      uint8_t ulen = plain_frame.payload[0];
      if (1 + ulen + (size_t)crypto_core_ristretto255_BYTES !=
          plain_frame.payload_len) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Bad PAKE_HELLO", 14, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      memcpy(session->pake_X, plain_frame.payload + 1 + ulen,
             crypto_core_ristretto255_BYTES);

      if (!global_config.auth_password) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"No PAKE password configured", 27,
                           1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      if (pake_derive_scalar(global_config.auth_password, session->pake_w) !=
          0) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"PAKE internal error", 19, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      /* Generate ephemeral scalar y and compute server share Y */
      randombytes_buf(session->pake_y, sizeof(session->pake_y));
      /* Clamp to valid scalar range */
      session->pake_y[0] &= 248;
      session->pake_y[31] &= 63;
      session->pake_y[31] |= 64;

      uint8_t Y[crypto_core_ristretto255_BYTES];
      if (pake_server_compute_share(session->pake_w, session->pake_y, Y) != 0) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"PAKE internal error", 19, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      session->pake_hello_received = 1;
      session_send_frame(session, NASFS_CMD_PAKE_RESPONSE, Y, sizeof(Y), 1);
      break;
    }

    case NASFS_CMD_AUTH: {
      if (session->state != SESSION_STATE_AUTHENTICATING) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }

      nasfs_auth_payload_t auth = {0};
      if (nasfs_auth_unpack(plain_frame.payload, plain_frame.payload_len,
                            &auth) != 0 ||
          !verify_auth_payload(session, &auth)) {
        log_all(LOG_WARNING, "Client authentication failed.");
        nasfs_auth_payload_free(&auth);
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Authentication failed", 21, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }

      log_all(LOG_INFO, "Client '%s' authenticated with %s.", auth.username,
              auth.method);
      session->state = SESSION_STATE_AUTHENTICATED;
      session_send_frame(session, NASFS_CMD_AUTH_ACK, NULL, 0, 1);
      nasfs_auth_payload_free(&auth);
      break;
    }

    case NASFS_CMD_PUT_REQ: {
      if (session->state != SESSION_STATE_AUTHENTICATED) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      int is_enc = 0;
      const uint8_t* filename_ptr = plain_frame.payload;
      size_t filename_len = plain_frame.payload_len;
      session->expected_plaintext_size = 0;
      session->upload_plaintext_bytes = 0;
      session->file_cipher_algo = NASFS_CIPHER_XSALSA20_POLY1305;
      session->file_hash_algo = NASFS_HASH_BLAKE2B;
      if (plain_frame.payload_len > 1 &&
          (plain_frame.payload[0] == 0 || plain_frame.payload[0] == 1)) {
        is_enc = plain_frame.payload[0];
        /* Encrypted PUT_REQ: [1 enc][16 salt][8 size][1 cipher][1 hash][name]
         */
        if (is_enc) {
          size_t name_offset = 1 + FILE_HEADER_SIZE + NASFS_OWNER_SLOT_V1_SIZE;
          if (plain_frame.payload_len <= name_offset) {
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          memcpy(session->file_salt, plain_frame.payload + 1,
                 crypto_pwhash_SALTBYTES);
          memcpy(&session->expected_plaintext_size,
                 plain_frame.payload + 1 + crypto_pwhash_SALTBYTES,
                 sizeof(uint64_t));
          uint8_t req_cipher =
              plain_frame
                  .payload[1 + crypto_pwhash_SALTBYTES + sizeof(uint64_t)];
          uint8_t req_hash =
              plain_frame
                  .payload[1 + crypto_pwhash_SALTBYTES + sizeof(uint64_t) + 1];
          /* Validate algo values against enum ranges */
          if (req_cipher > NASFS_CIPHER_AES_256_GCM ||
              req_hash > NASFS_HASH_CRC32) {
            log_all(LOG_ERROR, "PUT: Unknown cipher or hash algo requested.");
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Unknown crypto algo", 19, 1);
            session_close((uv_handle_t*)&session->handle);
            if (decrypted_payload) free(decrypted_payload);
            return;
          }
          session->file_cipher_algo = req_cipher;
          session->file_hash_algo = req_hash;
          memcpy(session->owner_slot,
                 plain_frame.payload + 1 + FILE_HEADER_SIZE,
                 sizeof(session->owner_slot));
          filename_ptr = plain_frame.payload + name_offset;
          filename_len = plain_frame.payload_len - name_offset;
        } else {
          filename_ptr = plain_frame.payload + 1;
          filename_len = plain_frame.payload_len - 1;
        }
      }
      if (!is_enc) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      session->file_encryption_enabled = is_enc;
      session->has_pending_block_meta = 0;
      session->server_block_seq = 0;

      session->state = SESSION_STATE_RECEIVING_FILE;
      submit_file_open(session, filename_ptr, filename_len, 1);
      break;
    }

    case NASFS_CMD_PUT_BLOCK_META: {
      if (session->state == SESSION_STATE_RECEIVING_FILE &&
          session->active_fd != -1 && !session->has_pending_block_meta) {
        nasfs_block_meta_t meta;
        if (protocol_decode_block_meta(plain_frame.payload,
                                       plain_frame.payload_len, &meta) < 0) {
          log_all(LOG_ERROR, "PUT: Received invalid block meta payload size.");
          session_send_frame(session, NASFS_CMD_ERROR,
                             (const uint8_t*)"Invalid block meta", 18, 1);
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        session->expected_block_seq = meta.seq_num;
        session->expected_block_size = meta.size;
        memcpy(session->expected_block_hash, meta.hash, 32);
        session->has_pending_block_meta = 1;
      } else {
        session_close((uv_handle_t*)&session->handle);
      }
      break;
    }

    case NASFS_CMD_PUT_DATA: {  // Unencrypted
      if (session->state == SESSION_STATE_RECEIVING_FILE &&
          session->active_fd != -1) {
        if (session->file_encryption_enabled) {
          if (!session->has_pending_block_meta) {
            log_all(LOG_ERROR, "PUT: Received data block without metadata.");
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Data block without metadata",
                               27, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          if (frame->payload_len != session->expected_block_size) {
            log_all(
                LOG_ERROR,
                "PUT: Received data block size mismatch. Expected %u, got %zu.",
                session->expected_block_size, frame->payload_len);
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Block size mismatch", 19, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          if (session->expected_block_seq != session->server_block_seq) {
            log_all(LOG_ERROR,
                    "PUT: Sequence number mismatch. Expected %llu, got %llu.",
                    (unsigned long long)session->server_block_seq,
                    (unsigned long long)session->expected_block_seq);
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Sequence mismatch", 17, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }

          uint8_t computed_hash[32] = {0};
          size_t computed_hash_len = 0;
          if (crypto_engine_hash((nasfs_hash_algo_t)session->file_hash_algo,
                                 frame->payload, frame->payload_len,
                                 computed_hash, &computed_hash_len) != 0) {
            log_all(LOG_ERROR, "PUT: Hash computation failed.");
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Hash failed", 11, 1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }

          if (sodium_memcmp(computed_hash, session->expected_block_hash, 32) !=
              0) {
            log_all(LOG_ERROR, "PUT: Hash verification failed for block %llu.",
                    (unsigned long long)session->server_block_seq);
            session_send_frame(session, NASFS_CMD_ERROR,
                               (const uint8_t*)"Hash verification failed", 24,
                               1);
            session_close((uv_handle_t*)&session->handle);
            break;
          }

          session->has_pending_block_meta = 0;
          session->server_block_seq++;
        }

        size_t prefix_size =
            session->file_encryption_enabled ? sizeof(uint32_t) : 0;
        size_t write_size = prefix_size + plain_frame.payload_len;
        if (write_size > INT64_MAX - session->file_offset) {
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        if (session->file_encryption_enabled) {
          if (plain_frame.payload_len <= NASFS_CIPHER_OVERHEAD ||
              plain_frame.payload_len > MAX_RECORD_SIZE) {
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          uint64_t plaintext_bytes =
              plain_frame.payload_len - NASFS_CIPHER_OVERHEAD;
          if (plaintext_bytes > session->expected_plaintext_size -
                                    session->upload_plaintext_bytes) {
            session_close((uv_handle_t*)&session->handle);
            break;
          }
          session->upload_plaintext_bytes += plaintext_bytes;
          protocol_manifest_record(&session->manifest, plain_frame.payload,
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
        int rc = uv_fs_write(session->handle.loop, &ctx->req,
                             session->active_fd, &ctx->buf, 1,
                             (int64_t)session->file_offset, on_put_fs_write);
        if (rc < 0) {
          fs_submission_failed(ctx, rc);
          break;
        }
        session->pending_fs++;
        session->file_offset += write_size;
      } else {
        session_close((uv_handle_t*)&session->handle);
      }
      break;
    }

    case NASFS_CMD_PUT_DONE:
      if (session->state == SESSION_STATE_RECEIVING_FILE &&
          session->active_fd != -1) {
        if (plain_frame.payload_len != NASFS_MANIFEST_SIZE ||
            session->has_pending_block_meta ||
            session->upload_plaintext_bytes !=
                session->expected_plaintext_size ||
            session->file_offset >
                INT64_MAX - sizeof(uint32_t) - NASFS_MANIFEST_SIZE) {
          log_all(LOG_ERROR, "PUT: Incomplete upload.");
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        if (protocol_manifest_verify(&session->manifest, plain_frame.payload,
                                     trusted_author) != 0) {
          uint8_t status = NASFS_PUT_PUBLICATION_FAILED;
          log_all(LOG_WARNING, "PUT: Manifest verification failed.");
          session_send_frame(session, NASFS_CMD_PUT_RESULT, &status,
                             sizeof(status), 1);
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        memcpy(session->upload_manifest, plain_frame.payload,
               NASFS_MANIFEST_SIZE);
        session->put_draining = 1;
        if (session->pending_fs == 0) finish_put(session);
      } else {
        session_close((uv_handle_t*)&session->handle);
      }
      break;

    case NASFS_CMD_GET_REQ: {
      if (session->state != SESSION_STATE_AUTHENTICATED) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      int is_enc = 0;
      const uint8_t* filename_ptr = plain_frame.payload;
      size_t filename_len = plain_frame.payload_len;
      if (plain_frame.payload_len > 1 &&
          (plain_frame.payload[0] == 0 || plain_frame.payload[0] == 1)) {
        is_enc = plain_frame.payload[0];
        filename_ptr = plain_frame.payload + 1;
        filename_len = plain_frame.payload_len - 1;
      }
      if (!is_enc) {
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      session->file_encryption_enabled = is_enc;
      session->has_pending_block_meta = 0;
      session->server_block_seq = 0;

      session->state = SESSION_STATE_SENDING_FILE;
      submit_file_open(session, filename_ptr, filename_len, 0);
      break;
    }
    default:
      session_close((uv_handle_t*)&session->handle);
      break;
  }

  if (decrypted_payload) free(decrypted_payload);
}

static void on_socket_write_done(uv_write_t* req, int status) {
  nasfs_write_ctx_t* ctx = (nasfs_write_ctx_t*)req;
  client_session_t* session = (client_session_t*)req->handle->data;
  if (status < 0) {
    log_all(LOG_ERROR, "Socket write failed: %s", uv_strerror(status));
    session_close((uv_handle_t*)&session->handle);
  } else {
    session->last_activity = uv_now(req->handle->loop);
    if (session->state == SESSION_STATE_SENDING_FILE &&
        ctx->type == NASFS_CMD_GET_DATA) {
      do_get_next_chunk(session);
    }
  }
  if (ctx->buf.base) free(ctx->buf.base);
  free(ctx);
}

static void session_alloc_buffer(uv_handle_t* handle, size_t suggested_size,
                                 uv_buf_t* buf) {
  client_session_t* session = (client_session_t*)handle->data;
  if (!session) {
    buf->base = NULL;
    buf->len = 0;
    return;
  }
  if (session->recv_capacity - session->recv_length < suggested_size) {
    size_t new_cap = session->recv_capacity == 0 ? INITIAL_RECV_BUFFER_SIZE
                                                 : session->recv_capacity * 2;
    while (new_cap - session->recv_length < suggested_size) new_cap *= 2;
    if (new_cap > MAX_RECV_BUFFER_SIZE) {
      session_close(handle);
      buf->base = NULL;
      buf->len = 0;
      return;
    }
    uint8_t* new_buf = realloc(session->recv_buffer, new_cap);
    if (!new_buf) {
      session_close(handle);
      buf->base = NULL;
      buf->len = 0;
      return;
    }
    session->recv_buffer = new_buf;
    session->recv_capacity = new_cap;
  }
  buf->base = (char*)(session->recv_buffer + session->recv_length);
  buf->len = session->recv_capacity - session->recv_length;
}

static void process_session_frames(client_session_t* session) {
  /* Retain complete frames in the receive buffer while disk writes drain. */
  while (session->recv_length > 0 && !session->put_draining &&
         session->pending_fs < MAX_PENDING_PUT_WRITES) {
    nasfs_frame_t frame;
    int consumed = protocol_parse_frame(session->recv_buffer,
                                        session->recv_length, &frame);
    if (consumed <= 0) {
      if (consumed < 0) session_close((uv_handle_t*)&session->handle);
      return;
    }
    session->last_activity = uv_now(session->handle.loop);
    session_dispatch_frame(session, &frame);
    if (session->state == SESSION_STATE_ERROR) return;
    memmove(session->recv_buffer, session->recv_buffer + consumed,
            session->recv_length - (size_t)consumed);
    session->recv_length -= (size_t)consumed;
  }
  if (!session->read_paused && session->pending_fs >= MAX_PENDING_PUT_WRITES) {
    uv_read_stop((uv_stream_t*)&session->handle);
    session->read_paused = 1;
  }
}

static void session_on_read(uv_stream_t* stream, ssize_t nread,
                            const uv_buf_t* buf) {
  client_session_t* session = stream->data;
  (void)buf;

  if (session->state == SESSION_STATE_ERROR) return;
  if (nread > 0) {
    session->recv_length += (size_t)nread;
    process_session_frames(session);
  } else if (nread < 0) {
    if (nread != UV_EOF) {
      log_all(LOG_ERROR, "Read error: %s", uv_strerror((int)nread));
    }
    session_close((uv_handle_t*)&session->handle);
  }
}

void session_on_new_connection(uv_stream_t* server, int status) {
  client_session_t* session;

  if (status < 0) {
    log_all(LOG_ERROR, "New connection error: %s", uv_strerror(status));
    return;
  }

  void* memory = NULL;
  if (posix_memalign(&memory, _Alignof(client_session_t), sizeof(*session)) !=
      0) {
    log_all(LOG_ERROR, "Failed to allocate session context.");
    return;
  }
  session = memory;
  memset(session, 0, sizeof(*session));

  session->state = SESSION_STATE_NEW;
  session->active_fd = -1;
  session->pake_hello_received = 0;
  memset(session->pake_y, 0, sizeof(session->pake_y));
  memset(session->pake_X, 0, sizeof(session->pake_X));
  memset(session->pake_w, 0, sizeof(session->pake_w));

  if (uv_tcp_init(server->loop, &session->handle) != 0) {
    free(session);
    return;
  }

  live_sessions++;
  session->last_activity = uv_now(server->loop);
  session->handle.data = session;
  session->storage = server->data;
  if (uv_accept(server, (uv_stream_t*)&session->handle) != 0) {
    session_close((uv_handle_t*)&session->handle);
    return;
  }

  size_t limit = global_config.max_connections > 0
                     ? (size_t)global_config.max_connections
                     : 128;
  if (live_sessions > limit) {
    log_all(LOG_WARNING, "Rejecting connection at session limit.");
    session_close((uv_handle_t*)&session->handle);
    return;
  }
  log_all(LOG_INFO, "Accepted new client connection.");
  if (uv_read_start((uv_stream_t*)&session->handle, session_alloc_buffer,
                    session_on_read) != 0) {
    session_close((uv_handle_t*)&session->handle);
  }
}
