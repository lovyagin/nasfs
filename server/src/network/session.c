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

#include <ctype.h>
#include <fcntl.h>
#include <oqs/oqs.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "config/config.h"
#include "handshake.h"
#include "logging/log.h"
#include "network/session.h"

#define INITIAL_RECV_BUFFER_SIZE 16384
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024)
#define IO_CHUNK_SIZE (64 * 1024)
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
static void session_send_frame(client_session_t* session, nasfs_cmd_type_t type,
                               const uint8_t* payload, size_t payload_len,
                               int encrypt);
static void do_get_next_chunk(client_session_t* session);
static void session_dispatch_frame(client_session_t* session,
                                   nasfs_frame_t* frame);
static int csv_list_contains(const char* csv_list, const char* candidate);

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
      !csv_list_contains(global_config.pubkey_auth_algorithms,
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

  message = nasfs_auth_build_message(auth->method, auth->username,
                                     session->shared_secret,
                                     session->shared_secret_len, &message_len);
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
      !csv_list_contains(global_config.auth_methods, auth->method)) {
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
                           (const uint8_t*)session->shared_secret,
                           session->shared_secret_len,
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

  return method_requires_password(auth->method) ||
         method_requires_publickey(auth->method);
}

/**
 * @brief Checks whether a comma-separated list contains a given token.
 *
 * @param csv_list Comma-separated list to search.
 * @param candidate Candidate token to match.
 * @return 1 if the token exists in the list, otherwise 0.
 */
static int csv_list_contains(const char* csv_list, const char* candidate) {
  const char* cursor;
  size_t candidate_len;

  if (!csv_list || !candidate) {
    return 0;
  }

  candidate_len = strlen(candidate);
  cursor = csv_list;

  while (*cursor != '\0') {
    const char* start = cursor;
    const char* end;

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

    if ((size_t)(end - start) == candidate_len &&
        strncmp(start, candidate, candidate_len) == 0) {
      return 1;
    }

    cursor = (*end == ',') ? end + 1 : end;
  }

  return 0;
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

      if (csv_list_contains(server_kex_list, candidate) &&
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
  if (csv_list_contains(client_cipher_list,
                        NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) &&
      csv_list_contains(server_cipher_list,
                        NASFS_CONTROL_CIPHER_XCHACHA20POLY1305)) {
    return strdup(NASFS_CONTROL_CIPHER_XCHACHA20POLY1305);
  }

  return NULL;
}

/* --- Core Session Lifecycle --- */

static void on_session_handle_closed(uv_handle_t* handle) {
  client_session_t* session = (client_session_t*)handle->data;
  if (session) {
    if (session->recv_buffer) free(session->recv_buffer);
    if (session->kem) OQS_KEM_free(session->kem);
    if (session->kem_secret_key) free(session->kem_secret_key);
    if (session->shared_secret) {
      sodium_free(session->shared_secret);
    }
    if (session->kex_algorithm) free(session->kex_algorithm);
    if (session->cipher_algorithm) free(session->cipher_algorithm);
    free(session);
    log_all(LOG_DEBUG, "Session resources deallocated.");
  }
}

void session_close(uv_handle_t* handle) {
  client_session_t* session = (client_session_t*)handle->data;
  if (!session || session->state == SESSION_STATE_ERROR) return;

  session->state = SESSION_STATE_ERROR;
  log_all(LOG_INFO, "Closing session for client.");

  if (session->active_fd != -1) {
    uv_fs_t close_req;
    uv_fs_close(handle->loop, &close_req, session->active_fd, NULL);
    uv_fs_req_cleanup(&close_req);
    session->active_fd = -1;
  }

  if (!uv_is_closing(handle)) {
    uv_close(handle, on_session_handle_closed);
  }
}

/* --- Protocol & Crypto Implementation --- */

static void session_send_frame(client_session_t* session, nasfs_cmd_type_t type,
                               const uint8_t* payload, size_t payload_len,
                               int encrypt) {
  uint8_t* payload_to_pack = (uint8_t*)payload;
  size_t payload_to_pack_len = payload_len;
  uint8_t* encrypted_payload = NULL;

  if (encrypt && session->is_secure) {
    payload_to_pack_len =
        payload_len + crypto_secretstream_xchacha20poly1305_ABYTES;
    encrypted_payload = malloc(payload_to_pack_len);
    if (!encrypted_payload) return;

    crypto_secretstream_xchacha20poly1305_push(&session->send_crypto_state,
                                               encrypted_payload, NULL, payload,
                                               payload_len, NULL, 0, 0);
    payload_to_pack = encrypted_payload;
  }

  size_t frame_size;
  uint8_t* frame_data = protocol_pack_frame(type, payload_to_pack,
                                            payload_to_pack_len, &frame_size);
  if (encrypted_payload) free(encrypted_payload);
  if (!frame_data) return;

  nasfs_write_ctx_t* ctx = malloc(sizeof(nasfs_write_ctx_t));
  if (!ctx) {
    free(frame_data);
    return;
  }

  ctx->buf = uv_buf_init((char*)frame_data, frame_size);
  ctx->type = type;
  if (uv_write(&ctx->req, (uv_stream_t*)&session->handle, &ctx->buf, 1,
               on_socket_write_done) < 0) {
    free(frame_data);
    free(ctx);
  }
}

static const char* sanitize_path(const char* path) {
  if (!path) return "invalid_filename";

  // Completely strip out any directory structure, only allowing the actual
  // filename
  const char* last_slash = strrchr(path, '/');
  const char* last_backslash = strrchr(path, '\\');
  const char* base = path;
  if (last_slash && last_slash > base) {
    base = last_slash + 1;
  }
  if (last_backslash && last_backslash > base) {
    base = last_backslash + 1;
  }

  // If the resulting base name is empty, or contains dot-dot sequences or
  // directory traversal, fall back to safe name
  if (strlen(base) == 0 || strcmp(base, ".") == 0 || strcmp(base, "..") == 0 ||
      strstr(base, "..") != NULL) {
    return "safe_file.dat";
  }

  return base;
}

/* --- File I/O Callbacks --- */

static void on_put_fs_write(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = (nasfs_fs_ctx_t*)req->data;
  if (req->result < 0)
    log_all(LOG_ERROR, "PUT: Write error: %s", uv_strerror((int)req->result));
  if (ctx->buf.base) free(ctx->buf.base);
  uv_fs_req_cleanup(req);
  free(ctx);
}

static void on_put_fs_open(uv_fs_t* req) {
  client_session_t* session = (client_session_t*)req->data;
  if (req->result < 0) {
    log_all(LOG_ERROR, "PUT: Open failed: %s", uv_strerror((int)req->result));
    session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t*)"Open failed",
                       11, 1);
    session->state = SESSION_STATE_AUTHENTICATED;
  } else {
    session->active_fd = (uv_file)req->result;
    if (session->file_encryption_enabled) {
      uv_fs_t write_req;
      uv_buf_t buf =
          uv_buf_init((char*)session->file_salt, crypto_pwhash_SALTBYTES);
      int rc = uv_fs_write(session->handle.loop, &write_req, session->active_fd,
                           &buf, 1, 0, NULL);
      uv_fs_req_cleanup(&write_req);
      if (rc < 0) {
        log_all(LOG_ERROR, "PUT: Salt write failed: %s", uv_strerror(rc));
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Salt write failed", 17, 1);
        session->state = SESSION_STATE_AUTHENTICATED;
        uv_fs_close(session->handle.loop, &(uv_fs_t){}, session->active_fd,
                    NULL);
        session->active_fd = -1;
        uv_fs_req_cleanup(req);
        return;
      }
      session->file_offset = crypto_pwhash_SALTBYTES;
    } else {
      session->file_offset = 0;
    }
    session_send_frame(session, NASFS_CMD_PUT_ACK, NULL, 0, 1);
  }
  uv_fs_req_cleanup(req);
}

static void on_get_fs_read(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = (nasfs_fs_ctx_t*)req->data;
  client_session_t* session = ctx->session;

  if (req->result < 0) {
    log_all(LOG_ERROR, "GET: Read failed: %s", uv_strerror((int)req->result));
    session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t*)"Read failed",
                       11, 1);
    session->state = SESSION_STATE_AUTHENTICATED;
  } else if (req->result == 0) {  // EOF
    session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0, 1);
    session->state = SESSION_STATE_AUTHENTICATED;
    if (session->active_fd != -1) {
      uv_fs_close(session->handle.loop, &(uv_fs_t){}, session->active_fd, NULL);
      session->active_fd = -1;
    }
  } else {
    size_t bytes = req->result;
    session->file_offset += bytes;
    if (session->file_encryption_enabled) {
      nasfs_block_meta_t meta;
      meta.seq_num = session->server_block_seq;
      meta.size = bytes;
      if (crypto_generichash(meta.hash, sizeof(meta.hash),
                             (const uint8_t*)ctx->buf.base, bytes, NULL,
                             0) != 0) {
        log_all(LOG_ERROR, "GET: Hash computation failed.");
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Hash calculation failed", 23, 1);
        session_close((uv_handle_t*)&session->handle);
        if (ctx->buf.base) free(ctx->buf.base);
        uv_fs_req_cleanup(req);
        free(ctx);
        return;
      }
      session_send_frame(session, NASFS_CMD_GET_BLOCK_META,
                         (const uint8_t*)&meta, sizeof(meta), 1);
      session->server_block_seq++;
    }
    session_send_frame(session, NASFS_CMD_GET_DATA, (uint8_t*)ctx->buf.base,
                       bytes, 0);
  }

  if (ctx->buf.base) free(ctx->buf.base);
  uv_fs_req_cleanup(req);
  free(ctx);
}

static void do_get_next_chunk(client_session_t* session) {
  if (session->state != SESSION_STATE_SENDING_FILE || session->active_fd == -1)
    return;
  nasfs_fs_ctx_t* ctx = malloc(sizeof(nasfs_fs_ctx_t));
  if (!ctx) return;
  size_t chunk_size = IO_CHUNK_SIZE;
  if (session->file_encryption_enabled) {
    chunk_size = IO_CHUNK_SIZE + crypto_secretbox_MACBYTES;
  }
  ctx->buf = uv_buf_init(malloc(chunk_size), chunk_size);
  ctx->session = session;
  ctx->req.data = ctx;
  if (uv_fs_read(session->handle.loop, &ctx->req, session->active_fd, &ctx->buf,
                 1, session->file_offset, on_get_fs_read) < 0) {
    free(ctx->buf.base);
    free(ctx);
  }
}

static void on_get_fs_open(uv_fs_t* req) {
  client_session_t* session = (client_session_t*)req->data;
  if (req->result < 0) {
    log_all(LOG_ERROR, "GET: Open failed: %s", uv_strerror((int)req->result));
    session_send_frame(session, NASFS_CMD_ERROR,
                       (const uint8_t*)"File not found", 14, 1);
    session->state = SESSION_STATE_AUTHENTICATED;
  } else {
    session->active_fd = (uv_file)req->result;
    if (session->file_encryption_enabled) {
      uint8_t salt[crypto_pwhash_SALTBYTES];
      uv_fs_t read_req;
      uv_buf_t buf = uv_buf_init((char*)salt, crypto_pwhash_SALTBYTES);
      int rc = uv_fs_read(session->handle.loop, &read_req, session->active_fd,
                          &buf, 1, 0, NULL);
      uv_fs_req_cleanup(&read_req);
      if (rc < (int)crypto_pwhash_SALTBYTES) {
        log_all(LOG_ERROR, "GET: Salt read failed: read %d bytes", rc);
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Salt read failed", 16, 1);
        session->state = SESSION_STATE_AUTHENTICATED;
        uv_fs_close(session->handle.loop, &(uv_fs_t){}, session->active_fd,
                    NULL);
        session->active_fd = -1;
        uv_fs_req_cleanup(req);
        return;
      }
      session->file_offset = crypto_pwhash_SALTBYTES;
      session_send_frame(session, NASFS_CMD_GET_ACK, salt,
                         crypto_pwhash_SALTBYTES, 1);
    } else {
      session->file_offset = 0;
      session_send_frame(session, NASFS_CMD_GET_ACK, NULL, 0, 1);
    }
    do_get_next_chunk(session);
  }
  uv_fs_req_cleanup(req);
}

/* --- Main Dispatcher & Network Callbacks --- */

static void session_dispatch_frame(client_session_t* session,
                                   nasfs_frame_t* frame) {
  /* Handle unencrypted handshake commands */
  if (!session->is_secure) {
    switch (frame->type) {
      case NASFS_CMD_PQC_HELLO:
        if (session->state != SESSION_STATE_NEW) return;
        {
          char* client_kex_list = NULL;
          char* client_cipher_list = NULL;
          uint8_t* pk = NULL;
          uint8_t* selection_payload = NULL;
          size_t selection_payload_len = 0;

          if (nasfs_handshake_unpack_client_hello(
                  frame->payload, frame->payload_len, &client_kex_list,
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

          session_send_frame(session, NASFS_CMD_PQC_PUBLIC_KEY,
                             selection_payload, selection_payload_len, 0);
          free(selection_payload);
          log_all(LOG_INFO, "Negotiated KEX: %s; control cipher: %s",
                  session->kex_algorithm, session->cipher_algorithm);
          session->state = SESSION_STATE_HANDSHAKE;
        }
        return;

      case NASFS_CMD_PQC_CIPHERTEXT:
        if (session->state != SESSION_STATE_HANDSHAKE) return;
        if (frame->payload_len <
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
          uint8_t
              server_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

          if (crypto_secretstream_xchacha20poly1305_init_pull(
                  &session->recv_crypto_state, client_header,
                  session->shared_secret) != 0 ||
              crypto_secretstream_xchacha20poly1305_init_push(
                  &session->send_crypto_state, server_header,
                  session->shared_secret) != 0) {
            session_close((uv_handle_t*)&session->handle);
            return;
          }

          log_all(LOG_INFO, "PQC Handshake successful. Channel is now secure.");
          session->is_secure = 1;
          session->state = SESSION_STATE_AUTHENTICATED;
          OQS_KEM_free(session->kem);
          session->kem = NULL;
          free(session->kem_secret_key);
          session->kem_secret_key = NULL;
          session_send_frame(session, NASFS_CMD_SECURE_READY, server_header,
                             sizeof(server_header), 0);
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
    if (crypto_secretstream_xchacha20poly1305_pull(
            &session->recv_crypto_state, decrypted_payload, &decrypted_len,
            NULL, frame->payload, frame->payload_len, NULL, 0) != 0) {
      free(decrypted_payload);
      log_all(LOG_ERROR, "Corrupted encrypted frame received. Closing.");
      session_close((uv_handle_t*)&session->handle);
      return;
    }
    plain_frame.payload = decrypted_payload;
    plain_frame.payload_len = decrypted_len;
  }

  switch (plain_frame.type) {
    case NASFS_CMD_AUTH: {
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
      session->is_authenticated = 1;
      session->state = SESSION_STATE_AUTHENTICATED;
      session_send_frame(session, NASFS_CMD_AUTH_ACK, NULL, 0, 1);
      nasfs_auth_payload_free(&auth);
      break;
    }

    case NASFS_CMD_PUT_REQ: {
      if (!session->is_authenticated) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Authentication required", 23, 1);
        session_close((uv_handle_t*)&session->handle);
        break;
      }
      int is_enc = 0;
      const uint8_t* filename_ptr = plain_frame.payload;
      size_t filename_len = plain_frame.payload_len;
      if (plain_frame.payload_len > 1 &&
          (plain_frame.payload[0] == 0 || plain_frame.payload[0] == 1)) {
        is_enc = plain_frame.payload[0];
        if (is_enc &&
            plain_frame.payload_len >= (1 + crypto_pwhash_SALTBYTES)) {
          memcpy(session->file_salt, plain_frame.payload + 1,
                 crypto_pwhash_SALTBYTES);
          filename_ptr = plain_frame.payload + (1 + crypto_pwhash_SALTBYTES);
          filename_len =
              plain_frame.payload_len - (1 + crypto_pwhash_SALTBYTES);
        } else {
          filename_ptr = plain_frame.payload + 1;
          filename_len = plain_frame.payload_len - 1;
        }
      }
      session->file_encryption_enabled = is_enc;
      session->has_pending_block_meta = 0;
      session->server_block_seq = 0;

      char raw[256] = {0};
      memcpy(raw, filename_ptr, filename_len < 255 ? filename_len : 255);
      char path[1024];
      snprintf(path, sizeof(path), "%s/%s",
               global_config.storage_dir ? global_config.storage_dir : ".",
               sanitize_path(raw));
      session->state = SESSION_STATE_RECEIVING_FILE;
      session->fs_req.data = session;
      uv_fs_open(session->handle.loop, &session->fs_req, path,
                 O_WRONLY | O_CREAT | O_TRUNC, 0644, on_put_fs_open);
      break;
    }

    case NASFS_CMD_PUT_BLOCK_META: {
      if (session->is_authenticated &&
          session->state == SESSION_STATE_RECEIVING_FILE) {
        if (plain_frame.payload_len < sizeof(nasfs_block_meta_t)) {
          log_all(LOG_ERROR, "PUT: Received invalid block meta payload size.");
          session_send_frame(session, NASFS_CMD_ERROR,
                             (const uint8_t*)"Invalid block meta", 18, 1);
          session_close((uv_handle_t*)&session->handle);
          break;
        }
        nasfs_block_meta_t* meta = (nasfs_block_meta_t*)plain_frame.payload;
        session->expected_block_seq = meta->seq_num;
        session->expected_block_size = meta->size;
        memcpy(session->expected_block_hash, meta->hash, 32);
        session->has_pending_block_meta = 1;
      }
      break;
    }

    case NASFS_CMD_PUT_DATA: {  // Unencrypted
      if (session->is_authenticated &&
          session->state == SESSION_STATE_RECEIVING_FILE &&
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

          uint8_t computed_hash[32];
          if (crypto_generichash(computed_hash, sizeof(computed_hash),
                                 frame->payload, frame->payload_len, NULL,
                                 0) != 0) {
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

        nasfs_fs_ctx_t* ctx = malloc(sizeof(nasfs_fs_ctx_t));
        if (ctx) {
          ctx->buf =
              uv_buf_init(malloc(frame->payload_len), frame->payload_len);
          memcpy(ctx->buf.base, frame->payload, frame->payload_len);
          ctx->req.data = ctx;
          uv_fs_write(session->handle.loop, &ctx->req, session->active_fd,
                      &ctx->buf, 1, session->file_offset, on_put_fs_write);
          session->file_offset += frame->payload_len;
        }
      }
      break;
    }

    case NASFS_CMD_PUT_DONE:
      if (session->is_authenticated &&
          session->state == SESSION_STATE_RECEIVING_FILE) {
        log_all(LOG_INFO, "Upload complete.");
        if (session->active_fd != -1) {
          uv_fs_close(session->handle.loop, &(uv_fs_t){}, session->active_fd,
                      NULL);
          session->active_fd = -1;
        }
        session->state = SESSION_STATE_AUTHENTICATED;
      }
      break;

    case NASFS_CMD_GET_REQ: {
      if (!session->is_authenticated) {
        session_send_frame(session, NASFS_CMD_ERROR,
                           (const uint8_t*)"Authentication required", 23, 1);
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
      session->file_encryption_enabled = is_enc;
      session->has_pending_block_meta = 0;
      session->server_block_seq = 0;

      char raw[256] = {0};
      memcpy(raw, filename_ptr, filename_len < 255 ? filename_len : 255);
      char path[1024];
      snprintf(path, sizeof(path), "%s/%s",
               global_config.storage_dir ? global_config.storage_dir : ".",
               sanitize_path(raw));
      session->state = SESSION_STATE_SENDING_FILE;
      session->fs_req.data = session;
      uv_fs_open(session->handle.loop, &session->fs_req, path, O_RDONLY, 0,
                 on_get_fs_open);
      break;
    }
    default:
      break;
  }

  if (decrypted_payload) free(decrypted_payload);
}

static void on_socket_write_done(uv_write_t* req, int status) {
  nasfs_write_ctx_t* ctx = (nasfs_write_ctx_t*)req;
  client_session_t* session = (client_session_t*)req->handle->data;
  if (status < 0)
    log_all(LOG_ERROR, "Socket write failed: %s", uv_strerror(status));
  else if (session && session->state == SESSION_STATE_SENDING_FILE &&
           ctx->type == NASFS_CMD_GET_DATA) {
    do_get_next_chunk(session);
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

static void session_on_read(uv_stream_t* stream, ssize_t nread,
                            const uv_buf_t* buf) {
  client_session_t* session = (client_session_t*)stream->data;
  (void)buf;

  if (!session) {
    return;
  }

  if (nread > 0) {
    session->recv_length += (size_t)nread;

    while (session->recv_length > 0) {
      nasfs_frame_t frame;
      int consumed = protocol_parse_frame(session->recv_buffer,
                                          session->recv_length, &frame);
      if (consumed > 0) {
        session_dispatch_frame(session, &frame);
        if (session->state == SESSION_STATE_ERROR) {
          return;
        }
        memmove(session->recv_buffer, session->recv_buffer + consumed,
                session->recv_length - (size_t)consumed);
        session->recv_length -= (size_t)consumed;
      } else {
        if (consumed < 0) {
          session_close((uv_handle_t*)&session->handle);
        }
        break;
      }
    }
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

  session = calloc(1, sizeof(*session));
  if (!session) {
    log_all(LOG_ERROR, "Failed to allocate session context.");
    return;
  }

  session->state = SESSION_STATE_NEW;
  session->active_fd = -1;

  if (uv_tcp_init(server->loop, &session->handle) != 0) {
    free(session);
    return;
  }

  session->handle.data = session;
  if (uv_accept(server, (uv_stream_t*)&session->handle) != 0) {
    uv_close((uv_handle_t*)&session->handle, on_session_handle_closed);
    return;
  }

  log_all(LOG_INFO, "Accepted new client connection.");
  if (uv_read_start((uv_stream_t*)&session->handle, session_alloc_buffer,
                    session_on_read) != 0) {
    session_close((uv_handle_t*)&session->handle);
  }
}
