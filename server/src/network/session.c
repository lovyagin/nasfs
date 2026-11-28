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
#include "network/session_internal.h"
#include "pake.h"

#define INITIAL_RECV_BUFFER_SIZE 16384
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024)

static void log_authenticated_client(const nasfs_auth_payload_t* auth) {
  static const char hex[] = "0123456789abcdef";
  char username[256 * 4 + 4];
  char* out = username;
  const unsigned char* in = (const unsigned char*)auth->username;
  for (size_t i = 0; *in && i < 256; i++, in++) {
    unsigned int byte = *in;
    if (byte < 0x20 || byte >= 0x7f || byte == '\\' || byte == 0x27) {
      *out++ = '\\';
      *out++ = 'x';
      *out++ = hex[byte >> 4u];
      *out++ = hex[byte & 0x0fu];
    } else {
      *out++ = (char)byte;
    }
  }
  if (*in)
    memcpy(out, "...", sizeof("..."));
  else
    *out = '\0';
  log_all(LOG_INFO, "Client '%s' authenticated with %s.", username,
          auth->method);
}

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
typedef struct {
  uv_write_t req;
  uv_buf_t buf;
  nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

/* --- Forward Declarations --- */
static void session_on_read(uv_stream_t* stream, ssize_t nread,
                            const uv_buf_t* buf);
static void session_alloc_buffer(uv_handle_t* handle, size_t suggested_size,
                                 uv_buf_t* buf);
static void on_socket_write_done(uv_write_t* req, int status);
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
  char line[NASFS_AUTH_ALGORITHM_MAX + 1 + 2 * NASFS_AUTH_PUBLIC_KEY_MAX + 2];

  if (!path || !alg || !public_key) {
    return 0;
  }

  file = fopen(path, "r");
  if (!file) {
    return 0;
  }

  int line_status;
  while ((line_status = nasfs_auth_read_line(file, line, sizeof(line))) != 0) {
    if (line_status < 0) continue;
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
      !OQS_SIG_alg_is_enabled(auth->sig_algorithm)) {
    return 0;
  }

  sig = OQS_SIG_new(auth->sig_algorithm);
  if (!sig || auth->public_key_len != sig->length_public_key ||
      !nasfs_auth_keys_fit(auth->sig_algorithm, sig->length_public_key,
                           sig->length_secret_key) ||
      !authorized_key_matches(global_config.authorized_keys_file,
                              auth->sig_algorithm, auth->public_key,
                              auth->public_key_len)) {
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
  free(session->recv_buffer);
  free(session->files.access.subject);
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

void session_finish_close(client_session_t* session) {
  if (nasfs_file_service_close(session) && session->handle_closed)
    session_free(session);
}

static void on_session_handle_closed(uv_handle_t* handle) {
  client_session_t* session = handle->data;
  session->handle_closed = 1;
  session_finish_close(session);
}

void session_close(uv_handle_t* handle) {
  client_session_t* session = handle->data;
  if (!session || session->state == SESSION_STATE_ERROR) return;

  session->state = SESSION_STATE_ERROR;
  log_all(LOG_INFO, "Closing session for client.");
  uv_close(handle, on_session_handle_closed);
  session_finish_close(session);
}

void session_expire_idle(uv_handle_t* handle, void* listener) {
  if (handle->type != UV_TCP || handle == listener || uv_is_closing(handle))
    return;
  client_session_t* session = handle->data;
  nasfs_file_service_on_clock(session);
  if (uv_now(handle->loop) - session->last_activity >=
      (uint64_t)global_config.client_timeout * 1000u) {
    log_all(LOG_WARNING, "Session idle timeout.");
    session_close(handle);
  }
}

/* --- Protocol & Crypto Implementation --- */

int session_send_frame(client_session_t* session, nasfs_cmd_type_t type,
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

  if (nasfs_control_command(frame->type)) {
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
      session->pake_y[0] &= 248u;
      session->pake_y[31] &= 63u;
      session->pake_y[31] |= 64u;

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

      log_authenticated_client(&auth);
      crypto_generichash_state scope;
      crypto_generichash_init(&scope, NULL, 0, 32);
      crypto_generichash_update(&scope, (const uint8_t*)auth.method,
                                strlen(auth.method) + 1);
      crypto_generichash_update(&scope, (const uint8_t*)auth.username,
                                strlen(auth.username) + 1);
      if (auth.public_key_len > 0)
        crypto_generichash_update(&scope, auth.public_key, auth.public_key_len);
      crypto_generichash_final(&scope, session->files.access.scope, 32);
      session->files.access.subject = auth.username;
      auth.username = NULL;
      session->state = SESSION_STATE_AUTHENTICATED;
      session_send_frame(session, NASFS_CMD_AUTH_ACK, NULL, 0, 1);
      nasfs_auth_payload_free(&auth);
      break;
    }

    case NASFS_CMD_PUT_REQ:
    case NASFS_CMD_PUT_RESUME:
    case NASFS_CMD_PUT_BLOCK_META:
    case NASFS_CMD_PUT_DATA:
    case NASFS_CMD_PUT_DONE:
    case NASFS_CMD_GET_REQ:
    case NASFS_CMD_RESOLVE:
    case NASFS_CMD_COLLECT:
    case NASFS_CMD_GET_ADVANCE:
    case NASFS_CMD_GET_REPAIR:
    case NASFS_CMD_PUT_PARITY:
      nasfs_file_service_dispatch(session, plain_frame);
      break;
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
        (ctx->type == NASFS_CMD_GET_INDEX ||
         ctx->type == NASFS_CMD_GET_REPAIR_DATA ||
         (ctx->type == NASFS_CMD_GET_DATA &&
          session->files.header.ecc == NASFS_ECC_OFF))) {
      nasfs_file_service_get_next(session);
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

void process_session_frames(client_session_t* session) {
  /* Retain complete frames in the receive buffer while disk writes drain. */
  while (session->recv_length > 0 && !nasfs_file_service_draining(session) &&
         !nasfs_file_service_at_capacity(session)) {
    nasfs_frame_t frame;
    int consumed = protocol_parse_frame(session->recv_buffer,
                                        session->recv_length, &frame);
    if (consumed <= 0) {
      if (consumed < 0) session_close((uv_handle_t*)&session->handle);
      return;
    }
    session_dispatch_frame(session, &frame);
    if (session->state == SESSION_STATE_ERROR) return;
    memmove(session->recv_buffer, session->recv_buffer + consumed,
            session->recv_length - (size_t)consumed);
    session->recv_length -= (size_t)consumed;
  }
  if (!session->read_paused && nasfs_file_service_at_capacity(session)) {
    uv_read_stop((uv_stream_t*)&session->handle);
    session->read_paused = 1;
  }
}

void session_resume_read(client_session_t* session) {
  if (session->read_paused && session->state != SESSION_STATE_ERROR) {
    process_session_frames(session);
    if (session->state != SESSION_STATE_ERROR &&
        !nasfs_file_service_at_capacity(session)) {
      session->read_paused = 0;
      if (uv_read_start((uv_stream_t*)&session->handle, session_alloc_buffer,
                        session_on_read) < 0) {
        session_close((uv_handle_t*)&session->handle);
      }
    }
  }
}

static void session_on_read(uv_stream_t* stream, ssize_t nread,
                            const uv_buf_t* buf) {
  client_session_t* session = stream->data;
  (void)buf;

  if (session->state == SESSION_STATE_ERROR) return;
  if (nread > 0) {
    session->last_activity = uv_now(stream->loop);
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
  session->files.active_fd = -1;
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
  session->files.store = server->data;
  session->files.trusted_author = trusted_author;
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
