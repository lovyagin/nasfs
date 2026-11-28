/**
 * @file client.c
 * @brief NASFS client connection and file transfer operations.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * Implements an asynchronous libuv-based client that supports
 * PQC key exchange, and subsequent PUT/GET file operations over an
 * encrypted control channel.
 */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <oqs/oqs.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uv.h>

#ifdef __APPLE__
#include <sys/acl.h>
#endif

#include "auth.h"
#include "crypto_engine.h"
#include "defaults.h"
#include "handshake.h"
#include "nasfs_client.h"
#include "pake.h"
#include "protocol.h"

#define CLIENT_INITIAL_BUFFER 16384
#define CLIENT_MAX_RECV_BUFFER (64 * 1024 * 1024)

enum { OP_NONE = 0 };

typedef struct {
  uv_write_t req;
  uv_buf_t buf;
  nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

typedef struct {
  uv_fs_t req;
  uv_buf_t buf;
  uv_stream_t* stream;
} nasfs_fs_ctx_t;

typedef struct {
  crypto_generichash_state file_manifest;
  const char* local_filename;
  const char* remote_filename;
  char* download_parent;
  const char* download_name;
  uint64_t file_offset;
  uint64_t client_block_seq;
  uint64_t expected_block_seq;
  uint64_t put_plaintext_size;      /* size of local file being uploaded */
  uint64_t expected_plaintext_size; /* expected size announced in GET_ACK */
  struct stat download_initial_destination;
  nasfs_client_operation_t current_op;
  uv_file local_fd;
  int download_directory;
  int download_staging;
  int download_had_destination;
  int put_ack_pending;
  int put_result_pending;
  int download_has_owner_slot;
  int batch_upload_exclusive;
  int download_legacy_counter;
  int require_manifest_digest;
  int has_pending_block_meta;
  uint32_t expected_block_size;
  nasfs_cipher_algo_t file_cipher_algo;
  nasfs_hash_algo_t file_hash_algo;
  uint8_t file_salt[crypto_pwhash_SALTBYTES];
  uint8_t manifest_digest[32];
  uint8_t encryption_key[crypto_secretbox_KEYBYTES];
  uint8_t expected_block_hash[32];
  char download_temp_name[sizeof(".nasfs-download.") + 32];
  char download_staging_name[64];
} client_transfer_t;

typedef struct {
  client_transfer_t transfer;
  const nasfs_client_options_t* options;
  const nasfs_client_request_t* batch_queue;
  nasfs_client_result_t* results;
  struct {
    dev_t device;
    ino_t inode;
  } published_downloads[NASFS_MAX_BATCH];
  size_t batch_count;
  size_t batch_idx;

  /* Connection and loop state */
  uv_loop_t* loop;

  uint8_t* client_recv_buffer;
  size_t client_recv_length;
  size_t client_recv_capacity;

  uint8_t* shared_secret;
  size_t shared_secret_len;
  int is_secure;
  uint8_t trusted_server_key[crypto_sign_PUBLICKEYBYTES];
  uint8_t hello_hash[32];
  uint8_t handshake_transcript[32];
  uint8_t ciphertext_hash[32];
  uint8_t auth_context[32];
  uint8_t author_secret[crypto_sign_SECRETKEYBYTES];
  uint8_t author_public[crypto_sign_PUBLICKEYBYTES];
  int allow_unsigned_reads;

  int client_exit_code;
  int client_finished;
  int local_read_pending;
  uv_signal_t interrupt_watcher;
  uv_signal_t terminate_watcher;
  uv_timer_t idle_timer;
  uint64_t last_activity;
  crypto_secretstream_xchacha20poly1305_state send_crypto_state;
  crypto_secretstream_xchacha20poly1305_state recv_crypto_state;

  /* PAKE ephemeral state — valid only during pake handshake */
  uint8_t pake_x[32]; /* client ephemeral scalar */
  uint8_t pake_w[32]; /* password scalar */
  char* negotiated_kex_algorithm;
  char* negotiated_cipher_algorithm;

  /* File Encryption/Integrity State */
  int file_encryption_enabled;
  uint8_t master_key[32];

} nasfs_client_t;

static const char download_lock_name[] = ".publish.lock";

static void report_event(nasfs_client_t* client, nasfs_client_event_t event,
                         uint64_t bytes) {
  const nasfs_client_options_t* options = client->options;
  if (options->notify)
    options->notify(options->callback_data, event, client->batch_idx - 1, bytes,
                    NULL);
}

static void client_message(nasfs_client_t* client, nasfs_client_event_t event,
                           const char* format, ...) {
  const nasfs_client_options_t* options = client->options;
  if (!options->notify) return;
  char message[1024];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  options->notify(options->callback_data, event, 0, 0, message);
}

/* Forward Declarations */
static void send_command(uv_stream_t* stream, nasfs_cmd_type_t cmd,
                         const uint8_t* payload, size_t payload_len,
                         int encrypt);
static void do_put_read_chunk(uv_stream_t* stream);
static void close_connection(uv_handle_t* handle);
static void send_put_req(uv_stream_t* stream);
static void send_get_req(uv_stream_t* stream);
static void start_next_operation(uv_stream_t* stream);

static int read_master_salt(int dir, uint8_t salt[crypto_pwhash_SALTBYTES]) {
  int fd = openat(dir, "master.salt", O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return errno == ENOENT ? 1 : -1;

  struct stat st;
  uint8_t bytes[crypto_pwhash_SALTBYTES + 1];
  int result = -1;
  if (fstat(fd, &st) == 0) {
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077u) != 0) {
      errno = EINVAL;
    } else {
      size_t used = 0;
      while (used < sizeof(bytes)) {
        ssize_t n = read(fd, bytes + used, sizeof(bytes) - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) break;
        if (n == 0) {
          if (used == crypto_pwhash_SALTBYTES) {
            memcpy(salt, bytes, used);
            result = 0;
          } else {
            errno = EINVAL;
          }
          break;
        }
        used += (size_t)n;
      }
      if (used == sizeof(bytes)) errno = EINVAL;
    }
  }
  int saved = errno;
  if (close(fd) < 0 && result == 0) return -1;
  errno = saved;
  return result;
}

static int publish_master_salt(int dir) {
  unsigned char random_suffix[16];
  char name[sizeof(".master.salt.") + 2 * sizeof(random_suffix)];
  uint8_t salt[crypto_pwhash_SALTBYTES];
  randombytes_buf(random_suffix, sizeof(random_suffix));
  memcpy(name, ".master.salt.", sizeof(".master.salt.") - 1);
  sodium_bin2hex(name + sizeof(".master.salt.") - 1,
                 2 * sizeof(random_suffix) + 1, random_suffix,
                 sizeof(random_suffix));
  int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) return -1;

  randombytes_buf(salt, sizeof(salt));
  size_t written = 0;
  int result = -1;
  while (written < sizeof(salt)) {
    ssize_t n = write(fd, salt + written, sizeof(salt) - written);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      if (n == 0) errno = EIO;
      break;
    }
    written += (size_t)n;
  }
  if (written == sizeof(salt)) result = fsync(fd);
  int saved = errno;
  if (close(fd) < 0 && result == 0) {
    result = -1;
    saved = errno;
  }
  if (result == 0 && linkat(dir, name, dir, "master.salt", 0) < 0 &&
      errno != EEXIST) {
    result = -1;
    saved = errno;
  }
  if (unlinkat(dir, name, 0) < 0 && result == 0) return -1;
  errno = saved;
  return result;
}

static int load_master_salt(nasfs_client_t* client,
                            uint8_t salt[crypto_pwhash_SALTBYTES],
                            int allow_create) {
  const char* home = client->options->home;
  if (!home || !*home) {
    errno = ENOENT;
    return -1;
  }

  int home_fd = open(home, O_RDONLY | O_DIRECTORY);
  if (home_fd < 0) return -1;
  int dir = -1;
  int result = -1;
  int saved;
  if (allow_create && mkdirat(home_fd, ".nasfs", 0700) < 0 && errno != EEXIST)
    goto done;
  dir = openat(home_fd, ".nasfs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (dir < 0) goto done;
  struct stat st;
  if (fstat(dir, &st) < 0) goto done;
  if (st.st_uid != geteuid() || (st.st_mode & 022u) != 0) {
    errno = EACCES;
    goto done;
  }

  result = read_master_salt(dir, salt);
  if (result == 1 && allow_create && publish_master_salt(dir) == 0) {
    result = read_master_salt(dir, salt);
  }
  if (result == 0) {
    /* A concurrent reader can observe the link before its creator syncs it. */
    if (fsync(dir) < 0 || fsync(home_fd) < 0) result = -1;
  }

done:
  saved = errno;
  if (dir >= 0) close(dir);
  close(home_fd);
  errno = saved;
  return result == 0 ? 0 : -1;
}

static int load_server_key(nasfs_client_t* client,
                           const struct sockaddr_in* endpoint) {
  if (client->options->server_pin) {
    return nasfs_handshake_read_key(client->options->server_pin,
                                    client->trusted_server_key, 0);
  }
  const char* home = client->options->home;
  char address[16];
  if (!home || uv_ip4_name(endpoint, address, sizeof(address)) != 0) return -1;
  size_t size =
      strlen(home) + sizeof("/.nasfs/server-255.255.255.255-65535.pub");
  char* path = malloc(size);
  if (!path) return -1;
  snprintf(path, size, "%s/.nasfs/server-%s-%u.pub", home, address,
           (unsigned)ntohs(endpoint->sin_port));
  int result = nasfs_handshake_read_key(path, client->trusted_server_key, 0);
  if (result < 0)
    client_message(client, NASFS_CLIENT_ERROR,
                   "Missing or invalid server pin: %s\n", path);
  free(path);
  return result;
}
static int auth_method_requires_password(const char* method) {
  return strcmp(method, NASFS_AUTH_METHOD_PASSWORD) == 0 ||
         strcmp(method, NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY) == 0;
}

static int auth_method_requires_publickey(const char* method) {
  return strcmp(method, NASFS_AUTH_METHOD_PUBLICKEY) == 0 ||
         strcmp(method, NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY) == 0;
}

static void trim_line(char* line) {
  size_t len;

  if (!line) {
    return;
  }

  len = strlen(line);
  while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
    line[--len] = '\0';
  }
}

static int load_identity_file(nasfs_client_t* client, const char* path,
                              const char* expected_algorithm, char** algorithm,
                              uint8_t** public_key, size_t* public_key_len,
                              uint8_t** secret_key, size_t* secret_key_len) {
  FILE* file;
  char header[128];
  char alg_line[NASFS_AUTH_ALGORITHM_MAX + 2];
  char public_hex[2 * NASFS_AUTH_PUBLIC_KEY_MAX + 2];
  char secret_hex[2 * NASFS_AUTH_SECRET_KEY_MAX + 2];

  if (!path || !algorithm || !public_key || !public_key_len || !secret_key ||
      !secret_key_len) {
    return -1;
  }

  file = fopen(path, "r");
  if (!file) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Failed to open identity file: %s\n", path);
    return -1;
  }

  if (nasfs_auth_read_line(file, header, sizeof(header)) != 1 ||
      nasfs_auth_read_line(file, alg_line, sizeof(alg_line)) != 1 ||
      nasfs_auth_read_line(file, public_hex, sizeof(public_hex)) != 1 ||
      nasfs_auth_read_line(file, secret_hex, sizeof(secret_hex)) != 1) {
    fclose(file);
    return -1;
  }
  fclose(file);

  trim_line(header);
  trim_line(alg_line);
  trim_line(public_hex);
  trim_line(secret_hex);

  if (strcmp(header, "NASFS-MLDSA-PRIVATE-v1") != 0 ||
      !nasfs_auth_keys_fit(alg_line, strlen(public_hex) / 2,
                           strlen(secret_hex) / 2) ||
      (expected_algorithm && expected_algorithm[0] != '\0' &&
       strcmp(expected_algorithm, alg_line) != 0)) {
    return -1;
  }

  *algorithm = strdup(alg_line);
  *public_key = nasfs_hex_decode(public_hex, public_key_len);
  *secret_key = nasfs_hex_decode(secret_hex, secret_key_len);

  if (!*algorithm || !*public_key || !*secret_key) {
    free(*algorithm);
    free(*public_key);
    free(*secret_key);
    *algorithm = NULL;
    *public_key = NULL;
    *secret_key = NULL;
    return -1;
  }

  return 0;
}

static int build_publickey_signature(nasfs_client_t* client, char** algorithm,
                                     uint8_t** public_key,
                                     size_t* public_key_len,
                                     uint8_t** signature,
                                     size_t* signature_len) {
  uint8_t* secret_key = NULL;
  size_t secret_key_len = 0;
  uint8_t* message = NULL;
  size_t message_len = 0;
  OQS_SIG* sig = NULL;
  int rc = -1;

  if (!client->options->identity_file) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "NASFS_IDENTITY_FILE is required for publickey auth\n");
    return -1;
  }

  if (load_identity_file(client, client->options->identity_file,
                         client->options->auth_sig_algorithm, algorithm,
                         public_key, public_key_len, &secret_key,
                         &secret_key_len) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Failed to load identity file\n");
    return -1;
  }

  sig = OQS_SIG_new(*algorithm);
  if (!sig || *public_key_len != sig->length_public_key ||
      secret_key_len != sig->length_secret_key) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Identity file does not match signature algorithm\n");
    goto out;
  }

  message = nasfs_auth_build_message(
      client->options->auth_method, client->options->auth_user,
      client->auth_context, sizeof(client->auth_context), &message_len);
  *signature = malloc(sig->length_signature);
  if (!message || !*signature) {
    goto out;
  }

  if (OQS_SIG_sign(sig, *signature, signature_len, message, message_len,
                   secret_key) == OQS_SUCCESS) {
    rc = 0;
  }

out:
  if (rc != 0) {
    free(*algorithm);
    free(*public_key);
    free(*signature);
    *algorithm = NULL;
    *public_key = NULL;
    *signature = NULL;
    *public_key_len = 0;
    *signature_len = 0;
  }
  if (sig) OQS_SIG_free(sig);
  free(secret_key);
  free(message);
  return rc;
}

static void send_pake_hello(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  if (pake_derive_scalar(client->options->auth_password, client->pake_w) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "PAKE: failed to derive password scalar\n");
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }
  randombytes_buf(client->pake_x, sizeof(client->pake_x));
  client->pake_x[0] &= 248u;
  client->pake_x[31] &= 63u;
  client->pake_x[31] |= 64u;

  uint8_t X[crypto_core_ristretto255_BYTES];
  if (pake_client_compute_share(client->pake_w, client->pake_x, X) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "PAKE: failed to compute client share\n");
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }

  uint8_t ulen = (uint8_t)strlen(client->options->auth_user);
  size_t payload_len = 1 + ulen + sizeof(X);
  uint8_t* payload = malloc(payload_len);
  if (!payload) {
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }
  payload[0] = ulen;
  memcpy(payload + 1, client->options->auth_user, ulen);
  memcpy(payload + 1 + ulen, X, sizeof(X));
  send_command(stream, NASFS_CMD_PAKE_HELLO, payload, payload_len, 1);
  free(payload);
}

static void send_pake_auth_proof(uv_stream_t* stream, const uint8_t* Y) {
  nasfs_client_t* client = stream->data;
  uint8_t K[32];
  if (pake_client_derive_key(client->pake_w, client->pake_x, Y, K) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "PAKE: failed to derive session key\n");
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }

  uint8_t proof[32];
  const uint8_t tag[] = "client";
  if (crypto_generichash(proof, sizeof(proof), K, sizeof(K), tag,
                         sizeof(tag) - 1) != 0) {
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }

  char* proof_hex = nasfs_hex_encode(proof, sizeof(proof));
  if (!proof_hex) {
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }

  nasfs_auth_payload_t auth = {0};
  auth.method = (char*)NASFS_AUTH_METHOD_PAKE;
  auth.username = (char*)client->options->auth_user;
  auth.password = proof_hex;

  size_t payload_len = 0;
  uint8_t* payload = nasfs_auth_pack(&auth, &payload_len);
  free(proof_hex);
  if (!payload) {
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }
  send_command(stream, NASFS_CMD_AUTH, payload, payload_len, 1);
  free(payload);
}

static void send_auth(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  nasfs_auth_payload_t auth = {0};
  uint8_t* payload = NULL;
  size_t payload_len = 0;
  char* sig_algorithm = NULL;
  char* password_proof_hex = NULL;

  auth.method = (char*)client->options->auth_method;
  auth.username = (char*)client->options->auth_user;
  if (auth_method_requires_password(client->options->auth_method)) {
    // 1. Domain Separation: Compute client-side memory-hard authentication
    // password P_auth
    uint8_t p_auth[32];
    uint8_t auth_salt[crypto_pwhash_SALTBYTES];
    // Static domain salt for authentication
    memset(auth_salt, 0x55, sizeof(auth_salt));

    if (crypto_pwhash(p_auth, sizeof(p_auth), client->options->auth_password,
                      strlen(client->options->auth_password), auth_salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Failed to derive P_auth using Argon2id\n");
      client->client_exit_code = 1;
      close_connection((uv_handle_t*)stream);
      return;
    }

    // 2. DoS-safe Fast Challenge-Response: Proof = BLAKE2b(auth_context,
    // key=P_auth)
    uint8_t proof[32];
    if (crypto_generichash(proof, sizeof(proof), client->auth_context,
                           sizeof(client->auth_context), p_auth,
                           sizeof(p_auth)) != 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Failed to compute fast session password proof\n");
      client->client_exit_code = 1;
      close_connection((uv_handle_t*)stream);
      return;
    }
    password_proof_hex = nasfs_hex_encode(proof, sizeof(proof));
    auth.password = password_proof_hex;
  }

  if (auth_method_requires_publickey(client->options->auth_method) &&
      build_publickey_signature(client, &sig_algorithm, &auth.public_key,
                                &auth.public_key_len, &auth.signature,
                                &auth.signature_len) != 0) {
    client->client_exit_code = 1;
    free(password_proof_hex);
    close_connection((uv_handle_t*)stream);
    return;
  }
  auth.sig_algorithm = sig_algorithm;

  payload = nasfs_auth_pack(&auth, &payload_len);
  free(sig_algorithm);
  free(auth.public_key);
  free(auth.signature);
  free(password_proof_hex);
  if (!payload) {
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }

  send_command(stream, NASFS_CMD_AUTH, payload, payload_len, 1);
  free(payload);
}

static void alloc_buffer(uv_handle_t* handle, size_t suggested_size,
                         uv_buf_t* buf) {
  nasfs_client_t* client = handle->data;
  if (client->client_recv_capacity - client->client_recv_length <
      suggested_size) {
    size_t new_cap = client->client_recv_capacity == 0
                         ? CLIENT_INITIAL_BUFFER
                         : client->client_recv_capacity * 2;
    while (new_cap - client->client_recv_length < suggested_size) new_cap *= 2;
    if (new_cap > CLIENT_MAX_RECV_BUFFER) {
      buf->base = NULL;
      buf->len = 0;
      close_connection(handle);
      return;
    }
    uint8_t* new_buf = realloc(client->client_recv_buffer, new_cap);
    if (!new_buf) {
      buf->base = NULL;
      buf->len = 0;
      close_connection(handle);
      return;
    }
    client->client_recv_buffer = new_buf;
    client->client_recv_capacity = new_cap;
  }
  buf->base = (char*)(client->client_recv_buffer + client->client_recv_length);
  buf->len = client->client_recv_capacity - client->client_recv_length;
}

/* Send PUT_REQ for the current local_filename / remote_filename. */
static void send_put_req(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  transfer->local_fd = open(transfer->local_filename, O_RDONLY | O_NONBLOCK);
  if (transfer->local_fd < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot open PUT source '%s': %s\n",
                   transfer->local_filename, strerror(errno));
    close_connection((uv_handle_t*)stream);
    return;
  }

  struct stat st;
  if (fstat(transfer->local_fd, &st) < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot stat PUT source '%s': %s\n",
                   transfer->local_filename, strerror(errno));
    close_connection((uv_handle_t*)stream);
    return;
  }
  if (!S_ISREG(st.st_mode) || st.st_size < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "PUT source must be a regular file: %s\n",
                   transfer->local_filename);
    close_connection((uv_handle_t*)stream);
    return;
  }
  transfer->put_plaintext_size = (uint64_t)st.st_size;
  transfer->put_ack_pending = 1;

  size_t fn_len = strlen(transfer->remote_filename);
  if (client->file_encryption_enabled) {
    size_t payload_len =
        1 + NASFS_FILE_METADATA_SIZE + NASFS_OWNER_SLOT_V1_SIZE + fn_len + 1;
    uint8_t* req_payload = malloc(payload_len);
    if (!req_payload) {
      close_connection((uv_handle_t*)stream);
      return;
    }
    req_payload[0] = transfer->batch_upload_exclusive
                         ? NASFS_PUT_REQUEST_EXCLUSIVE
                         : NASFS_FILE_REQUEST_PORTABLE;
    randombytes_buf(transfer->file_salt, crypto_pwhash_SALTBYTES);
    uint8_t owner_slot[NASFS_OWNER_SLOT_V1_SIZE];
    if (crypto_engine_create_owner_slot(owner_slot, transfer->encryption_key,
                                        client->master_key,
                                        transfer->file_salt) != 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Failed to create NASLUKS owner slot\n");
      free(req_payload);
      close_connection((uv_handle_t*)stream);
      return;
    }
    size_t off = 1;
    memcpy(req_payload + off, transfer->file_salt, crypto_pwhash_SALTBYTES);
    off += crypto_pwhash_SALTBYTES;
    protocol_store_u64(req_payload + off, transfer->put_plaintext_size);
    off += sizeof(uint64_t);
    req_payload[off++] = (uint8_t)transfer->file_cipher_algo;
    req_payload[off++] = (uint8_t)transfer->file_hash_algo;
    memcpy(req_payload + off, owner_slot, sizeof(owner_slot));
    off += sizeof(owner_slot);
    memcpy(req_payload + off, (const uint8_t*)transfer->remote_filename,
           fn_len + 1);
    protocol_manifest_init(
        &transfer->file_manifest, transfer->remote_filename,
        transfer->put_plaintext_size, transfer->file_salt,
        transfer->file_cipher_algo | NASFS_FILE_CIPHER_PORTABLE,
        transfer->file_hash_algo);
    protocol_manifest_owner_slot(&transfer->file_manifest, owner_slot,
                                 sizeof(owner_slot));
    send_command(stream, NASFS_CMD_PUT_REQ, req_payload, payload_len, 1);
    free(req_payload);
  } else {
    size_t payload_len = 1 + fn_len + 1;
    uint8_t* req_payload = malloc(payload_len);
    if (!req_payload) {
      close_connection((uv_handle_t*)stream);
      return;
    }
    req_payload[0] = 0;
    memcpy(req_payload + 1, (const uint8_t*)transfer->remote_filename,
           fn_len + 1);
    send_command(stream, NASFS_CMD_PUT_REQ, req_payload, payload_len, 1);
    free(req_payload);
  }
}

/* Send GET_REQ for the current remote_filename. */
static void send_get_req(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  size_t fn_len = strlen(transfer->remote_filename);
  size_t payload_len = 1 + fn_len + 1;
  uint8_t* req_payload = malloc(payload_len);
  if (!req_payload) {
    close_connection((uv_handle_t*)stream);
    return;
  }
  req_payload[0] =
      client->file_encryption_enabled ? NASFS_FILE_REQUEST_PORTABLE : 0;
  memcpy(req_payload + 1, (const uint8_t*)transfer->remote_filename,
         fn_len + 1);
  send_command(stream, NASFS_CMD_GET_REQ, req_payload, payload_len, 1);
  free(req_payload);
}

static int close_local_file(nasfs_client_t* client) {
  if (client->transfer.local_fd == -1) return 0;

  uv_fs_t req;
  int rc = uv_fs_close(client->loop, &req, client->transfer.local_fd, NULL);
  uv_fs_req_cleanup(&req);
  client->transfer.local_fd = -1;
  if (rc < 0) {
    client_message(client, NASFS_CLIENT_ERROR, "Local file close failed: %s\n",
                   uv_strerror(rc));
    client->client_exit_code = 1;
  }
  return rc;
}

static void discard_download(nasfs_client_t* client) {
  if (client->transfer.download_staging >= 0) {
    if (client->transfer.download_temp_name[0] &&
        unlinkat(client->transfer.download_staging,
                 client->transfer.download_temp_name, 0) < 0 &&
        errno != ENOENT) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Cannot remove temporary download '%s': %s\n",
                     client->transfer.download_temp_name, strerror(errno));
    }
    close(client->transfer.download_staging);
    client->transfer.download_staging = -1;
    client->transfer.download_temp_name[0] = '\0';
  }
  if (client->transfer.download_directory >= 0) {
    close(client->transfer.download_directory);
    client->transfer.download_directory = -1;
  }
  free(client->transfer.download_parent);
  client->transfer.download_parent = NULL;
}

static int prepare_download(nasfs_client_t* client) {
  const char* slash = strrchr(client->transfer.local_filename, '/');
  const char* name = slash ? slash + 1 : client->transfer.local_filename;
  if (!*name) {
    errno = EINVAL;
    return -1;
  }
  client->transfer.download_parent =
      slash ? strndup(client->transfer.local_filename,
                      (size_t)(name - client->transfer.local_filename))
            : strdup(".");
  if (!client->transfer.download_parent) return -1;
  client->transfer.download_directory = open(
      client->transfer.download_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (client->transfer.download_directory < 0) return -1;
  client->transfer.download_name = name;
  client->transfer.download_had_destination =
      fstatat(client->transfer.download_directory,
              client->transfer.download_name,
              &client->transfer.download_initial_destination,
              AT_SYMLINK_NOFOLLOW) == 0;
  if (!client->transfer.download_had_destination && errno != ENOENT) return -1;
  return 0;
}

static int private_download_entry(int fd, const struct stat* st) {
  if (st->st_uid != geteuid() || (st->st_mode & 077u) != 0) return 0;
#ifdef __APPLE__
  acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
  if (!acl) return errno == ENOENT;
  acl_entry_t entry;
  int rc = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  int empty = rc < 0 && errno == EINVAL;
  acl_free(acl);
  return empty;
#else
  (void)fd;
  return 1;
#endif
}

static int open_download_staging(nasfs_client_t* client) {
  struct stat parent, staging;
  snprintf(client->transfer.download_staging_name,
           sizeof(client->transfer.download_staging_name), ".nasfs-client.%lu",
           (unsigned long)geteuid());
  if (mkdirat(client->transfer.download_directory,
              client->transfer.download_staging_name, 0700) < 0 &&
      errno != EEXIST)
    return -1;
  client->transfer.download_staging =
      openat(client->transfer.download_directory,
             client->transfer.download_staging_name,
             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (client->transfer.download_staging < 0 ||
      fstat(client->transfer.download_directory, &parent) < 0 ||
      fstat(client->transfer.download_staging, &staging) < 0)
    return -1;
  if (parent.st_dev != staging.st_dev ||
      !private_download_entry(client->transfer.download_staging, &staging)) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

static int open_download_file(nasfs_client_t* client) {
  if (open_download_staging(client) < 0) return -1;
  static const char prefix[] = ".nasfs-download.";
  char candidate[sizeof(client->transfer.download_temp_name)] =
      ".nasfs-download.";
  for (int attempt = 0; attempt < 8; attempt++) {
    unsigned char random_id[16];
    randombytes_buf(random_id, sizeof(random_id));
    sodium_bin2hex(candidate + sizeof(prefix) - 1,
                   sizeof(candidate) - sizeof(prefix) + 1, random_id,
                   sizeof(random_id));
    int fd = openat(client->transfer.download_staging, candidate,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
      memcpy(client->transfer.download_temp_name, candidate, sizeof(candidate));
      client->transfer.local_fd = fd;
      return 0;
    }
    if (errno != EEXIST) return -1;
  }
  return -1;
}

static int same_download_entry(const struct stat* first,
                               const struct stat* second) {
  return first->st_dev == second->st_dev && first->st_ino == second->st_ino;
}

static int same_download_snapshot(const struct stat* first,
                                  const struct stat* second) {
#ifdef __APPLE__
  const struct timespec mtime1 = first->st_mtimespec;
  const struct timespec mtime2 = second->st_mtimespec;
  const struct timespec ctime1 = first->st_ctimespec;
  const struct timespec ctime2 = second->st_ctimespec;
#else
  const struct timespec mtime1 = first->st_mtim;
  const struct timespec mtime2 = second->st_mtim;
  const struct timespec ctime1 = first->st_ctim;
  const struct timespec ctime2 = second->st_ctim;
#endif
  return same_download_entry(first, second) &&
         first->st_size == second->st_size &&
         first->st_mode == second->st_mode && first->st_uid == second->st_uid &&
         first->st_gid == second->st_gid && mtime1.tv_sec == mtime2.tv_sec &&
         mtime1.tv_nsec == mtime2.tv_nsec && ctime1.tv_sec == ctime2.tv_sec &&
         ctime1.tv_nsec == ctime2.tv_nsec;
}

static int check_download_parent(nasfs_client_t* client) {
  struct stat opened;
  struct stat named;
  if (fstat(client->transfer.download_directory, &opened) == 0 &&
      stat(client->transfer.download_parent, &named) == 0 &&
      same_download_entry(&opened, &named))
    return 0;
  client_message(client, NASFS_CLIENT_ERROR,
                 "Download destination directory changed: '%s'\n",
                 client->transfer.download_parent);
  return -1;
}

static int replace_download(nasfs_client_t* client) {
  client_transfer_t* transfer = &client->transfer;
  struct stat destination;
  if (fstatat(transfer->download_directory, transfer->download_name,
              &destination, AT_SYMLINK_NOFOLLOW) < 0) {
    if (errno == ENOENT) errno = EAGAIN;
    return -1;
  }
  if (!same_download_snapshot(&destination,
                              &transfer->download_initial_destination)) {
    errno = EAGAIN;
    return -1;
  }
  if (!S_ISREG(destination.st_mode)) {
    errno = EINVAL;
    return -1;
  }
  if (!(destination.st_mode & (unsigned)(S_IWUSR | S_IWGRP | S_IWOTH))) {
    errno = EACCES;
    return -1;
  }
  for (size_t i = 0; i + 1 < client->batch_idx; i++) {
    if (destination.st_dev == client->published_downloads[i].device &&
        destination.st_ino == client->published_downloads[i].inode) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Duplicate batch destination: '%s' aliases '%s'\n",
                     transfer->local_filename,
                     client->batch_queue[i].local_path);
      errno = EEXIST;
      return -1;
    }
  }
  if (faccessat(transfer->download_directory, transfer->download_name, W_OK,
                AT_EACCESS | AT_SYMLINK_NOFOLLOW) < 0)
    return -1;

  struct stat current;
  if (fstatat(transfer->download_directory, transfer->download_name, &current,
              AT_SYMLINK_NOFOLLOW) < 0)
    return -1;
  if (!same_download_snapshot(&transfer->download_initial_destination,
                              &current)) {
    errno = EAGAIN;
    return -1;
  }
  if (renameat(transfer->download_staging, transfer->download_temp_name,
               transfer->download_directory, transfer->download_name) < 0)
    return -1;
  transfer->download_temp_name[0] = '\0';
  return 0;
}

static int lock_download_replacement(nasfs_client_t* client) {
  int lock =
      openat(client->transfer.download_staging, download_lock_name,
             O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
  if (lock < 0) return -1;
  struct stat opened, named, staging, named_staging;
  int error = EACCES;
  if (fstat(lock, &opened) == 0 && S_ISREG(opened.st_mode) &&
      opened.st_nlink == 1 && private_download_entry(lock, &opened)) {
    if (flock(lock, LOCK_EX) < 0) {
      error = errno;
    } else if (fstatat(client->transfer.download_staging, download_lock_name,
                       &named, AT_SYMLINK_NOFOLLOW) == 0 &&
               same_download_entry(&opened, &named) &&
               fstat(client->transfer.download_staging, &staging) == 0 &&
               fstatat(client->transfer.download_directory,
                       client->transfer.download_staging_name, &named_staging,
                       AT_SYMLINK_NOFOLLOW) == 0 &&
               same_download_entry(&staging, &named_staging)) {
      return lock;
    }
  }
  close(lock);
  errno = error;
  return -1;
}

static int publish_download(nasfs_client_t* client) {
  client_transfer_t* transfer = &client->transfer;
  struct stat downloaded, named;
  if (fstat(transfer->local_fd, &downloaded) < 0 ||
      fstatat(transfer->download_staging, transfer->download_temp_name, &named,
              AT_SYMLINK_NOFOLLOW) < 0 ||
      !same_download_snapshot(&downloaded, &named)) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Download staging changed: '%s'\n",
                   transfer->local_filename);
    return -1;
  }
  if (close_local_file(client) < 0 || check_download_parent(client) < 0)
    return -1;

  int rc;
  if (transfer->download_had_destination) {
    // The lock coordinates NASFS publishers. External writers must also
    // coordinate to avoid a race between the final check and renameat.
    int lock = lock_download_replacement(client);
    if (lock < 0) {
      rc = -1;
    } else {
      rc = check_download_parent(client) < 0 ? -1 : replace_download(client);
      int error = errno;
      close(lock);
      errno = error;
    }
  } else {
    rc = linkat(transfer->download_staging, transfer->download_temp_name,
                transfer->download_directory, transfer->download_name, 0);
  }
  if (rc < 0) {
    const char* reason = errno == EAGAIN ? "destination changed during transfer"
                                         : strerror(errno);
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot publish download '%s': %s\n",
                   transfer->local_filename, reason);
    return -1;
  }
  if (client->batch_count > 1) {
    client->published_downloads[client->batch_idx - 1].device =
        downloaded.st_dev;
    client->published_downloads[client->batch_idx - 1].inode =
        downloaded.st_ino;
  }
  discard_download(client);
  return 0;
}

/* Reset per-file transfer state and start the next queued operation. */
static void start_next_operation(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  if (close_local_file(client) < 0) {
    close_connection((uv_handle_t*)stream);
    return;
  }
  transfer->file_offset = 0;
  transfer->client_block_seq = 0;
  transfer->has_pending_block_meta = 0;
  transfer->expected_block_size = 0;
  transfer->expected_plaintext_size = 0;

  if (client->batch_idx >= client->batch_count) {
    client->client_finished = 1;
    close_connection((uv_handle_t*)stream);
    return;
  }

  const nasfs_client_request_t* op = &client->batch_queue[client->batch_idx++];
  transfer->current_op = op->operation;
  transfer->batch_upload_exclusive = op->create_only;
  client->results[client->batch_idx - 1].outcome = NASFS_CLIENT_FAILED;
  transfer->local_filename = op->local_path;
  transfer->remote_filename = op->remote_name;

  report_event(client, NASFS_CLIENT_STARTED, 0);

  if (transfer->current_op == NASFS_CLIENT_PUT) {
    send_put_req(stream);
  } else {
    if (prepare_download(client) < 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Cannot prepare download '%s': %s\n",
                     transfer->local_filename, strerror(errno));
      close_connection((uv_handle_t*)stream);
      return;
    }
    send_get_req(stream);
  }
}

static void close_connection(uv_handle_t* handle) {
  nasfs_client_t* client = handle->data;
  if (uv_is_closing(handle)) return;
  if (!client->client_finished && client->client_exit_code == 0)
    client->client_exit_code = 1;
  if (client->transfer.put_result_pending) {
    client->results[client->batch_idx - 1].outcome = NASFS_CLIENT_PUT_UNKNOWN;
    client_message(
        client, NASFS_CLIENT_ERROR,
        "PUT outcome unknown for '%s': no valid publication response\n",
        client->transfer.remote_filename);
  }
  uv_close(handle, NULL);
  if (client->interrupt_watcher.data)
    uv_close((uv_handle_t*)&client->interrupt_watcher, NULL);
  if (client->terminate_watcher.data)
    uv_close((uv_handle_t*)&client->terminate_watcher, NULL);
  if (client->idle_timer.data)
    uv_close((uv_handle_t*)&client->idle_timer, NULL);
  if (!client->local_read_pending) close_local_file(client);
  discard_download(client);
  client_message(client, NASFS_CLIENT_INFO, "\nConnection closed.\n");
}

static void on_client_signal(uv_signal_t* watcher, int signum) {
  nasfs_client_t* client = ((uv_handle_t*)watcher->data)->data;
  client_message(client, NASFS_CLIENT_ERROR,
                 "Transfer interrupted by signal %d\n", signum);
  client->client_exit_code = 128 + signum;
  if (client->batch_idx)
    client->results[client->batch_idx - 1].outcome = NASFS_CLIENT_CANCELLED;
  close_connection(watcher->data);
}

static void on_client_timeout(uv_timer_t* timer) {
  nasfs_client_t* client = ((uv_handle_t*)timer->data)->data;
  if (client->options->should_cancel &&
      client->options->should_cancel(client->options->callback_data)) {
    if (client->batch_idx)
      client->results[client->batch_idx - 1].outcome = NASFS_CLIENT_CANCELLED;
    close_connection(timer->data);
    return;
  }
  if (uv_now(timer->loop) - client->last_activity >= 30000) {
    client_message(client, NASFS_CLIENT_ERROR, "Connection idle timeout\n");
    close_connection(timer->data);
  }
}

static void on_write(uv_write_t* req, int status) {
  nasfs_client_t* client = req->handle->data;
  nasfs_write_ctx_t* ctx = (nasfs_write_ctx_t*)req;
  uv_stream_t* stream = req->handle;
  if (status) {
    client_message(client, NASFS_CLIENT_ERROR, "Write error: %s\n",
                   uv_strerror(status));
    close_connection((uv_handle_t*)stream);
  } else {
    client->last_activity = uv_now(stream->loop);
  }

  if (ctx->buf.base) free(ctx->buf.base);
  if (client->transfer.current_op == NASFS_CLIENT_PUT &&
      !uv_is_closing((uv_handle_t*)stream)) {
    if (client->transfer.local_fd != -1 && ctx->type == NASFS_CMD_PUT_DATA) {
      free(ctx);
      do_put_read_chunk(stream);
      return;
    }
  }

  free(ctx);
}

static void send_command(uv_stream_t* stream, nasfs_cmd_type_t cmd,
                         const uint8_t* payload, size_t payload_len,
                         int encrypt) {
  nasfs_client_t* client = stream->data;
  if (uv_is_closing((uv_handle_t*)stream)) return;

  uint8_t* payload_to_pack = (uint8_t*)payload;
  size_t payload_to_pack_len = payload_len;
  uint8_t* encrypted_payload = NULL;

  if (encrypt && client->is_secure) {
    payload_to_pack_len =
        payload_len + crypto_secretstream_xchacha20poly1305_ABYTES;
    encrypted_payload = malloc(payload_to_pack_len);
    if (!encrypted_payload) goto fail;

    uint8_t command = (uint8_t)cmd;
    if (crypto_secretstream_xchacha20poly1305_push(
            &client->send_crypto_state, encrypted_payload, NULL, payload,
            payload_len, &command, sizeof(command),
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
      free(encrypted_payload);
      goto fail;
    }
    payload_to_pack = encrypted_payload;
  }

  size_t frame_size;
  uint8_t* frame_data = protocol_pack_frame(cmd, payload_to_pack,
                                            payload_to_pack_len, &frame_size);
  if (encrypted_payload) free(encrypted_payload);
  if (!frame_data) goto fail;

  nasfs_write_ctx_t* ctx = malloc(sizeof(nasfs_write_ctx_t));
  if (!ctx) {
    free(frame_data);
    goto fail;
  }

  ctx->buf = uv_buf_init((char*)frame_data, frame_size);
  ctx->type = cmd;
  int rc = uv_write(&ctx->req, stream, &ctx->buf, 1, on_write);
  if (rc == 0) {
    if (cmd == NASFS_CMD_PUT_DONE) client->transfer.put_result_pending = 1;
    return;
  }

  client_message(client, NASFS_CLIENT_ERROR, "Write submission failed: %s\n",
                 uv_strerror(rc));
  free(frame_data);
  free(ctx);
fail:
  close_connection((uv_handle_t*)stream);
}

static void on_local_read(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = req->data;
  uv_stream_t* stream = ctx->stream;
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;

  client->local_read_pending = 0;
  if (uv_is_closing((uv_handle_t*)stream)) {
    close_local_file(client);
    goto cleanup;
  }
  if (req->result < 0) {
    client_message(client, NASFS_CLIENT_ERROR, "\nRead error: %s\n",
                   uv_strerror((int)req->result));
    client->client_exit_code = 1;
    close_connection((uv_handle_t*)stream);
  } else if ((req->result == 0 &&
              transfer->file_offset != transfer->put_plaintext_size) ||
             (uint64_t)req->result >
                 transfer->put_plaintext_size - transfer->file_offset) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "PUT source size changed during upload: %s\n",
                   transfer->local_filename);
    close_connection((uv_handle_t*)stream);
  } else if (req->result == 0) {
    client_message(client, NASFS_CLIENT_INFO,
                   "\nFinished reading local file. Waiting for publication.\n");
    uint8_t manifest[NASFS_MANIFEST_SIZE];
    if (protocol_manifest_sign(&transfer->file_manifest, manifest,
                               client->author_secret) != 0) {
      close_connection((uv_handle_t*)stream);
      goto cleanup;
    }
    memcpy(transfer->manifest_digest, manifest,
           sizeof(transfer->manifest_digest));
    send_command(stream, NASFS_CMD_PUT_DONE, manifest, sizeof(manifest), 1);
  } else {
    size_t bytes_read = req->result;
    transfer->file_offset += bytes_read;

    if (client->file_encryption_enabled) {
      size_t ciphertext_len = bytes_read + 32; /* max overhead for any cipher */
      uint8_t* ciphertext = malloc(ciphertext_len);
      if (!ciphertext) {
        client_message(client, NASFS_CLIENT_ERROR,
                       "\nOut of memory for encryption\n");
        client->client_exit_code = 1;
        close_connection((uv_handle_t*)stream);
        goto cleanup;
      }

      uint8_t block_key[crypto_secretbox_KEYBYTES];
      crypto_engine_derive_block_key(block_key, transfer->encryption_key,
                                     transfer->file_salt,
                                     transfer->client_block_seq, 0);

      size_t actual_ciphertext_len = 0;
      if (crypto_engine_encrypt_block(
              transfer->file_cipher_algo, (const uint8_t*)ctx->buf.base,
              bytes_read, block_key, transfer->client_block_seq, ciphertext,
              &actual_ciphertext_len) != 0) {
        client_message(client, NASFS_CLIENT_ERROR, "\nEncryption failed\n");
        free(ciphertext);
        client->client_exit_code = 1;
        close_connection((uv_handle_t*)stream);
        goto cleanup;
      }
      ciphertext_len = actual_ciphertext_len;

      nasfs_block_meta_t meta;
      meta.seq_num = transfer->client_block_seq;
      meta.size = (uint32_t)ciphertext_len;
      memset(meta.hash, 0, sizeof(meta.hash));
      size_t hash_out_len = 0;
      if (crypto_engine_hash(transfer->file_hash_algo, ciphertext,
                             ciphertext_len, meta.hash, &hash_out_len) != 0) {
        client_message(client, NASFS_CLIENT_ERROR,
                       "\nHash computation failed\n");
        free(ciphertext);
        client->client_exit_code = 1;
        close_connection((uv_handle_t*)stream);
        goto cleanup;
      }

      uint8_t encoded_meta[NASFS_BLOCK_META_SIZE];
      protocol_encode_block_meta(encoded_meta, &meta);
      send_command(stream, NASFS_CMD_PUT_BLOCK_META, encoded_meta,
                   sizeof(encoded_meta), 1);
      transfer->client_block_seq++;

      protocol_manifest_record(&transfer->file_manifest, ciphertext,
                               ciphertext_len);
      send_command(stream, NASFS_CMD_PUT_DATA, ciphertext, ciphertext_len, 0);
      free(ciphertext);
    } else {
      send_command(stream, NASFS_CMD_PUT_DATA, (uint8_t*)ctx->buf.base,
                   bytes_read, 1);
    }

    report_event(client, NASFS_CLIENT_PROGRESS, transfer->file_offset);
    fflush(stdout);
  }
cleanup:
  free(ctx->buf.base);
  uv_fs_req_cleanup(req);
  free(ctx);
}

static void do_put_read_chunk(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  nasfs_fs_ctx_t* ctx = malloc(sizeof(*ctx));
  if (!ctx) {
    close_connection((uv_handle_t*)stream);
    return;
  }
  ctx->buf = uv_buf_init(malloc(client->options->block_size),
                         client->options->block_size);
  if (!ctx->buf.base) {
    free(ctx);
    close_connection((uv_handle_t*)stream);
    return;
  }
  ctx->stream = stream;
  ctx->req.data = ctx;
  int rc =
      uv_fs_read(client->loop, &ctx->req, client->transfer.local_fd, &ctx->buf,
                 1, client->transfer.file_offset, on_local_read);
  if (rc < 0) {
    client_message(client, NASFS_CLIENT_ERROR, "Read submission failed: %s\n",
                   uv_strerror(rc));
    uv_fs_req_cleanup(&ctx->req);
    free(ctx->buf.base);
    free(ctx);
    close_connection((uv_handle_t*)stream);
    return;
  }
  client->local_read_pending = 1;
}

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  (void)buf;

  if (nread > 0) {
    client->last_activity = uv_now(stream->loop);
    client->client_recv_length += nread;
    while (client->client_recv_length > 0 &&
           !uv_is_closing((uv_handle_t*)stream)) {
      nasfs_frame_t frame;
      int consumed = protocol_parse_frame(client->client_recv_buffer,
                                          client->client_recv_length, &frame);
      if (consumed > 0) {
        if (!client->is_secure) {
          if (frame.type == NASFS_CMD_PQC_PUBLIC_KEY) {
            OQS_KEM* kem;
            uint8_t* public_key = NULL;
            size_t public_key_len = 0;

            if (client->shared_secret ||
                frame.payload_len <= crypto_sign_BYTES + 1) {
              close_connection((uv_handle_t*)stream);
              return;
            }
            size_t selection_len = frame.payload_len - crypto_sign_BYTES;
            nasfs_handshake_transcript(client->handshake_transcript,
                                       client->hello_hash, frame.payload,
                                       selection_len);
            if (crypto_sign_verify_detached(frame.payload + selection_len,
                                            client->handshake_transcript, 32,
                                            client->trusted_server_key) != 0) {
              client_message(client, NASFS_CLIENT_ERROR,
                             "Server identity verification failed\n");
              close_connection((uv_handle_t*)stream);
              return;
            }

            if (nasfs_handshake_unpack_server_selection(
                    frame.payload, selection_len - 1,
                    &client->negotiated_kex_algorithm,
                    &client->negotiated_cipher_algorithm, &public_key,
                    &public_key_len) != 0) {
              close_connection((uv_handle_t*)stream);
              return;
            }

            uint8_t profile =
                nasfs_handshake_profile(client->negotiated_kex_algorithm);
            if (profile == 0 || profile != frame.payload[selection_len - 1] ||
                !nasfs_handshake_offer_contains(
                    client->options->kex_algorithms,
                    client->negotiated_kex_algorithm) ||
                !nasfs_handshake_offer_contains(
                    client->options->cipher_algorithms,
                    client->negotiated_cipher_algorithm) ||
                strcmp(client->negotiated_cipher_algorithm,
                       NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) != 0) {
              free(public_key);
              close_connection((uv_handle_t*)stream);
              return;
            }

            kem = OQS_KEM_new(client->negotiated_kex_algorithm);
            if (kem && public_key_len == kem->length_public_key) {
              size_t payload_size =
                  kem->length_ciphertext +
                  crypto_secretstream_xchacha20poly1305_HEADERBYTES;
              uint8_t* payload = malloc(payload_size);
              client->shared_secret = sodium_malloc(kem->length_shared_secret);
              client->shared_secret_len = kem->length_shared_secret;
              uint8_t key[32];
              if (payload && client->shared_secret &&
                  OQS_KEM_encaps(kem, payload, client->shared_secret,
                                 public_key) == OQS_SUCCESS &&
                  nasfs_handshake_key(key, client->shared_secret,
                                      client->shared_secret_len,
                                      client->handshake_transcript,
                                      NASFS_KEY_CLIENT_CONTROL) == 0 &&
                  crypto_secretstream_xchacha20poly1305_init_push(
                      &client->send_crypto_state,
                      payload + kem->length_ciphertext, key) == 0) {
                nasfs_handshake_hash(client->ciphertext_hash, payload,
                                     payload_size);
                client_message(client, NASFS_CLIENT_INFO,
                               "Negotiated KEX %s with control cipher %s.\n",
                               client->negotiated_kex_algorithm,
                               client->negotiated_cipher_algorithm);
                client_message(
                    client, NASFS_CLIENT_INFO,
                    "Received public key. Sending ciphertext and stream "
                    "header.\n");
                send_command(stream, NASFS_CMD_PQC_CIPHERTEXT, payload,
                             payload_size, 0);
              } else {
                close_connection((uv_handle_t*)stream);
              }
              sodium_memzero(key, sizeof(key));
              free(payload);
              OQS_KEM_free(kem);
            } else {
              if (kem) {
                OQS_KEM_free(kem);
              }
              close_connection((uv_handle_t*)stream);
            }
            free(public_key);
          } else if (frame.type == NASFS_CMD_READY) {
            size_t header_len =
                crypto_secretstream_xchacha20poly1305_HEADERBYTES;
            uint8_t key[32], expected[32];
            int invalid =
                !client->shared_secret ||
                frame.payload_len != header_len + sizeof(expected) ||
                nasfs_handshake_key(
                    key, client->shared_secret, client->shared_secret_len,
                    client->handshake_transcript, NASFS_KEY_SERVER_FINISHED) ||
                nasfs_handshake_finished(expected, key, client->ciphertext_hash,
                                         frame.payload, header_len) ||
                sodium_memcmp(expected, frame.payload + header_len,
                              sizeof(expected)) ||
                nasfs_handshake_key(
                    key, client->shared_secret, client->shared_secret_len,
                    client->handshake_transcript, NASFS_KEY_SERVER_CONTROL) ||
                crypto_secretstream_xchacha20poly1305_init_pull(
                    &client->recv_crypto_state, frame.payload, key) ||
                nasfs_handshake_key(client->auth_context, client->shared_secret,
                                    client->shared_secret_len,
                                    client->handshake_transcript,
                                    NASFS_KEY_CLIENT_AUTH);
            sodium_memzero(key, sizeof(key));
            if (invalid) {
              client_message(client, NASFS_CLIENT_ERROR,
                             "Server handshake confirmation failed\n");
              close_connection((uv_handle_t*)stream);
              return;
            }
            sodium_free(client->shared_secret);
            client->shared_secret = NULL;
            client->is_secure = 1;
            client_message(
                client, NASFS_CLIENT_INFO,
                "PQC Handshake successful. Channel is now secure. Sending "
                "AUTH...\n");
            if (strcmp(client->options->auth_method, NASFS_AUTH_METHOD_PAKE) ==
                0) {
              send_pake_hello(stream);
            } else {
              send_auth(stream);
            }
          } else if (frame.type == NASFS_CMD_ERROR) {
            client_message(client, NASFS_CLIENT_ERROR,
                           "Handshake failed: %.*s\n", (int)frame.payload_len,
                           (const char*)frame.payload);
            close_connection((uv_handle_t*)stream);
          } else {
            close_connection((uv_handle_t*)stream);
          }
        } else {
          unsigned long long decrypted_len;
          nasfs_frame_t plain_frame = frame;
          unsigned char* decrypted_payload = NULL;

          if ((frame.type >= 0x10 && frame.type < 0x20) ||
              frame.type == NASFS_CMD_ERROR) {
            decrypted_payload = malloc(frame.payload_len);
            if (!decrypted_payload) {
              close_connection((uv_handle_t*)stream);
              return;
            }
            uint8_t command = (uint8_t)frame.type;
            uint8_t tag;
            if (crypto_secretstream_xchacha20poly1305_pull(
                    &client->recv_crypto_state, decrypted_payload,
                    &decrypted_len, &tag, frame.payload, frame.payload_len,
                    &command, sizeof(command)) != 0 ||
                tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
              free(decrypted_payload);
              close_connection((uv_handle_t*)stream);
              return;
            }
            plain_frame.payload = decrypted_payload;
            plain_frame.payload_len = decrypted_len;
          }

          switch (plain_frame.type) {
            case NASFS_CMD_PAKE_RESPONSE:
              if (plain_frame.payload_len != crypto_core_ristretto255_BYTES) {
                client_message(client, NASFS_CLIENT_ERROR,
                               "PAKE: bad response length\n");
                client->client_exit_code = 1;
                close_connection((uv_handle_t*)stream);
                break;
              }
              send_pake_auth_proof(stream, plain_frame.payload);
              break;

            case NASFS_CMD_AUTH_ACK:
              if (transfer->current_op != OP_NONE ||
                  plain_frame.payload_len != 0) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              start_next_operation(stream);
              break;
            case NASFS_CMD_PUT_ACK:
              if (transfer->current_op != NASFS_CLIENT_PUT ||
                  !transfer->put_ack_pending || transfer->local_fd == -1 ||
                  plain_frame.payload_len != 0) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              transfer->put_ack_pending = 0;
              do_put_read_chunk(stream);
              break;
            case NASFS_CMD_PUT_RESULT:
              if (transfer->current_op != NASFS_CLIENT_PUT ||
                  !transfer->put_result_pending ||
                  plain_frame.payload_len != 1) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              if (plain_frame.payload[0] == NASFS_PUT_PUBLISHED) {
                transfer->put_result_pending = 0;
                nasfs_client_result_t* result =
                    &client->results[client->batch_idx - 1];
                result->outcome = NASFS_CLIENT_PUT_PUBLISHED;
                result->has_digest = 1;
                memcpy(result->digest, transfer->manifest_digest,
                       sizeof(result->digest));
                report_event(client, NASFS_CLIENT_COMPLETED,
                             transfer->file_offset);
                start_next_operation(stream);
              } else if (plain_frame.payload[0] ==
                         NASFS_PUT_PUBLICATION_FAILED) {
                transfer->put_result_pending = 0;
                client->results[client->batch_idx - 1].outcome =
                    NASFS_CLIENT_REJECTED;
                client_message(client, NASFS_CLIENT_ERROR,
                               "Server could not publish '%s'\n",
                               transfer->remote_filename);
                close_connection((uv_handle_t*)stream);
              } else {
                close_connection((uv_handle_t*)stream);
              }
              break;
            case NASFS_CMD_GET_ACK: {
              if (transfer->current_op != NASFS_CLIENT_GET ||
                  transfer->local_fd != -1) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              uint8_t manifest_cipher = transfer->file_cipher_algo;
              if (client->file_encryption_enabled) {
                /* GET_ACK: [16 salt][8 size][1 cipher][1 hash][optional slot]
                 */
                transfer->download_has_owner_slot =
                    plain_frame.payload_len ==
                    NASFS_FILE_METADATA_SIZE + NASFS_OWNER_SLOT_V1_SIZE;
                if (!transfer->download_has_owner_slot &&
                    plain_frame.payload_len != NASFS_FILE_METADATA_SIZE) {
                  client_message(
                      client, NASFS_CLIENT_ERROR,
                      "Failed to download: Invalid GET_ACK length.\n");
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }
                memcpy(transfer->file_salt, plain_frame.payload,
                       crypto_pwhash_SALTBYTES);
                transfer->expected_plaintext_size = protocol_load_u64(
                    plain_frame.payload + crypto_pwhash_SALTBYTES);
                manifest_cipher =
                    plain_frame
                        .payload[crypto_pwhash_SALTBYTES + sizeof(uint64_t)];
                transfer->download_legacy_counter =
                    (manifest_cipher & NASFS_FILE_CIPHER_PORTABLE) == 0;
                transfer->file_cipher_algo =
                    manifest_cipher & ~NASFS_FILE_CIPHER_PORTABLE;
                transfer->file_hash_algo =
                    (nasfs_hash_algo_t)
                        plain_frame.payload[crypto_pwhash_SALTBYTES +
                                            sizeof(uint64_t) + 1];

                if (transfer->file_cipher_algo > NASFS_CIPHER_AES_256_GCM ||
                    transfer->file_hash_algo > NASFS_HASH_CRC32) {
                  client_message(client, NASFS_CLIENT_ERROR,
                                 "Invalid file cipher or hash algorithm\n");
                  close_connection((uv_handle_t*)stream);
                  break;
                }
                int key_rc =
                    transfer->download_has_owner_slot
                        ? crypto_engine_open_owner_slot(
                              transfer->encryption_key,
                              plain_frame.payload + NASFS_FILE_METADATA_SIZE,
                              client->master_key, transfer->file_salt)
                        : crypto_engine_derive_key(
                              NASFS_KDF_HKDF_SHA256,
                              (const char*)client->master_key,
                              sizeof(client->master_key), transfer->file_salt,
                              crypto_pwhash_SALTBYTES, transfer->encryption_key,
                              sizeof(transfer->encryption_key));
                if (key_rc != 0) {
                  client_message(
                      client, NASFS_CLIENT_ERROR,
                      "Cannot open NASLUKS owner slot or derive legacy "
                      "file key\n");
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }
              }

              protocol_manifest_init(
                  &transfer->file_manifest, transfer->remote_filename,
                  transfer->expected_plaintext_size, transfer->file_salt,
                  manifest_cipher, transfer->file_hash_algo);
              if (transfer->download_has_owner_slot) {
                protocol_manifest_owner_slot(
                    &transfer->file_manifest,
                    plain_frame.payload + NASFS_FILE_METADATA_SIZE,
                    NASFS_OWNER_SLOT_V1_SIZE);
              }
              if (open_download_file(client) < 0) {
                client_message(
                    client, NASFS_CLIENT_ERROR,
                    "Cannot create temporary download for '%s': %s\n",
                    transfer->local_filename, strerror(errno));
                close_connection((uv_handle_t*)stream);
              }
              break;
            }
            case NASFS_CMD_GET_BLOCK_META: {
              nasfs_block_meta_t meta;
              if (transfer->current_op != NASFS_CLIENT_GET ||
                  transfer->local_fd < 0 || transfer->has_pending_block_meta ||
                  protocol_decode_block_meta(plain_frame.payload,
                                             plain_frame.payload_len,
                                             &meta) < 0) {
                client_message(client, NASFS_CLIENT_ERROR,
                               "Received invalid block meta size\n");
                client->client_exit_code = 1;
                free(decrypted_payload);
                if (uv_is_closing((uv_handle_t*)stream)) return;
                close_connection((uv_handle_t*)stream);
                return;
              }
              transfer->expected_block_seq = meta.seq_num;
              transfer->expected_block_size = meta.size;
              memcpy(transfer->expected_block_hash, meta.hash, 32);
              transfer->has_pending_block_meta = 1;
              break;
            }
            case NASFS_CMD_GET_DATA: {
              uv_fs_t write_req;
              uv_buf_t write_buf;
              int rc;

              if (transfer->current_op != NASFS_CLIENT_GET ||
                  transfer->local_fd == -1) {
                free(decrypted_payload);
                if (uv_is_closing((uv_handle_t*)stream)) return;
                close_connection((uv_handle_t*)stream);
                return;
              }

              uint8_t* write_data = plain_frame.payload;
              size_t write_len = plain_frame.payload_len;
              uint8_t* decrypted_buf = NULL;

              if (client->file_encryption_enabled) {
                if (!transfer->has_pending_block_meta) {
                  client_message(
                      client, NASFS_CLIENT_ERROR,
                      "\nError: Received data block without metadata.\n");
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }
                if (plain_frame.payload_len != transfer->expected_block_size) {
                  client_message(
                      client, NASFS_CLIENT_ERROR,
                      "\nError: Block size mismatch. Expected %u, got %zu.\n",
                      transfer->expected_block_size, plain_frame.payload_len);
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }
                if (transfer->client_block_seq !=
                    transfer->expected_block_seq) {
                  client_message(
                      client, NASFS_CLIENT_ERROR,
                      "\nError: Sequence number mismatch. Expected %llu, "
                      "got %llu.\n",
                      (unsigned long long)transfer->client_block_seq,
                      (unsigned long long)transfer->expected_block_seq);
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }

                uint8_t computed_hash[32] = {0};
                size_t computed_hash_len = 0;
                if (crypto_engine_hash(transfer->file_hash_algo,
                                       plain_frame.payload,
                                       plain_frame.payload_len, computed_hash,
                                       &computed_hash_len) != 0) {
                  client_message(client, NASFS_CLIENT_ERROR,
                                 "\nError: Hash computation failed.\n");
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }

                if (sodium_memcmp(computed_hash, transfer->expected_block_hash,
                                  32) != 0) {
                  client_message(
                      client, NASFS_CLIENT_ERROR,
                      "\nError: Integrity check failed (hash mismatch) on "
                      "block %llu.\n",
                      (unsigned long long)transfer->client_block_seq);
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }

                decrypted_buf = malloc(plain_frame.payload_len);
                if (!decrypted_buf) {
                  client_message(client, NASFS_CLIENT_ERROR,
                                 "\nError: Out of memory for decryption.\n");
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }

                uint8_t block_key[crypto_secretbox_KEYBYTES];
                crypto_engine_derive_block_key(
                    block_key, transfer->encryption_key, transfer->file_salt,
                    transfer->client_block_seq,
                    transfer->download_legacy_counter);

                size_t plaintext_len = 0;
                if (crypto_engine_decrypt_block(
                        transfer->file_cipher_algo, plain_frame.payload,
                        plain_frame.payload_len, block_key,
                        transfer->client_block_seq,
                        transfer->download_legacy_counter, decrypted_buf,
                        &plaintext_len) != 0) {
                  client_message(
                      client, NASFS_CLIENT_ERROR,
                      "\nError: Decryption failed. Wrong key or corrupted "
                      "data on block %llu.\n",
                      (unsigned long long)transfer->client_block_seq);
                  free(decrypted_buf);
                  client->client_exit_code = 1;
                  free(decrypted_payload);
                  if (uv_is_closing((uv_handle_t*)stream)) return;
                  close_connection((uv_handle_t*)stream);
                  return;
                }
                protocol_manifest_record(&transfer->file_manifest,
                                         plain_frame.payload,
                                         plain_frame.payload_len);
                write_data = decrypted_buf;
                write_len = plaintext_len;

                transfer->has_pending_block_meta = 0;
                transfer->client_block_seq++;
              }

              if (write_len > INT64_MAX - transfer->file_offset ||
                  (client->file_encryption_enabled &&
                   write_len > transfer->expected_plaintext_size -
                                   transfer->file_offset)) {
                client_message(client, NASFS_CLIENT_ERROR,
                               "Download exceeds expected file size\n");
                free(decrypted_buf);
                close_connection((uv_handle_t*)stream);
                break;
              }
              write_buf = uv_buf_init((char*)write_data, write_len);
              rc = uv_fs_write(client->loop, &write_req, transfer->local_fd,
                               &write_buf, 1, transfer->file_offset, NULL);
              uv_fs_req_cleanup(&write_req);
              free(decrypted_buf);

              if (rc < 0 || (size_t)rc != write_len) {
                client_message(client, NASFS_CLIENT_ERROR,
                               "Failed to write downloaded data: %s\n",
                               rc < 0 ? uv_strerror(rc) : "short write");
                close_connection((uv_handle_t*)stream);
                break;
              }
              transfer->file_offset += (uint64_t)rc;
              report_event(client, NASFS_CLIENT_PROGRESS,
                           transfer->file_offset);
              fflush(stdout);
              break;
            }
            case NASFS_CMD_GET_DONE:
              if (transfer->current_op != NASFS_CLIENT_GET ||
                  transfer->local_fd == -1) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              if (client->file_encryption_enabled &&
                  transfer->file_offset != transfer->expected_plaintext_size) {
                client_message(
                    client, NASFS_CLIENT_ERROR,
                    "\nIntegrity error: expected %llu bytes, got %llu "
                    "(file truncated or padded by server).\n",
                    (unsigned long long)transfer->expected_plaintext_size,
                    (unsigned long long)transfer->file_offset);
                client->client_exit_code = 1;
                close_connection((uv_handle_t*)stream);
                break;
              }
              if (!(client->allow_unsigned_reads &&
                    !transfer->download_has_owner_slot &&
                    plain_frame.payload_len == 0) &&
                  (plain_frame.payload_len != NASFS_MANIFEST_SIZE ||
                   protocol_manifest_verify(&transfer->file_manifest,
                                            plain_frame.payload,
                                            client->author_public) != 0)) {
                client_message(client, NASFS_CLIENT_ERROR,
                               "File manifest missing or invalid\n");
                close_connection((uv_handle_t*)stream);
                break;
              }
              if (transfer->require_manifest_digest &&
                  (plain_frame.payload_len != NASFS_MANIFEST_SIZE ||
                   sodium_memcmp(transfer->manifest_digest, plain_frame.payload,
                                 sizeof(transfer->manifest_digest)) != 0)) {
                client_message(client, NASFS_CLIENT_ERROR,
                               "Unexpected file manifest version\n");
                close_connection((uv_handle_t*)stream);
                break;
              }
              if (transfer->has_pending_block_meta ||
                  publish_download(client) < 0) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              nasfs_client_result_t* result =
                  &client->results[client->batch_idx - 1];
              result->outcome = NASFS_CLIENT_GET_PUBLISHED;
              if (plain_frame.payload_len == NASFS_MANIFEST_SIZE) {
                result->has_digest = 1;
                memcpy(result->digest, plain_frame.payload,
                       sizeof(result->digest));
              }
              report_event(client, NASFS_CLIENT_COMPLETED,
                           transfer->file_offset);
              start_next_operation(stream);
              break;
            case NASFS_CMD_ERROR:
              if (transfer->current_op == NASFS_CLIENT_PUT &&
                  transfer->put_ack_pending)
                client->results[client->batch_idx - 1].outcome =
                    NASFS_CLIENT_REJECTED;
              client_message(client, NASFS_CLIENT_ERROR, "Server error: %.*s\n",
                             (int)plain_frame.payload_len,
                             (const char*)plain_frame.payload);
              client->client_exit_code = 1;
              close_connection((uv_handle_t*)stream);
              break;
            default:
              close_connection((uv_handle_t*)stream);
              break;
          }

          free(decrypted_payload);
          if (uv_is_closing((uv_handle_t*)stream)) return;
        }
        memmove(client->client_recv_buffer,
                client->client_recv_buffer + consumed,
                client->client_recv_length - consumed);
        client->client_recv_length -= consumed;
      } else {
        if (consumed < 0) close_connection((uv_handle_t*)stream);
        break;
      }
    }
  } else if (nread < 0) {
    if (!client->is_secure) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Connection ended before the NASFS handshake completed\n");
    }
    close_connection((uv_handle_t*)stream);
  }
}

static void on_connect(uv_connect_t* req, int status) {
  nasfs_client_t* client = req->handle->data;
  if (status < 0) {
    client_message(client, NASFS_CLIENT_ERROR, "Connection error: %s\n",
                   uv_strerror(status));
    close_connection((uv_handle_t*)req->handle);
    return;
  }
  client_message(client, NASFS_CLIENT_INFO,
                 "Connected to server. Initiating PQC Handshake...\n");
  {
    uint8_t* hello_payload;
    size_t hello_payload_len = 0;

    hello_payload = nasfs_handshake_pack_client_hello(
        client->options->kex_algorithms, client->options->cipher_algorithms,
        &hello_payload_len);
    if (!hello_payload) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Failed to build PQC hello payload\n");
      close_connection((uv_handle_t*)req->handle);
      return;
    }

    uint8_t* with_nonce =
        realloc(hello_payload, hello_payload_len + NASFS_HANDSHAKE_NONCE);
    if (!with_nonce) {
      free(hello_payload);
      close_connection((uv_handle_t*)req->handle);
      return;
    }
    hello_payload = with_nonce;
    memmove(hello_payload + NASFS_HANDSHAKE_NONCE, hello_payload,
            hello_payload_len);
    randombytes_buf(hello_payload, NASFS_HANDSHAKE_NONCE);
    hello_payload_len += NASFS_HANDSHAKE_NONCE;
    nasfs_handshake_hash(client->hello_hash, hello_payload, hello_payload_len);
    send_command(req->handle, NASFS_CMD_HELLO, hello_payload, hello_payload_len,
                 0);
    free(hello_payload);
  }
  if (!uv_is_closing((uv_handle_t*)req->handle)) {
    int rc = uv_read_start(req->handle, alloc_buffer, on_read);
    if (rc < 0) {
      client_message(client, NASFS_CLIENT_ERROR, "Read start failed: %s\n",
                     uv_strerror(rc));
      close_connection((uv_handle_t*)req->handle);
    }
  }
}

int nasfs_client_run(const nasfs_client_options_t* options,
                     const nasfs_client_request_t* requests,
                     nasfs_client_result_t* output, size_t count) {
  if (!output || !count || count > NASFS_MAX_BATCH) return 1;
  memset(output, 0, count * sizeof(*output));
  if (!options || !requests) return 1;
  nasfs_client_operation_t operation = requests[0].operation;
  if ((operation != NASFS_CLIENT_PUT && operation != NASFS_CLIENT_GET) ||
      !options->ip || options->port < 1 || options->port > 65535 ||
      !options->kex_algorithms || !options->cipher_algorithms ||
      !options->auth_method || !options->auth_user ||
      !options->encryption_password || !options->encryption_password[0] ||
      options->block_size < 4096 || options->block_size > 4194304 ||
      !options->author_key || (options->expected_digest && count != 1) ||
      (operation == NASFS_CLIENT_PUT && options->kdf != NASFS_KDF_ARGON2ID) ||
      sodium_init() < 0) {
    if (options->notify)
      options->notify(options->callback_data, NASFS_CLIENT_ERROR, 0, 0,
                      "Invalid NASFS client options\n");
    return 1;
  }
  for (size_t i = 0; i < count; i++) {
    if (requests[i].operation != operation || !requests[i].local_path ||
        !requests[i].remote_name)
      return 1;
  }
  void* memory;
  if (posix_memalign(&memory, _Alignof(nasfs_client_t),
                     sizeof(nasfs_client_t)) != 0)
    return 1;
  nasfs_client_t* client = memory;
  memset(client, 0, sizeof(*client));
  client_transfer_t* transfer = &client->transfer;
  client->options = options;
  client->batch_queue = requests;
  client->batch_count = count;
  client->results = output;
  transfer->local_fd = -1;
  transfer->download_directory = -1;
  transfer->download_staging = -1;
  transfer->file_cipher_algo = options->file_cipher;
  transfer->file_hash_algo = options->file_hash;
  int is_upload = operation == NASFS_CLIENT_PUT;
  int return_code = 1;
  client->file_encryption_enabled = 1;
  uint8_t master_salt[crypto_pwhash_SALTBYTES];
  if (load_master_salt(client, master_salt, is_upload) < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot load or save ~/.nasfs/master.salt: %s\n",
                   strerror(errno));
    goto cleanup;
  }

  if (crypto_engine_derive_key(options->kdf, options->encryption_password,
                               strlen(options->encryption_password),
                               master_salt, crypto_pwhash_SALTBYTES,
                               client->master_key,
                               sizeof(client->master_key)) != 0) {
    client_message(client, NASFS_CLIENT_ERROR, "Failed to derive master key\n");
    goto cleanup;
  }

  if (!auth_method_requires_password(client->options->auth_method) &&
      !auth_method_requires_publickey(client->options->auth_method) &&
      strcmp(client->options->auth_method, NASFS_AUTH_METHOD_PAKE) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Invalid NASFS_AUTH_METHOD: %s\n",
                   client->options->auth_method);
    goto cleanup;
  }
  if ((auth_method_requires_password(client->options->auth_method) ||
       strcmp(client->options->auth_method, NASFS_AUTH_METHOD_PAKE) == 0) &&
      (!client->options->auth_password ||
       client->options->auth_password[0] == '\0')) {
    client_message(
        client, NASFS_CLIENT_ERROR,
        "NASFS_AUTH_PASSWORD required for the selected authentication "
        "method\n");
    goto cleanup;
  }

  if (client->options->auth_password &&
      strcmp(options->encryption_password, client->options->auth_password) ==
          0) {
    client_message(
        client, NASFS_CLIENT_ERROR,
        "File encryption password must differ from the login password\n");
    goto cleanup;
  }
  if (is_upload) {
    uint8_t seed[crypto_sign_SEEDBYTES];
    if (nasfs_handshake_read_key(options->author_key, seed, 1) < 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Expected a private NASFS_AUTHOR_SIGNING_SEED file\n");
      goto cleanup;
    }
    int result = crypto_sign_seed_keypair(client->author_public,
                                          client->author_secret, seed);
    sodium_memzero(seed, sizeof(seed));
    if (result != 0) goto cleanup;
  } else {
    if (options->expected_digest) {
      memcpy(transfer->manifest_digest, options->expected_digest,
             sizeof(transfer->manifest_digest));
      transfer->require_manifest_digest = 1;
    }
    client->allow_unsigned_reads = options->allow_unsigned_reads;
    if (nasfs_handshake_read_key(options->author_key, client->author_public,
                                 0) < 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Expected a trusted NASFS_AUTHOR_PUBLIC_KEY file\n");
      goto cleanup;
    }
  }

  uv_loop_t event_loop;
  int rc = uv_loop_init(&event_loop);
  if (rc < 0) goto cleanup;
  client->loop = &event_loop;
  uv_tcp_t socket;
  rc = uv_tcp_init(client->loop, &socket);
  if (rc < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "TCP initialization failed: %s\n", uv_strerror(rc));
    uv_loop_close(client->loop);
    goto cleanup;
  }

  socket.data = client;
  if (options->watch_signals) {
    rc = uv_signal_init(client->loop, &client->interrupt_watcher);
    if (rc == 0) {
      client->interrupt_watcher.data = &socket;
      rc =
          uv_signal_start(&client->interrupt_watcher, on_client_signal, SIGINT);
    }
    if (rc == 0) rc = uv_signal_init(client->loop, &client->terminate_watcher);
    if (rc == 0) {
      client->terminate_watcher.data = &socket;
      rc = uv_signal_start(&client->terminate_watcher, on_client_signal,
                           SIGTERM);
    }
  }
  if (rc == 0) rc = uv_timer_init(client->loop, &client->idle_timer);
  if (rc == 0) {
    client->idle_timer.data = &socket;
    client->last_activity = uv_now(client->loop);
    rc = uv_timer_start(&client->idle_timer, on_client_timeout, 100, 100);
  }

  struct sockaddr_in dest;
  if (rc == 0)
    rc = uv_ip4_addr(client->options->ip, client->options->port, &dest);
  if (rc == 0 && load_server_key(client, &dest) < 0) rc = UV_EACCES;
  uv_connect_t connect_req;
  if (rc == 0) {
    rc = uv_tcp_connect(&connect_req, &socket, (const struct sockaddr*)&dest,
                        on_connect);
  }
  if (rc < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Connection submission failed: %s\n", uv_strerror(rc));
    close_connection((uv_handle_t*)&socket);
  } else {
    client_message(client, NASFS_CLIENT_INFO, "Connecting to %s:%d...\n",
                   client->options->ip, client->options->port);
  }

  /* An accepted fs request may outlive TCP close and still reference socket. */
  uv_run(client->loop, UV_RUN_DEFAULT);
  rc = uv_loop_close(client->loop);
  if (rc < 0) {
    client_message(client, NASFS_CLIENT_ERROR, "Event loop close failed: %s\n",
                   uv_strerror(rc));
    client->client_exit_code = 1;
  }
  return_code = client->client_exit_code;
cleanup:
  free(client->client_recv_buffer);
  if (client->shared_secret) sodium_free(client->shared_secret);
  free(client->negotiated_kex_algorithm);
  free(client->negotiated_cipher_algorithm);
  sodium_memzero(client, sizeof(*client));
  free(client);
  return return_code;
}
