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
  crypto_generichash_state index;
  crypto_generichash_state index_selection;
  struct stat download_initial_destination;
  const char* local_filename;
  const char* remote_filename;
  char* download_parent;
  const char* download_name;
  FILE* index_file;
  uint8_t* parity[NASFS_ECC_MAX_PARITY];
  uint8_t* repair_rows[NASFS_ECC_MAX_DATA + NASFS_ECC_MAX_PARITY];
  uint64_t file_offset;
  uint64_t sequence;
  uint64_t index_position;
  uint64_t repair_start;
  uint64_t start;
  uint64_t length;
  uint64_t first;
  uint64_t end;
  nasfs_version_header_t header;
  nasfs_client_version_t version;
  nasfs_block_meta_t expected;
  nasfs_client_operation_t current_op;
  uv_file local_fd;
  int download_directory;
  int download_staging;
  int download_had_destination;
  int put_ack_pending;
  int put_result_pending;
  int get_ack_pending;
  int resolve_pending;
  int batch_upload_exclusive;
  int has_pending_block_meta;
  int partial;
  int index_verified;
  int repair_active;
  unsigned repair_data;
  unsigned repair_parity;
  unsigned repair_target;
  unsigned repair_position;
  uint8_t encryption_key[crypto_secretbox_KEYBYTES];
  uint8_t index_root[32];
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

static void send_put_req(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  nasfs_version_header_t* header = &transfer->header;
  transfer->local_fd =
      open(transfer->local_filename, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (transfer->local_fd < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot open PUT source '%s': %s\n",
                   transfer->local_filename, strerror(errno));
    close_connection((uv_handle_t*)stream);
    return;
  }
  struct stat st;
  if (fstat(transfer->local_fd, &st) < 0 || !S_ISREG(st.st_mode) ||
      st.st_size < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "PUT source must be a regular file: %s\n",
                   transfer->local_filename);
    close_connection((uv_handle_t*)stream);
    return;
  }
  header->size = (uint64_t)st.st_size;
  header->block_size = (uint32_t)client->options->block_size;
  header->cipher = (uint8_t)client->options->file_cipher;
  header->hash = (uint8_t)client->options->file_hash;
  header->ecc = (uint8_t)client->options->ecc;
  unsigned data, parity;
  if (nasfs_ecc_group(header->ecc, &data, &parity) < 0) {
    close_connection((uv_handle_t*)stream);
    return;
  }
  for (unsigned i = 0; i < parity; i++) {
    transfer->parity[i] =
        calloc(1, header->block_size + NASFS_VERSION_BLOCK_TAG);
    if (!transfer->parity[i]) {
      close_connection((uv_handle_t*)stream);
      return;
    }
  }
  randombytes_buf(header->salt, sizeof(header->salt));
  if (nasfs_version_file_size(header) < 0 ||
      crypto_engine_create_owner_slot(header->slot, transfer->encryption_key,
                                      client->master_key, header->salt) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot prepare version metadata\n");
    close_connection((uv_handle_t*)stream);
    return;
  }
  const size_t header_bytes = 1 + NASFS_VERSION_HEADER_SIZE;
  size_t length = strlen(transfer->remote_filename) + 1;
  uint8_t req[1 + NASFS_VERSION_HEADER_SIZE + 256];
  req[0] = transfer->batch_upload_exclusive ? NASFS_VERSION_EXCLUSIVE
                                            : NASFS_VERSION_REQUEST;
  nasfs_version_encode(req + 1, header);
  memcpy(req + header_bytes, transfer->remote_filename, length);
  nasfs_version_index_init(&transfer->index);
  transfer->put_ack_pending = 1;
  send_command(stream, NASFS_CMD_PUT_REQ, req, header_bytes + length, 1);
}

static void send_get_req(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  uint8_t req[NASFS_VERSION_GET_SIZE] = {NASFS_VERSION_REQUEST};
  memcpy(req + 1, transfer->version.id, sizeof(transfer->version.id));
  memcpy(req + 17, transfer->version.digest, sizeof(transfer->version.digest));
  protocol_store_u64(req + 49, transfer->start);
  protocol_store_u64(req + 57, transfer->length);
  transfer->get_ack_pending = 1;
  send_command(stream, NASFS_CMD_GET_REQ, req, sizeof(req), 1);
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

static void clear_repair(client_transfer_t* transfer) {
  for (size_t i = 0; i < NASFS_ECC_MAX_DATA + NASFS_ECC_MAX_PARITY; i++) {
    free(transfer->repair_rows[i]);
    transfer->repair_rows[i] = NULL;
  }
  transfer->repair_active = 0;
}

static void close_ecc(client_transfer_t* transfer) {
  clear_repair(transfer);
  if (transfer->index_file) fclose(transfer->index_file);
  transfer->index_file = NULL;
  for (size_t i = 0; i < NASFS_ECC_MAX_PARITY; i++) {
    free(transfer->parity[i]);
    transfer->parity[i] = NULL;
  }
}

static int load_index_row(client_transfer_t* transfer, uint64_t seq,
                          uint8_t row[NASFS_BLOCK_META_SIZE]) {
  if (!transfer->index_file ||
      fseeko(transfer->index_file, (off_t)(seq * NASFS_BLOCK_META_SIZE),
             SEEK_SET) != 0)
    return -1;
  return fread(row, 1, NASFS_BLOCK_META_SIZE, transfer->index_file) ==
                 NASFS_BLOCK_META_SIZE
             ? 0
             : -1;
}

static int request_repair(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  uint64_t start;
  if (transfer->repair_active ||
      nasfs_version_group(&transfer->header, transfer->sequence, &start,
                          &transfer->repair_data,
                          &transfer->repair_parity) < 0 ||
      !transfer->repair_parity)
    return -1;
  transfer->repair_start =
      nasfs_version_data_sequence(&transfer->header, start);
  transfer->repair_target = (unsigned)(transfer->sequence - start);
  transfer->repair_position = 0;
  transfer->repair_active = 1;
  send_command(stream, NASFS_CMD_GET_REPAIR, NULL, 0, 1);
  return 0;
}

static int receive_repair_row(client_transfer_t* transfer,
                              const nasfs_frame_t* frame) {
  if (!transfer->repair_active ||
      transfer->repair_position >=
          transfer->repair_data + transfer->repair_parity)
    return -1;
  uint8_t trusted[NASFS_BLOCK_META_SIZE];
  uint64_t seq = transfer->repair_start + transfer->repair_position;
  nasfs_block_meta_t meta;
  if (frame->payload_len <= NASFS_BLOCK_META_SIZE ||
      load_index_row(transfer, seq, trusted) < 0 ||
      sodium_memcmp(trusted, frame->payload, sizeof(trusted)) != 0 ||
      protocol_decode_block_meta(trusted, sizeof(trusted), &meta) < 0 ||
      frame->payload_len != sizeof(trusted) + meta.size)
    return -1;

  const uint8_t* bytes = frame->payload + sizeof(trusted);
  uint8_t hash[32];
  if (nasfs_version_hash_block(transfer->header.hash, bytes, meta.size, hash) !=
      0)
    return -1;
  if (sodium_memcmp(hash, meta.hash, sizeof(hash)) == 0) {
    size_t padded = transfer->header.block_size + NASFS_VERSION_BLOCK_TAG;
    uint8_t* row = calloc(1, padded);
    if (!row || meta.size > padded) {
      free(row);
      return -1;
    }
    memcpy(row, bytes, meta.size);
    transfer->repair_rows[transfer->repair_position] = row;
  }
  transfer->repair_position++;
  return 0;
}

static int begin_download(nasfs_client_t* client, const nasfs_frame_t* frame) {
  client_transfer_t* transfer = &client->transfer;
  nasfs_version_header_t* header = &transfer->header;
  if (!transfer->get_ack_pending ||
      frame->payload_len != NASFS_VERSION_DATA_OFFSET ||
      nasfs_version_decode(header, frame->payload, NASFS_VERSION_HEADER_SIZE) <
          0)
    return -1;
  transfer->get_ack_pending = 0;

  const uint8_t* proof = frame->payload + NASFS_VERSION_HEADER_SIZE;
  if (sodium_memcmp(transfer->version.id, header->id, sizeof(header->id)) !=
          0 ||
      sodium_memcmp(transfer->version.digest, proof + 32, 32) != 0 ||
      nasfs_version_verify(header, proof, client->author_public) < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "File manifest missing or invalid\n");
    return -1;
  }
  if (transfer->start > header->size ||
      (transfer->length != UINT64_MAX &&
       transfer->length > header->size - transfer->start))
    return -1;
  if (transfer->length == UINT64_MAX)
    transfer->length = header->size - transfer->start;

  uint64_t first = transfer->start / header->block_size;
  uint64_t end = transfer->start + transfer->length;
  transfer->first = first;
  transfer->end = transfer->length ? end / header->block_size +
                                         (end % header->block_size != 0)
                                   : first;
  transfer->sequence = first;
  transfer->partial =
      nasfs_version_record_count(header) &&
      (transfer->start != 0 || transfer->length != header->size ||
       header->ecc != NASFS_ECC_OFF);
  if (transfer->partial && header->ecc != NASFS_ECC_OFF) {
    transfer->index_file = tmpfile();
    if (!transfer->index_file) return -1;
  }
  transfer->index_position = 0;
  nasfs_version_index_init(&transfer->index);
  nasfs_version_index_init(&transfer->index_selection);
  memcpy(transfer->index_root, proof, sizeof(transfer->index_root));
  if (crypto_engine_open_owner_slot(transfer->encryption_key, header->slot,
                                    client->master_key, header->salt) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot open NASLUKS owner slot\n");
    return -1;
  }
  if (open_download_file(client) < 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Cannot create temporary download for '%s': %s\n",
                   transfer->local_filename, strerror(errno));
    return -1;
  }
  return 0;
}

static int read_index_row(client_transfer_t* transfer,
                          const nasfs_frame_t* frame, uint64_t sequence,
                          nasfs_block_meta_t* meta) {
  int64_t offset;
  uint32_t length;
  return transfer->local_fd < 0 ||
                 nasfs_version_record(&transfer->header, sequence, &offset,
                                      &length) < 0 ||
                 protocol_decode_block_meta(frame->payload, frame->payload_len,
                                            meta) < 0 ||
                 meta->seq_num != sequence || meta->size != length
             ? -1
             : 0;
}

static int receive_index(client_transfer_t* transfer,
                         const nasfs_frame_t* frame) {
  nasfs_block_meta_t meta;
  if (!transfer->partial || transfer->index_verified ||
      read_index_row(transfer, frame, transfer->index_position, &meta) < 0)
    return -1;
  if (transfer->index_file &&
      fwrite(frame->payload, 1, NASFS_BLOCK_META_SIZE, transfer->index_file) !=
          NASFS_BLOCK_META_SIZE)
    return -1;
  uint64_t first =
      nasfs_version_data_sequence(&transfer->header, transfer->first);
  uint64_t end = nasfs_version_data_sequence(&transfer->header, transfer->end);
  if (meta.seq_num >= first && meta.seq_num < end &&
      !nasfs_version_is_parity(&transfer->header, meta.seq_num))
    nasfs_version_index_add(&transfer->index_selection, &meta);
  nasfs_version_index_add(&transfer->index, &meta);
  if (++transfer->index_position ==
      nasfs_version_record_count(&transfer->header)) {
    uint8_t root[32];
    nasfs_version_index_final(&transfer->index, root);
    if (sodium_memcmp(root, transfer->index_root, sizeof(root)) != 0) return -1;
    if (transfer->index_file && fflush(transfer->index_file) != 0) return -1;
    nasfs_version_index_final(&transfer->index_selection, transfer->index_root);
    nasfs_version_index_init(&transfer->index);
    transfer->index_verified = 1;
  }
  return 0;
}

static int receive_block_meta(client_transfer_t* transfer,
                              const nasfs_frame_t* frame) {
  uint64_t sequence =
      nasfs_version_data_sequence(&transfer->header, transfer->sequence);
  if (transfer->has_pending_block_meta || transfer->sequence >= transfer->end ||
      (transfer->partial && !transfer->index_verified) ||
      read_index_row(transfer, frame, sequence, &transfer->expected) < 0)
    return -1;
  if (transfer->index_file) {
    uint8_t trusted[NASFS_BLOCK_META_SIZE];
    if (load_index_row(transfer, sequence, trusted) < 0 ||
        sodium_memcmp(trusted, frame->payload, sizeof(trusted)) != 0)
      return -1;
  }
  transfer->has_pending_block_meta = 1;
  return 0;
}

static int store_verified_block(uv_stream_t* stream,
                                const nasfs_frame_t* frame) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  uint8_t* data = malloc(frame->payload_len);
  if (!data) return -1;
  uint8_t key[crypto_secretbox_KEYBYTES];
  crypto_engine_derive_block_key(key, transfer->encryption_key,
                                 transfer->header.salt, transfer->sequence, 0);
  size_t plain_len = 0;
  int rc = crypto_engine_decrypt_block(transfer->header.cipher, frame->payload,
                                       frame->payload_len, key,
                                       transfer->sequence, 0, data, &plain_len);
  sodium_memzero(key, sizeof(key));
  if (rc < 0 || plain_len + NASFS_VERSION_BLOCK_TAG != frame->payload_len) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Decryption failed. Wrong key or corrupted data\n");
    free(data);
    return -1;
  }
  uint64_t block_start = transfer->sequence * transfer->header.block_size;
  size_t trim =
      transfer->start > block_start ? transfer->start - block_start : 0;
  size_t length = plain_len - trim;
  uint64_t remaining = transfer->length - transfer->file_offset;
  if (length > remaining) length = remaining;
  uv_buf_t buffer = uv_buf_init((char*)data + trim, length);
  uv_fs_t req;
  rc = uv_fs_write(client->loop, &req, transfer->local_fd, &buffer, 1,
                   (int64_t)transfer->file_offset, NULL);
  uv_fs_req_cleanup(&req);
  sodium_memzero(data, plain_len);
  free(data);
  if (rc < 0 || (size_t)rc != length) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Failed to write downloaded data: %s\n",
                   rc < 0 ? uv_strerror(rc) : "short write");
    return -1;
  }
  transfer->file_offset += length;
  nasfs_version_index_add(&transfer->index, &transfer->expected);
  transfer->sequence++;
  transfer->has_pending_block_meta = 0;
  report_event(client, NASFS_CLIENT_PROGRESS, transfer->file_offset);
  if (transfer->header.ecc != NASFS_ECC_OFF)
    send_command(stream, NASFS_CMD_GET_ADVANCE, NULL, 0, 1);
  return 0;
}

static int receive_block(uv_stream_t* stream, const nasfs_frame_t* frame) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  if (!transfer->has_pending_block_meta || transfer->repair_active ||
      frame->payload_len != transfer->expected.size)
    return -1;
  uint8_t digest[32];
  if (nasfs_version_hash_block(transfer->header.hash, frame->payload,
                               frame->payload_len, digest) < 0)
    return -1;
  if (sodium_memcmp(digest, transfer->expected.hash, sizeof(digest)) == 0)
    return store_verified_block(stream, frame);
  if (transfer->header.ecc != NASFS_ECC_OFF) return request_repair(stream);
  client_message(client, NASFS_CLIENT_ERROR,
                 "Integrity check failed (hash mismatch)\n");
  return -1;
}

static int complete_repair(uv_stream_t* stream, const nasfs_frame_t* done) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  if (!transfer->repair_active || done->payload_len ||
      transfer->repair_position !=
          transfer->repair_data + transfer->repair_parity)
    return -1;
  size_t padded = transfer->header.block_size + NASFS_VERSION_BLOCK_TAG;
  uint8_t* bytes = malloc(padded);
  if (!bytes) return -1;
  const uint8_t* p = transfer->repair_rows[transfer->repair_data];
  const uint8_t* q = transfer->repair_parity == 2
                         ? transfer->repair_rows[transfer->repair_data + 1]
                         : NULL;
  int rc = nasfs_ecc_restore(transfer->repair_rows, transfer->repair_data, p, q,
                             transfer->repair_target, padded, bytes);
  clear_repair(transfer);
  if (!rc) {
    uint8_t digest[32];
    size_t length = transfer->expected.size;
    if (nasfs_version_hash_block(transfer->header.hash, bytes, length,
                                 digest) != 0 ||
        sodium_memcmp(digest, transfer->expected.hash, sizeof(digest)) != 0) {
      rc = -1;
    } else {
      nasfs_frame_t repaired = {.payload = bytes, .payload_len = length};
      rc = store_verified_block(stream, &repaired);
    }
  }
  free(bytes);
  if (rc < 0)
    client_message(client, NASFS_CLIENT_ERROR, "ECC recovery failed\n");
  else
    client_message(client, NASFS_CLIENT_INFO,
                   "\nRecovered ciphertext with ECC.\n");
  return rc;
}

static int verify_download(nasfs_client_t* client, const nasfs_frame_t* frame) {
  client_transfer_t* transfer = &client->transfer;
  if (transfer->local_fd < 0 || frame->payload_len != 0 ||
      transfer->has_pending_block_meta || transfer->sequence != transfer->end ||
      transfer->file_offset != transfer->length ||
      (transfer->partial && !transfer->index_verified))
    return -1;
  uint8_t root[32];
  nasfs_version_index_final(&transfer->index, root);
  if (sodium_memcmp(root, transfer->index_root, sizeof(root)) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "File manifest index mismatch\n");
    return -1;
  }
  return publish_download(client);
}

static void start_resolved_operation(uv_stream_t* stream,
                                     const nasfs_frame_t* frame) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  if (!transfer->resolve_pending ||
      (frame->payload_len != 0 && frame->payload_len != 48)) {
    close_connection((uv_handle_t*)stream);
    return;
  }
  transfer->resolve_pending = 0;
  nasfs_client_result_t* result = &client->results[client->batch_idx - 1];
  if (frame->payload_len == 48) {
    memcpy(transfer->version.id, frame->payload, sizeof(transfer->version.id));
    memcpy(transfer->version.digest, frame->payload + 16,
           sizeof(transfer->version.digest));
  }
  if (transfer->current_op == NASFS_CLIENT_PUT) {
    if (transfer->batch_upload_exclusive && frame->payload_len != 0) {
      result->outcome = NASFS_CLIENT_CONFLICT;
      client_message(client, NASFS_CLIENT_ERROR,
                     "Server could not publish '%s': name already exists\n",
                     transfer->remote_filename);
      close_connection((uv_handle_t*)stream);
      return;
    }
    if (frame->payload_len == 0) {
      do {
        randombytes_buf(transfer->version.id, sizeof(transfer->version.id));
      } while (
          sodium_is_zero(transfer->version.id, sizeof(transfer->version.id)));
    }
    memcpy(transfer->header.id, transfer->version.id,
           sizeof(transfer->header.id));
    memcpy(transfer->header.parent, transfer->version.digest,
           sizeof(transfer->header.parent));
    send_put_req(stream);
    return;
  }
  if (frame->payload_len == 0) {
    result->outcome = NASFS_CLIENT_NOT_FOUND;
    client_message(client, NASFS_CLIENT_ERROR,
                   "Server error: version unavailable\n");
    close_connection((uv_handle_t*)stream);
    return;
  }
  if (transfer->current_op == NASFS_CLIENT_RESOLVE) {
    result->outcome = NASFS_CLIENT_RESOLVED;
    result->version = transfer->version;
    report_event(client, NASFS_CLIENT_COMPLETED, 0);
    start_next_operation(stream);
    return;
  }
  if (client->options->expected_digest &&
      sodium_memcmp(client->options->expected_digest, transfer->version.digest,
                    32) != 0) {
    client_message(client, NASFS_CLIENT_ERROR,
                   "Unexpected file manifest version\n");
    close_connection((uv_handle_t*)stream);
    return;
  }
  send_get_req(stream);
}

/* Reset per-file transfer state and start the next queued operation. */
static void start_next_operation(uv_stream_t* stream) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  if (close_local_file(client) < 0) {
    close_connection((uv_handle_t*)stream);
    return;
  }
  close_ecc(transfer);
  sodium_memzero(transfer, sizeof(*transfer));
  transfer->local_fd = -1;
  transfer->download_directory = -1;
  transfer->download_staging = -1;

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

  if (op->operation == NASFS_CLIENT_COLLECT) {
    send_command(stream, NASFS_CMD_COLLECT, NULL, 0, 1);
    return;
  }
  if (op->operation == NASFS_CLIENT_GET) {
    if (prepare_download(client) < 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Cannot prepare download '%s': %s\n",
                     transfer->local_filename, strerror(errno));
      close_connection((uv_handle_t*)stream);
      return;
    }
    if (op->version) {
      transfer->version = *op->version;
      transfer->start = op->offset;
      transfer->length = op->length;
      send_get_req(stream);
      return;
    }
    transfer->length = UINT64_MAX;
  }
  transfer->resolve_pending = 1;
  send_command(stream, NASFS_CMD_RESOLVE, (const uint8_t*)op->remote_name,
               strlen(op->remote_name) + 1, 1);
}

static void close_connection(uv_handle_t* handle) {
  nasfs_client_t* client = handle->data;
  if (uv_is_closing(handle)) return;
  if (!client->client_finished && client->client_exit_code == 0)
    client->client_exit_code = 1;
  if (client->transfer.put_result_pending) {
    client->results[client->batch_idx - 1].outcome = NASFS_CLIENT_PUT_UNKNOWN;
    client->results[client->batch_idx - 1].version = client->transfer.version;
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
  close_ecc(&client->transfer);
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

static void send_parity(uv_stream_t* stream, uint64_t first, unsigned count,
                        uint32_t length) {
  nasfs_client_t* client = stream->data;
  client_transfer_t* transfer = &client->transfer;
  for (unsigned i = 0; i < count && !uv_is_closing((uv_handle_t*)stream); i++) {
    nasfs_block_meta_t meta = {.seq_num = first + i, .size = length};
    if (nasfs_version_hash_block(transfer->header.hash, transfer->parity[i],
                                 length, meta.hash) != 0) {
      close_connection((uv_handle_t*)stream);
      return;
    }
    uint8_t row[NASFS_BLOCK_META_SIZE];
    protocol_encode_block_meta(row, &meta);
    nasfs_version_index_add(&transfer->index, &meta);
    send_command(stream, NASFS_CMD_PUT_BLOCK_META, row, sizeof(row), 1);
    if (uv_is_closing((uv_handle_t*)stream)) return;
    send_command(stream, NASFS_CMD_PUT_PARITY, transfer->parity[i], length, 0);
    if (uv_is_closing((uv_handle_t*)stream)) return;
    memset(transfer->parity[i], 0, length);
  }
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
  } else if (req->result == 0 &&
             transfer->file_offset == transfer->header.size) {
    uint8_t root[32], proof[NASFS_VERSION_PROOF_SIZE];
    nasfs_version_index_final(&transfer->index, root);
    if (nasfs_version_sign(&transfer->header, root, client->author_secret,
                           proof) != 0) {
      close_connection((uv_handle_t*)stream);
      goto cleanup;
    }
    memcpy(transfer->version.digest, proof + 32,
           sizeof(transfer->version.digest));
    client_message(client, NASFS_CLIENT_INFO,
                   "\nFinished reading local file. Waiting for publication.\n");
    send_command(stream, NASFS_CMD_PUT_DONE, proof, sizeof(proof), 1);
  } else {
    int64_t record_offset;
    uint32_t cipher_len;
    uint64_t physical =
        nasfs_version_data_sequence(&transfer->header, transfer->sequence);
    if (nasfs_version_record(&transfer->header, physical, &record_offset,
                             &cipher_len) < 0 ||
        req->result != (ssize_t)(cipher_len - NASFS_VERSION_BLOCK_TAG)) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "PUT source size changed during upload: %s\n",
                     transfer->local_filename);
      close_connection((uv_handle_t*)stream);
      goto cleanup;
    }
    uint8_t* ciphertext = malloc(cipher_len);
    if (!ciphertext) {
      close_connection((uv_handle_t*)stream);
      goto cleanup;
    }
    uint8_t key[crypto_secretbox_KEYBYTES];
    crypto_engine_derive_block_key(key, transfer->encryption_key,
                                   transfer->header.salt, transfer->sequence,
                                   0);
    size_t written = 0;
    int rc = crypto_engine_encrypt_block(
        transfer->header.cipher, (const uint8_t*)ctx->buf.base, req->result,
        key, transfer->sequence, ciphertext, &written);
    sodium_memzero(key, sizeof(key));
    nasfs_block_meta_t meta = {.seq_num = physical, .size = cipher_len};
    if (rc != 0 || written != cipher_len ||
        nasfs_version_hash_block(transfer->header.hash, ciphertext, cipher_len,
                                 meta.hash) != 0) {
      free(ciphertext);
      close_connection((uv_handle_t*)stream);
      goto cleanup;
    }
    unsigned data, parity;
    uint64_t start;
    if (nasfs_version_group(&transfer->header, transfer->sequence, &start,
                            &data, &parity) < 0) {
      free(ciphertext);
      close_connection((uv_handle_t*)stream);
      goto cleanup;
    }
    if (parity)
      nasfs_ecc_accumulate(transfer->parity[0], transfer->parity[1], ciphertext,
                           (unsigned)(transfer->sequence - start), cipher_len);
    uint8_t row[NASFS_BLOCK_META_SIZE];
    protocol_encode_block_meta(row, &meta);
    nasfs_version_index_add(&transfer->index, &meta);
    transfer->sequence++;
    transfer->file_offset += (uint64_t)req->result;
    send_command(stream, NASFS_CMD_PUT_BLOCK_META, row, sizeof(row), 1);
    send_command(stream, NASFS_CMD_PUT_DATA, ciphertext, cipher_len, 0);
    free(ciphertext);
    if (parity && transfer->sequence == start + data)
      send_parity(stream, physical + 1, parity,
                  transfer->header.block_size + NASFS_VERSION_BLOCK_TAG);
    report_event(client, NASFS_CLIENT_PROGRESS, transfer->file_offset);
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

          if (nasfs_control_command(frame.type)) {
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
              if (client->batch_idx != 0 || plain_frame.payload_len != 0) {
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
            case NASFS_CMD_RESOLVED:
              start_resolved_operation(stream, &plain_frame);
              break;
            case NASFS_CMD_COLLECTED:
              if (transfer->current_op != NASFS_CLIENT_COLLECT ||
                  plain_frame.payload_len != 0) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              client->results[client->batch_idx - 1].outcome =
                  NASFS_CLIENT_COLLECTED;
              report_event(client, NASFS_CLIENT_COMPLETED, 0);
              start_next_operation(stream);
              break;
            case NASFS_CMD_PUT_RESULT: {
              if ((!transfer->put_result_pending &&
                   !transfer->put_ack_pending) ||
                  plain_frame.payload_len != 1 ||
                  plain_frame.payload[0] > NASFS_PUT_UNCERTAIN ||
                  (!transfer->put_result_pending &&
                   plain_frame.payload[0] == NASFS_PUT_PUBLISHED) ||
                  plain_frame.payload[0] == NASFS_PUT_UNCERTAIN) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              transfer->put_result_pending = 0;
              nasfs_client_result_t* result =
                  &client->results[client->batch_idx - 1];
              uint8_t status = plain_frame.payload[0];
              if (status == NASFS_PUT_PUBLISHED) {
                result->outcome = NASFS_CLIENT_PUT_PUBLISHED;
                result->version = transfer->version;
                report_event(client, NASFS_CLIENT_COMPLETED,
                             transfer->file_offset);
                start_next_operation(stream);
              } else {
                result->outcome =
                    status == NASFS_PUT_CONFLICT ? NASFS_CLIENT_CONFLICT
                    : status == NASFS_PUT_QUOTA  ? NASFS_CLIENT_QUOTA
                                                 : NASFS_CLIENT_REJECTED;
                const char* reason =
                    status == NASFS_PUT_CONFLICT ? "version conflict"
                    : status == NASFS_PUT_QUOTA ? "quota exceeded; run collect "
                                                  "to reclaim expired versions"
                                                : "publication rejected";
                client_message(client, NASFS_CLIENT_ERROR,
                               "Server could not publish '%s': %s\n",
                               transfer->remote_filename, reason);
                close_connection((uv_handle_t*)stream);
              }
              break;
            }
            case NASFS_CMD_GET_ACK:
              if (begin_download(client, &plain_frame) < 0)
                close_connection((uv_handle_t*)stream);
              break;
            case NASFS_CMD_GET_INDEX:
              if (receive_index(transfer, &plain_frame) < 0) {
                client_message(client, NASFS_CLIENT_ERROR,
                               "File manifest index mismatch\n");
                close_connection((uv_handle_t*)stream);
              }
              break;
            case NASFS_CMD_GET_BLOCK_META:
              if (receive_block_meta(transfer, &plain_frame) < 0)
                close_connection((uv_handle_t*)stream);
              break;
            case NASFS_CMD_GET_DATA:
              if (receive_block(stream, &plain_frame) < 0)
                close_connection((uv_handle_t*)stream);
              break;
            case NASFS_CMD_GET_REPAIR_DATA:
              if (receive_repair_row(transfer, &plain_frame) < 0)
                close_connection((uv_handle_t*)stream);
              break;
            case NASFS_CMD_GET_REPAIR_DONE:
              if (complete_repair(stream, &plain_frame) < 0)
                close_connection((uv_handle_t*)stream);
              break;
            case NASFS_CMD_GET_DONE:
              if (verify_download(client, &plain_frame) < 0) {
                close_connection((uv_handle_t*)stream);
                break;
              }
              client->results[client->batch_idx - 1].outcome =
                  NASFS_CLIENT_GET_PUBLISHED;
              client->results[client->batch_idx - 1].version =
                  transfer->version;
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
  int is_upload = operation == NASFS_CLIENT_PUT;
  int transferring = is_upload || operation == NASFS_CLIENT_GET;
  if (operation < NASFS_CLIENT_PUT || operation > NASFS_CLIENT_COLLECT ||
      !options->ip || options->port < 1 || options->port > 65535 ||
      !options->kex_algorithms || !options->cipher_algorithms ||
      !options->auth_method || !options->auth_user ||
      (transferring &&
       (!options->encryption_password || !*options->encryption_password)) ||
      !options->block_size || options->block_size > NASFS_VERSION_MAX_BLOCK ||
      options->block_size < NASFS_VERSION_MIN_BLOCK || sodium_init() < 0) {
    if (options->notify)
      options->notify(options->callback_data, NASFS_CLIENT_ERROR, 0, 0,
                      "Invalid NASFS client options\n");
    return 1;
  }
  for (size_t i = 0; i < count; i++) {
    const nasfs_client_request_t* op = &requests[i];
    if (op->operation != operation || (transferring && !op->local_path) ||
        ((operation != NASFS_CLIENT_COLLECT && !op->version) &&
         (!op->remote_name || !*op->remote_name ||
          strlen(op->remote_name) > 255)) ||
        (op->version && operation != NASFS_CLIENT_GET) ||
        (op->version && options->expected_digest &&
         sodium_memcmp(op->version->digest, options->expected_digest, 32) != 0))
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
  int return_code = 1;
  if (transferring) {
    uint8_t master_salt[crypto_pwhash_SALTBYTES];
    if (load_master_salt(client, master_salt, is_upload) < 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Cannot load or save ~/.nasfs/master.salt: %s\n",
                     strerror(errno));
      goto cleanup;
    }
    if (crypto_engine_derive_key(
            NASFS_KDF_ARGON2ID, options->encryption_password,
            strlen(options->encryption_password), master_salt,
            sizeof(master_salt), client->master_key,
            sizeof(client->master_key)) != 0) {
      client_message(client, NASFS_CLIENT_ERROR,
                     "Failed to derive master key\n");
      goto cleanup;
    }
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

  if (transferring && client->options->auth_password &&
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
  } else if (transferring) {
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
