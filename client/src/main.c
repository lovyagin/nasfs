/**
 * @file main.c
 * @brief Main entry point for the NASFS client CLI with PQC handshake.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * Implements an asynchronous libuv-based client that supports
 * PQC key exchange, and subsequent PUT/GET file operations over an
 * encrypted control channel.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <oqs/oqs.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <uv.h>

#include "auth.h"
#include "crypto_engine.h"
#include "handshake.h"
#include "protocol.h"

static nasfs_cipher_algo_t parse_cipher_algo(const char* s) {
  if (!s) return NASFS_CIPHER_XSALSA20_POLY1305;
  if (strcmp(s, "xchacha20poly1305") == 0) return NASFS_CIPHER_XCHACHA20_POLY1305;
  if (strcmp(s, "aes256gcm") == 0) return NASFS_CIPHER_AES_256_GCM;
  return NASFS_CIPHER_XSALSA20_POLY1305; /* default */
}

static nasfs_hash_algo_t parse_hash_algo(const char* s) {
  if (!s) return NASFS_HASH_BLAKE2B;
  if (strcmp(s, "sha256") == 0) return NASFS_HASH_SHA256;
  if (strcmp(s, "adler32") == 0) return NASFS_HASH_ADLER32;
  if (strcmp(s, "crc32") == 0) return NASFS_HASH_CRC32;
  return NASFS_HASH_BLAKE2B; /* default */
}

static nasfs_kdf_algo_t parse_kdf_algo(const char* s) {
  if (!s) return NASFS_KDF_ARGON2ID;
  if (strcmp(s, "hkdf") == 0 || strcmp(s, "hkdf-sha256") == 0)
    return NASFS_KDF_HKDF_SHA256;
  if (strcmp(s, "pbkdf2") == 0 || strcmp(s, "pbkdf2-sha256") == 0)
    return NASFS_KDF_PBKDF2_SHA256;
  return NASFS_KDF_ARGON2ID; /* default */
}

#define IO_CHUNK_SIZE (64 * 1024)
#define CLIENT_INITIAL_BUFFER 16384
#define CLIENT_MAX_RECV_BUFFER (64 * 1024 * 1024)
#define DEFAULT_KEX_ALGORITHMS "ML-KEM-512,Kyber512,ML-KEM-768,Kyber768"
#define DEFAULT_CIPHER_ALGORITHMS NASFS_CONTROL_CIPHER_XCHACHA20POLY1305

typedef enum { OP_NONE, OP_PUT, OP_GET } client_op_t;

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

/* Global State */
uv_loop_t* loop;
client_op_t current_op = OP_NONE;
const char* local_filename = NULL;
const char* remote_filename = NULL;
uv_file local_fd = -1;
uint64_t file_offset = 0;

uint8_t* client_recv_buffer = NULL;
size_t client_recv_length = 0;
size_t client_recv_capacity = 0;

uint8_t* shared_secret = NULL;
size_t shared_secret_len = 0;
int is_secure = 0;
int client_exit_code = 0;
crypto_secretstream_xchacha20poly1305_state send_crypto_state;
crypto_secretstream_xchacha20poly1305_state recv_crypto_state;
const char* client_kex_algorithms = DEFAULT_KEX_ALGORITHMS;
const char* client_cipher_algorithms = DEFAULT_CIPHER_ALGORITHMS;
const char* client_auth_method = NASFS_AUTH_METHOD_PASSWORD;
const char* client_auth_user = "user";
const char* client_auth_password = "nasfs";
const char* client_identity_file = NULL;
const char* client_auth_sig_algorithm = NASFS_AUTH_DEFAULT_SIG_ALGORITHM;
char* negotiated_kex_algorithm = NULL;
char* negotiated_cipher_algorithm = NULL;

/* File Encryption/Integrity State */
int file_encryption_enabled = 0;
char* raw_encryption_password = NULL;
uint8_t file_salt[crypto_pwhash_SALTBYTES] = {0};
uint8_t encryption_key[crypto_secretbox_KEYBYTES] = {0};
uint8_t master_key[32] = {0};
uint64_t client_block_seq = 0;
int has_pending_block_meta = 0;
uint64_t expected_block_seq = 0;
uint32_t expected_block_size = 0;
uint8_t expected_block_hash[32] = {0};

/* File size tracking for truncation detection */
uint64_t put_plaintext_size = 0;      /* size of local file being uploaded */
uint64_t expected_plaintext_size = 0; /* expected size announced in GET_ACK */

/* Modular algorithm selection */
nasfs_cipher_algo_t file_cipher_algo = NASFS_CIPHER_XSALSA20_POLY1305;
nasfs_hash_algo_t file_hash_algo = NASFS_HASH_BLAKE2B;
nasfs_kdf_algo_t master_kdf_algo = NASFS_KDF_ARGON2ID;

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

const char* client_server_ip = SERVER_IP;
int client_server_port = SERVER_PORT;

/* Forward Declarations */
void send_command(uv_stream_t* stream, nasfs_cmd_type_t cmd,
                  const uint8_t* payload, size_t payload_len, int encrypt);
void do_put_read_chunk(uv_stream_t* stream);
void on_close(uv_handle_t* handle);

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

static const char* get_basename(const char* path) {
  const char* base = strrchr(path, '/');
  if (!base) base = strrchr(path, '\\');
  return base ? base + 1 : path;
}

static int auth_method_requires_password(const char* method) {
  return strcmp(method, NASFS_AUTH_METHOD_PASSWORD) == 0 ||
         strcmp(method, NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY) == 0;
}

static int auth_method_requires_publickey(const char* method) {
  return strcmp(method, NASFS_AUTH_METHOD_PUBLICKEY) == 0 ||
         strcmp(method, NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY) == 0;
}

static int write_keypair_files(const char* private_path,
                               const char* public_path, const char* algorithm) {
  OQS_SIG* sig;
  uint8_t* public_key = NULL;
  uint8_t* secret_key = NULL;
  char* public_hex = NULL;
  char* secret_hex = NULL;
  FILE* private_file = NULL;
  FILE* public_file = NULL;
  int rc = 1;

  sig = OQS_SIG_new(algorithm);
  if (!sig) {
    fprintf(stderr, "Unsupported signature algorithm: %s\n", algorithm);
    return 1;
  }

  public_key = malloc(sig->length_public_key);
  secret_key = malloc(sig->length_secret_key);
  if (!public_key || !secret_key ||
      OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
    fprintf(stderr, "Failed to generate signature keypair\n");
    goto out;
  }

  public_hex = nasfs_hex_encode(public_key, sig->length_public_key);
  secret_hex = nasfs_hex_encode(secret_key, sig->length_secret_key);
  if (!public_hex || !secret_hex) {
    fprintf(stderr, "Failed to encode signature keypair\n");
    goto out;
  }

  private_file = fopen(private_path, "w");
  if (!private_file) {
    fprintf(stderr, "Failed to open private key file: %s\n", private_path);
    goto out;
  }
  if (fprintf(private_file, "NASFS-MLDSA-PRIVATE-v1\n%s\n%s\n%s\n", algorithm,
              public_hex, secret_hex) < 0) {
    fprintf(stderr, "Failed to write private key file: %s\n", private_path);
    goto out;
  }
  fclose(private_file);
  private_file = NULL;
  chmod(private_path, S_IRUSR | S_IWUSR);

  public_file = fopen(public_path, "w");
  if (!public_file) {
    fprintf(stderr, "Failed to open public key file: %s\n", public_path);
    goto out;
  }
  if (fprintf(public_file, "%s %s\n", algorithm, public_hex) < 0) {
    fprintf(stderr, "Failed to write public key file: %s\n", public_path);
    goto out;
  }

  rc = 0;

out:
  if (private_file) fclose(private_file);
  if (public_file) fclose(public_file);
  free(public_hex);
  free(secret_hex);
  free(public_key);
  free(secret_key);
  OQS_SIG_free(sig);
  return rc;
}

static int load_identity_file(const char* path, const char* expected_algorithm,
                              char** algorithm, uint8_t** public_key,
                              size_t* public_key_len, uint8_t** secret_key,
                              size_t* secret_key_len) {
  FILE* file;
  char header[128];
  char alg_line[128];
  char public_hex[10000];
  char secret_hex[10000];

  if (!path || !algorithm || !public_key || !public_key_len || !secret_key ||
      !secret_key_len) {
    return -1;
  }

  file = fopen(path, "r");
  if (!file) {
    fprintf(stderr, "Failed to open identity file: %s\n", path);
    return -1;
  }

  if (!fgets(header, sizeof(header), file) ||
      !fgets(alg_line, sizeof(alg_line), file) ||
      !fgets(public_hex, 10000, file) || !fgets(secret_hex, 10000, file)) {
    fclose(file);
    return -1;
  }
  fclose(file);

  trim_line(header);
  trim_line(alg_line);
  trim_line(public_hex);
  trim_line(secret_hex);

  if (strcmp(header, "NASFS-MLDSA-PRIVATE-v1") != 0 ||
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

static int build_publickey_signature(char** algorithm, uint8_t** public_key,
                                     size_t* public_key_len,
                                     uint8_t** signature,
                                     size_t* signature_len) {
  uint8_t* secret_key = NULL;
  size_t secret_key_len = 0;
  uint8_t* message = NULL;
  size_t message_len = 0;
  OQS_SIG* sig = NULL;
  int rc = -1;

  if (!client_identity_file) {
    fprintf(stderr, "NASFS_IDENTITY_FILE is required for publickey auth\n");
    return -1;
  }

  if (load_identity_file(client_identity_file, client_auth_sig_algorithm,
                         algorithm, public_key, public_key_len, &secret_key,
                         &secret_key_len) != 0) {
    fprintf(stderr, "Failed to load identity file\n");
    return -1;
  }

  sig = OQS_SIG_new(*algorithm);
  if (!sig || *public_key_len != sig->length_public_key ||
      secret_key_len != sig->length_secret_key) {
    fprintf(stderr, "Identity file does not match signature algorithm\n");
    goto out;
  }

  message =
      nasfs_auth_build_message(client_auth_method, client_auth_user,
                               shared_secret, shared_secret_len, &message_len);
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

static void send_auth(uv_stream_t* stream) {
  nasfs_auth_payload_t auth = {0};
  uint8_t* payload = NULL;
  size_t payload_len = 0;
  char* sig_algorithm = NULL;
  char* password_proof_hex = NULL;

  auth.method = (char*)client_auth_method;
  auth.username = (char*)client_auth_user;
  if (auth_method_requires_password(client_auth_method)) {
    // 1. Domain Separation: Compute client-side memory-hard authentication
    // password P_auth
    uint8_t p_auth[32];
    uint8_t auth_salt[crypto_pwhash_SALTBYTES];
    // Static domain salt for authentication
    memset(auth_salt, 0x55, sizeof(auth_salt));

    if (crypto_pwhash(p_auth, sizeof(p_auth), client_auth_password,
                      strlen(client_auth_password), auth_salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
      fprintf(stderr, "Failed to derive P_auth using Argon2id\n");
      client_exit_code = 1;
      uv_close((uv_handle_t*)stream, on_close);
      return;
    }

    // 2. DoS-safe Fast Challenge-Response: Proof = BLAKE2b(shared_secret,
    // key=P_auth)
    uint8_t proof[32];
    if (crypto_generichash(proof, sizeof(proof), (const uint8_t*)shared_secret,
                           shared_secret_len, p_auth, sizeof(p_auth)) != 0) {
      fprintf(stderr, "Failed to compute fast session password proof\n");
      client_exit_code = 1;
      uv_close((uv_handle_t*)stream, on_close);
      return;
    }
    password_proof_hex = nasfs_hex_encode(proof, sizeof(proof));
    auth.password = password_proof_hex;
  }

  if (auth_method_requires_publickey(client_auth_method) &&
      build_publickey_signature(&sig_algorithm, &auth.public_key,
                                &auth.public_key_len, &auth.signature,
                                &auth.signature_len) != 0) {
    client_exit_code = 1;
    free(password_proof_hex);
    uv_close((uv_handle_t*)stream, on_close);
    return;
  }
  auth.sig_algorithm = sig_algorithm;

  payload = nasfs_auth_pack(&auth, &payload_len);
  free(sig_algorithm);
  free(auth.public_key);
  free(auth.signature);
  free(password_proof_hex);
  if (!payload) {
    client_exit_code = 1;
    uv_close((uv_handle_t*)stream, on_close);
    return;
  }

  send_command(stream, NASFS_CMD_AUTH, payload, payload_len, 1);
  free(payload);
}

void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  if (client_recv_capacity - client_recv_length < suggested_size) {
    size_t new_cap = client_recv_capacity == 0 ? CLIENT_INITIAL_BUFFER
                                               : client_recv_capacity * 2;
    while (new_cap - client_recv_length < suggested_size) new_cap *= 2;
    if (new_cap > CLIENT_MAX_RECV_BUFFER) {
      buf->base = NULL;
      buf->len = 0;
      uv_close(handle, on_close);
      return;
    }
    uint8_t* new_buf = realloc(client_recv_buffer, new_cap);
    if (!new_buf) {
      buf->base = NULL;
      buf->len = 0;
      uv_close(handle, on_close);
      return;
    }
    client_recv_buffer = new_buf;
    client_recv_capacity = new_cap;
  }
  buf->base = (char*)(client_recv_buffer + client_recv_length);
  buf->len = client_recv_capacity - client_recv_length;
}

void on_close(uv_handle_t* handle) {
  if (client_recv_buffer) free(client_recv_buffer);
  if (shared_secret) sodium_free(shared_secret);
  if (negotiated_kex_algorithm) free(negotiated_kex_algorithm);
  if (negotiated_cipher_algorithm) free(negotiated_cipher_algorithm);
  if (local_fd != -1) uv_fs_close(loop, &(uv_fs_t){}, local_fd, NULL);
  free(handle);
  printf("\nConnection closed.\n");
}

void on_write(uv_write_t* req, int status) {
  nasfs_write_ctx_t* ctx = (nasfs_write_ctx_t*)req;
  uv_stream_t* stream = req->handle;
  if (status) {
    fprintf(stderr, "Write error: %s\n", uv_strerror(status));
    client_exit_code = 1;
  }

  if (ctx->buf.base) free(ctx->buf.base);
  if (current_op == OP_PUT && status == 0) {
    if (local_fd != -1 && ctx->type == NASFS_CMD_PUT_DATA) {
      free(ctx);
      do_put_read_chunk(stream);
      return;
    }
    if (ctx->type == NASFS_CMD_PUT_DONE) {
      free(ctx);
      uv_close((uv_handle_t*)stream, on_close);
      return;
    }
  }

  free(ctx);
}

void send_command(uv_stream_t* stream, nasfs_cmd_type_t cmd,
                  const uint8_t* payload, size_t payload_len, int encrypt) {
  uint8_t* payload_to_pack = (uint8_t*)payload;
  size_t payload_to_pack_len = payload_len;
  uint8_t* encrypted_payload = NULL;

  if (encrypt && is_secure) {
    payload_to_pack_len =
        payload_len + crypto_secretstream_xchacha20poly1305_ABYTES;
    encrypted_payload = malloc(payload_to_pack_len);
    if (!encrypted_payload) return;

    crypto_secretstream_xchacha20poly1305_push(&send_crypto_state,
                                               encrypted_payload, NULL, payload,
                                               payload_len, NULL, 0, 0);
    payload_to_pack = encrypted_payload;
  }

  size_t frame_size;
  uint8_t* frame_data = protocol_pack_frame(cmd, payload_to_pack,
                                            payload_to_pack_len, &frame_size);
  if (encrypted_payload) free(encrypted_payload);
  if (!frame_data) return;

  nasfs_write_ctx_t* ctx = malloc(sizeof(nasfs_write_ctx_t));
  if (!ctx) {
    free(frame_data);
    return;
  }

  ctx->buf = uv_buf_init((char*)frame_data, frame_size);
  ctx->type = cmd;
  if (uv_write(&ctx->req, stream, &ctx->buf, 1, on_write) < 0) {
    free(frame_data);
    free(ctx);
  }
}

void on_local_read(uv_fs_t* req) {
  nasfs_fs_ctx_t* ctx = (nasfs_fs_ctx_t*)req->data;
  uv_stream_t* stream = ctx->stream;

  if (req->result < 0) {
    fprintf(stderr, "\nRead error: %s\n", uv_strerror((int)req->result));
    client_exit_code = 1;
    uv_close((uv_handle_t*)stream, on_close);
  } else if (req->result == 0) {
    printf("\nFinished reading local file. Sending PUT_DONE.\n");
    send_command(stream, NASFS_CMD_PUT_DONE, NULL, 0, 1);
  } else {
    size_t bytes_read = req->result;
    file_offset += bytes_read;

    if (file_encryption_enabled) {
      size_t ciphertext_len = bytes_read + 32; /* max overhead for any cipher */
      uint8_t* ciphertext = malloc(ciphertext_len);
      if (!ciphertext) {
        fprintf(stderr, "\nOut of memory for encryption\n");
        client_exit_code = 1;
        uv_close((uv_handle_t*)stream, on_close);
        if (ctx->buf.base) free(ctx->buf.base);
        uv_fs_req_cleanup(req);
        free(ctx);
        return;
      }

      /* Derive a per-block key: BLAKE2b(encryption_key || file_salt || seq) */
      uint8_t block_key[crypto_secretbox_KEYBYTES];
      uint8_t key_input[crypto_secretbox_KEYBYTES + crypto_pwhash_SALTBYTES +
                        sizeof(client_block_seq)];
      memcpy(key_input, encryption_key, crypto_secretbox_KEYBYTES);
      memcpy(key_input + crypto_secretbox_KEYBYTES, file_salt,
             crypto_pwhash_SALTBYTES);
      memcpy(key_input + crypto_secretbox_KEYBYTES + crypto_pwhash_SALTBYTES,
             &client_block_seq, sizeof(client_block_seq));
      crypto_generichash(block_key, sizeof(block_key), key_input,
                         sizeof(key_input), NULL, 0);

      size_t actual_ciphertext_len = 0;
      if (crypto_engine_encrypt_block(file_cipher_algo,
                                      (const uint8_t*)ctx->buf.base, bytes_read,
                                      block_key, client_block_seq, ciphertext,
                                      &actual_ciphertext_len) != 0) {
        fprintf(stderr, "\nEncryption failed\n");
        free(ciphertext);
        client_exit_code = 1;
        uv_close((uv_handle_t*)stream, on_close);
        if (ctx->buf.base) free(ctx->buf.base);
        uv_fs_req_cleanup(req);
        free(ctx);
        return;
      }
      ciphertext_len = actual_ciphertext_len;

      nasfs_block_meta_t meta;
      meta.seq_num = client_block_seq;
      meta.size = (uint32_t)ciphertext_len;
      memset(meta.hash, 0, sizeof(meta.hash));
      size_t hash_out_len = 0;
      if (crypto_engine_hash(file_hash_algo, ciphertext, ciphertext_len,
                             meta.hash, &hash_out_len) != 0) {
        fprintf(stderr, "\nHash computation failed\n");
        free(ciphertext);
        client_exit_code = 1;
        uv_close((uv_handle_t*)stream, on_close);
        if (ctx->buf.base) free(ctx->buf.base);
        uv_fs_req_cleanup(req);
        free(ctx);
        return;
      }

      send_command(stream, NASFS_CMD_PUT_BLOCK_META, (const uint8_t*)&meta,
                   sizeof(meta), 1);
      client_block_seq++;

      send_command(stream, NASFS_CMD_PUT_DATA, ciphertext, ciphertext_len, 0);
      free(ciphertext);
    } else {
      send_command(stream, NASFS_CMD_PUT_DATA, (uint8_t*)ctx->buf.base,
                   bytes_read, 1);
    }

    printf("\rUploaded %llu bytes...", (unsigned long long)file_offset);
    fflush(stdout);
  }
  if (ctx->buf.base) free(ctx->buf.base);
  uv_fs_req_cleanup(req);
  free(ctx);
}

void do_put_read_chunk(uv_stream_t* stream) {
  nasfs_fs_ctx_t* ctx = malloc(sizeof(nasfs_fs_ctx_t));
  if (!ctx) return;
  ctx->buf = uv_buf_init(malloc(IO_CHUNK_SIZE), IO_CHUNK_SIZE);
  ctx->stream = stream;
  ctx->req.data = ctx;
  if (uv_fs_read(loop, &ctx->req, local_fd, &ctx->buf, 1, file_offset,
                 on_local_read) < 0) {
    free(ctx->buf.base);
    free(ctx);
  }
}

void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
  (void)buf;

  if (nread > 0) {
    client_recv_length += nread;
    while (client_recv_length > 0) {
      nasfs_frame_t frame;
      int consumed =
          protocol_parse_frame(client_recv_buffer, client_recv_length, &frame);
      if (consumed > 0) {
        if (!is_secure) {
          if (frame.type == NASFS_CMD_PQC_PUBLIC_KEY) {
            OQS_KEM* kem;
            uint8_t* public_key = NULL;
            size_t public_key_len = 0;

            if (nasfs_handshake_unpack_server_selection(
                    frame.payload, frame.payload_len, &negotiated_kex_algorithm,
                    &negotiated_cipher_algorithm, &public_key,
                    &public_key_len) != 0) {
              uv_close((uv_handle_t*)stream, on_close);
              return;
            }

            if (strcmp(negotiated_cipher_algorithm,
                       NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) != 0) {
              free(public_key);
              uv_close((uv_handle_t*)stream, on_close);
              return;
            }

            kem = OQS_KEM_new(negotiated_kex_algorithm);
            if (kem && public_key_len == kem->length_public_key) {
              size_t payload_size =
                  kem->length_ciphertext +
                  crypto_secretstream_xchacha20poly1305_HEADERBYTES;
              uint8_t* payload = malloc(payload_size);
              shared_secret = sodium_malloc(kem->length_shared_secret);
              shared_secret_len = kem->length_shared_secret;
              if (payload && shared_secret &&
                  OQS_KEM_encaps(kem, payload, shared_secret, public_key) ==
                      OQS_SUCCESS &&
                  crypto_secretstream_xchacha20poly1305_init_push(
                      &send_crypto_state, payload + kem->length_ciphertext,
                      shared_secret) == 0) {
                printf("Negotiated KEX %s with control cipher %s.\n",
                       negotiated_kex_algorithm, negotiated_cipher_algorithm);
                printf(
                    "Received public key. Sending ciphertext and stream "
                    "header.\n");
                send_command(stream, NASFS_CMD_PQC_CIPHERTEXT, payload,
                             payload_size, 0);
              } else {
                uv_close((uv_handle_t*)stream, on_close);
              }
              free(payload);
              OQS_KEM_free(kem);
            } else {
              if (kem) {
                OQS_KEM_free(kem);
              }
              uv_close((uv_handle_t*)stream, on_close);
            }
            free(public_key);
          } else if (frame.type == NASFS_CMD_SECURE_READY) {
            if (crypto_secretstream_xchacha20poly1305_init_pull(
                    &recv_crypto_state, frame.payload, shared_secret) != 0) {
              uv_close((uv_handle_t*)stream, on_close);
              return;
            }
            is_secure = 1;
            printf(
                "PQC Handshake successful. Channel is now secure. Sending "
                "AUTH...\n");
            send_auth(stream);
          }
        } else {
          unsigned long long decrypted_len;
          nasfs_frame_t plain_frame = frame;
          unsigned char* decrypted_payload = NULL;

          if (frame.type >= 0x10 && frame.type < 0x20) {
            decrypted_payload = malloc(frame.payload_len);
            if (!decrypted_payload) {
              uv_close((uv_handle_t*)stream, on_close);
              return;
            }
            if (crypto_secretstream_xchacha20poly1305_pull(
                    &recv_crypto_state, decrypted_payload, &decrypted_len, NULL,
                    frame.payload, frame.payload_len, NULL, 0) != 0) {
              free(decrypted_payload);
              uv_close((uv_handle_t*)stream, on_close);
              return;
            }
            plain_frame.payload = decrypted_payload;
            plain_frame.payload_len = decrypted_len;
          }

          switch (plain_frame.type) {
            case NASFS_CMD_AUTH_ACK:
              if (current_op == OP_PUT) {
                size_t fn_len = strlen(remote_filename);
                if (file_encryption_enabled) {
                  /* [1 enc][16 salt][8 size][1 cipher][1 hash][name\0] */
                  size_t payload_len = 1 + crypto_pwhash_SALTBYTES +
                                       sizeof(uint64_t) + 2 + fn_len + 1;
                  uint8_t* req_payload = malloc(payload_len);
                  if (req_payload) {
                    req_payload[0] = 1;
                    randombytes_buf(file_salt, crypto_pwhash_SALTBYTES);

                    if (crypto_engine_derive_key(
                            NASFS_KDF_HKDF_SHA256, (const char*)master_key,
                            file_salt, crypto_pwhash_SALTBYTES, encryption_key,
                            sizeof(encryption_key)) != 0) {
                      fprintf(stderr,
                              "Failed to derive file key using HKDF-SHA256\n");
                      free(req_payload);
                      uv_close((uv_handle_t*)stream, on_close);
                      return;
                    }
                    size_t off = 1;
                    memcpy(req_payload + off, file_salt, crypto_pwhash_SALTBYTES);
                    off += crypto_pwhash_SALTBYTES;
                    memcpy(req_payload + off, &put_plaintext_size,
                           sizeof(uint64_t));
                    off += sizeof(uint64_t);
                    req_payload[off++] = (uint8_t)file_cipher_algo;
                    req_payload[off++] = (uint8_t)file_hash_algo;
                    memcpy(req_payload + off, (const uint8_t*)remote_filename,
                           fn_len + 1);
                    send_command(stream, NASFS_CMD_PUT_REQ, req_payload,
                                 payload_len, 1);
                    free(req_payload);
                  }
                } else {
                  size_t payload_len = 1 + fn_len + 1;
                  uint8_t* req_payload = malloc(payload_len);
                  if (req_payload) {
                    req_payload[0] = 0;
                    memcpy(req_payload + 1, (const uint8_t*)remote_filename,
                           fn_len + 1);
                    send_command(stream, NASFS_CMD_PUT_REQ, req_payload,
                                 payload_len, 1);
                    free(req_payload);
                  }
                }
              } else if (current_op == OP_GET) {
                size_t fn_len = strlen(remote_filename);
                size_t payload_len = 1 + fn_len + 1;
                uint8_t* req_payload = malloc(payload_len);
                if (req_payload) {
                  req_payload[0] = file_encryption_enabled ? 1 : 0;
                  memcpy(req_payload + 1, (const uint8_t*)remote_filename,
                         fn_len + 1);
                  send_command(stream, NASFS_CMD_GET_REQ, req_payload,
                               payload_len, 1);
                  free(req_payload);
                }
              }
              break;
            case NASFS_CMD_PUT_ACK: {
              uv_fs_t open_req;
              int fd = uv_fs_open(loop, &open_req, local_filename, O_RDONLY, 0,
                                  NULL);
              if (fd < 0) {
                fprintf(stderr, "Failed to open local file for PUT: %s\n",
                        uv_strerror(fd));
                client_exit_code = 1;
                uv_fs_req_cleanup(&open_req);
                if (decrypted_payload) free(decrypted_payload);
                uv_close((uv_handle_t*)stream, on_close);
                return;
              }
              local_fd = (uv_file)fd;
              file_offset = 0;
              client_block_seq = 0;
              has_pending_block_meta = 0;
              uv_fs_req_cleanup(&open_req);
              do_put_read_chunk(stream);
              break;
            }
            case NASFS_CMD_GET_ACK: {
              if (file_encryption_enabled) {
                /* GET_ACK payload: [16 salt][8 size][1 cipher][1 hash] */
                size_t expected_ack_len =
                    crypto_pwhash_SALTBYTES + sizeof(uint64_t) + 2;
                if (plain_frame.payload_len < expected_ack_len) {
                  fprintf(stderr,
                          "Failed to download: Server GET_ACK too short.\n");
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }
                memcpy(file_salt, plain_frame.payload, crypto_pwhash_SALTBYTES);
                memcpy(&expected_plaintext_size,
                       plain_frame.payload + crypto_pwhash_SALTBYTES,
                       sizeof(uint64_t));
                file_cipher_algo = (nasfs_cipher_algo_t)plain_frame.payload[
                    crypto_pwhash_SALTBYTES + sizeof(uint64_t)];
                file_hash_algo = (nasfs_hash_algo_t)plain_frame.payload[
                    crypto_pwhash_SALTBYTES + sizeof(uint64_t) + 1];

                if (crypto_engine_derive_key(
                        NASFS_KDF_HKDF_SHA256, (const char*)master_key,
                        file_salt, crypto_pwhash_SALTBYTES, encryption_key,
                        sizeof(encryption_key)) != 0) {
                  fprintf(stderr,
                          "Failed to derive file key from downloaded salt\n");
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }
              }

              uv_fs_t open_req;
              int fd = uv_fs_open(loop, &open_req, local_filename,
                                  O_WRONLY | O_CREAT | O_TRUNC, 0644, NULL);
              if (fd < 0) {
                fprintf(stderr, "Failed to open local file for GET: %s\n",
                        uv_strerror(fd));
                client_exit_code = 1;
                uv_fs_req_cleanup(&open_req);
                if (decrypted_payload) free(decrypted_payload);
                uv_close((uv_handle_t*)stream, on_close);
                return;
              }
              local_fd = (uv_file)fd;
              file_offset = 0;
              client_block_seq = 0;
              has_pending_block_meta = 0;
              uv_fs_req_cleanup(&open_req);
              break;
            }
            case NASFS_CMD_GET_BLOCK_META: {
              if (plain_frame.payload_len < sizeof(nasfs_block_meta_t)) {
                fprintf(stderr, "Received invalid block meta size\n");
                client_exit_code = 1;
                if (decrypted_payload) free(decrypted_payload);
                uv_close((uv_handle_t*)stream, on_close);
                return;
              }
              nasfs_block_meta_t* meta =
                  (nasfs_block_meta_t*)plain_frame.payload;
              expected_block_seq = meta->seq_num;
              expected_block_size = meta->size;
              memcpy(expected_block_hash, meta->hash, 32);
              has_pending_block_meta = 1;
              break;
            }
            case NASFS_CMD_GET_DATA: {
              uv_fs_t write_req;
              uv_buf_t write_buf;
              int rc;

              if (local_fd == -1) {
                if (decrypted_payload) free(decrypted_payload);
                uv_close((uv_handle_t*)stream, on_close);
                return;
              }

              uint8_t* write_data = plain_frame.payload;
              size_t write_len = plain_frame.payload_len;
              uint8_t* decrypted_buf = NULL;

              if (file_encryption_enabled) {
                if (!has_pending_block_meta) {
                  fprintf(stderr,
                          "\nError: Received data block without metadata.\n");
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }
                if (plain_frame.payload_len != expected_block_size) {
                  fprintf(
                      stderr,
                      "\nError: Block size mismatch. Expected %u, got %zu.\n",
                      expected_block_size, plain_frame.payload_len);
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }
                if (client_block_seq != expected_block_seq) {
                  fprintf(stderr,
                          "\nError: Sequence number mismatch. Expected %llu, "
                          "got %llu.\n",
                          (unsigned long long)client_block_seq,
                          (unsigned long long)expected_block_seq);
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }

                uint8_t computed_hash[32] = {0};
                size_t computed_hash_len = 0;
                if (crypto_engine_hash(file_hash_algo, plain_frame.payload,
                                       plain_frame.payload_len, computed_hash,
                                       &computed_hash_len) != 0) {
                  fprintf(stderr, "\nError: Hash computation failed.\n");
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }

                if (sodium_memcmp(computed_hash, expected_block_hash, 32) !=
                    0) {
                  fprintf(stderr,
                          "\nError: Integrity check failed (hash mismatch) on "
                          "block %llu.\n",
                          (unsigned long long)client_block_seq);
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }

                decrypted_buf = malloc(plain_frame.payload_len);
                if (!decrypted_buf) {
                  fprintf(stderr, "\nError: Out of memory for decryption.\n");
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }

                /* Derive per-block key: BLAKE2b(encryption_key||salt||seq) */
                uint8_t block_key[crypto_secretbox_KEYBYTES];
                uint8_t key_input[crypto_secretbox_KEYBYTES +
                                  crypto_pwhash_SALTBYTES +
                                  sizeof(client_block_seq)];
                memcpy(key_input, encryption_key, crypto_secretbox_KEYBYTES);
                memcpy(key_input + crypto_secretbox_KEYBYTES, file_salt,
                       crypto_pwhash_SALTBYTES);
                memcpy(key_input + crypto_secretbox_KEYBYTES +
                           crypto_pwhash_SALTBYTES,
                       &client_block_seq, sizeof(client_block_seq));
                crypto_generichash(block_key, sizeof(block_key), key_input,
                                   sizeof(key_input), NULL, 0);

                size_t plaintext_len = 0;
                if (crypto_engine_decrypt_block(
                        file_cipher_algo, plain_frame.payload,
                        plain_frame.payload_len, block_key, client_block_seq,
                        decrypted_buf, &plaintext_len) != 0) {
                  fprintf(stderr,
                          "\nError: Decryption failed. Wrong key or corrupted "
                          "data on block %llu.\n",
                          (unsigned long long)client_block_seq);
                  free(decrypted_buf);
                  client_exit_code = 1;
                  if (decrypted_payload) free(decrypted_payload);
                  uv_close((uv_handle_t*)stream, on_close);
                  return;
                }
                write_data = decrypted_buf;
                write_len = plaintext_len;

                has_pending_block_meta = 0;
                client_block_seq++;
              }

              write_buf = uv_buf_init((char*)write_data, write_len);
              rc = uv_fs_write(loop, &write_req, local_fd, &write_buf, 1,
                               file_offset, NULL);
              if (decrypted_buf) free(decrypted_buf);

              if (rc < 0) {
                fprintf(stderr, "Failed to write downloaded data: %s\n",
                        uv_strerror(rc));
                client_exit_code = 1;
                uv_fs_req_cleanup(&write_req);
                if (decrypted_payload) free(decrypted_payload);
                uv_close((uv_handle_t*)stream, on_close);
                return;
              }
              file_offset += write_len;
              uv_fs_req_cleanup(&write_req);
              printf("\rDownloaded %llu bytes...",
                     (unsigned long long)file_offset);
              fflush(stdout);
              break;
            }
            case NASFS_CMD_GET_DONE:
              if (file_encryption_enabled && expected_plaintext_size > 0 &&
                  file_offset != expected_plaintext_size) {
                fprintf(stderr,
                        "\nIntegrity error: expected %llu bytes, got %llu "
                        "(file truncated or padded by server).\n",
                        (unsigned long long)expected_plaintext_size,
                        (unsigned long long)file_offset);
                client_exit_code = 1;
                uv_close((uv_handle_t*)stream, on_close);
                break;
              }
              printf("\nDownload complete.\n");
              uv_close((uv_handle_t*)stream, on_close);
              break;
            case NASFS_CMD_ERROR:
              fprintf(stderr, "Server error: %.*s\n",
                      (int)plain_frame.payload_len,
                      (const char*)plain_frame.payload);
              client_exit_code = 1;
              uv_close((uv_handle_t*)stream, on_close);
              break;
            default:
              break;
          }

          if (decrypted_payload) free(decrypted_payload);
        }
        memmove(client_recv_buffer, client_recv_buffer + consumed,
                client_recv_length - consumed);
        client_recv_length -= consumed;
      } else {
        if (consumed < 0) uv_close((uv_handle_t*)stream, on_close);
        break;
      }
    }
  } else if (nread < 0) {
    uv_close((uv_handle_t*)stream, on_close);
  }
}

void on_connect(uv_connect_t* req, int status) {
  if (status < 0) {
    fprintf(stderr, "Connection error: %s\n", uv_strerror(status));
    client_exit_code = 1;
    free(req);
    return;
  }
  printf("Connected to server. Initiating PQC Handshake...\n");
  {
    uint8_t* hello_payload;
    size_t hello_payload_len = 0;

    hello_payload = nasfs_handshake_pack_client_hello(
        client_kex_algorithms, client_cipher_algorithms, &hello_payload_len);
    if (!hello_payload) {
      fprintf(stderr, "Failed to build PQC hello payload\n");
      client_exit_code = 1;
      free(req);
      return;
    }

    send_command(req->handle, NASFS_CMD_PQC_HELLO, hello_payload,
                 hello_payload_len, 0);
    free(hello_payload);
  }
  uv_read_start(req->handle, alloc_buffer, on_read);
  free(req);
}

int main(int argc, char** argv) {
  const char* env_kex_algorithms;
  const char* env_cipher_algorithms;
  const char* env_auth_method;
  const char* env_auth_user;
  const char* env_auth_password;
  const char* env_identity_file;
  const char* env_auth_sig_algorithm;
  const char* env_server_ip;
  const char* env_server_port;

  if (argc >= 2 && strcmp(argv[1], "keygen") == 0) {
    const char* algorithm =
        (argc >= 5) ? argv[4] : NASFS_AUTH_DEFAULT_SIG_ALGORITHM;
    if (argc < 4) {
      fprintf(stderr,
              "Usage:\n  %s keygen <private_key> <authorized_keys> "
              "[signature_algorithm]\n",
              argv[0]);
      return 1;
    }
    return write_keypair_files(argv[2], argv[3], algorithm);
  }

  if (argc < 3) {
    fprintf(stderr,
            "Usage:\n  %s put <local_file> [remote_file]\n  %s get "
            "<remote_file> [local_file]\n  %s keygen <private_key> "
            "<authorized_keys> [signature_algorithm]\n",
            argv[0], argv[0], argv[0]);
    return 1;
  }

  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to initialize libsodium\n");
    return 1;
  }

  env_kex_algorithms = getenv("NASFS_KEX_ALGORITHMS");
  env_cipher_algorithms = getenv("NASFS_CIPHER_ALGORITHMS");
  env_auth_method = getenv("NASFS_AUTH_METHOD");
  env_auth_user = getenv("NASFS_AUTH_USER");
  env_auth_password = getenv("NASFS_AUTH_PASSWORD");
  env_identity_file = getenv("NASFS_IDENTITY_FILE");
  env_auth_sig_algorithm = getenv("NASFS_AUTH_SIG_ALGORITHM");

  if (env_kex_algorithms && env_kex_algorithms[0] != '\0') {
    client_kex_algorithms = env_kex_algorithms;
  }
  if (env_cipher_algorithms && env_cipher_algorithms[0] != '\0') {
    client_cipher_algorithms = env_cipher_algorithms;
  }
  if (env_auth_method && env_auth_method[0] != '\0') {
    client_auth_method = env_auth_method;
  }
  if (env_auth_user && env_auth_user[0] != '\0') {
    client_auth_user = env_auth_user;
  }
  if (env_auth_password && env_auth_password[0] != '\0') {
    client_auth_password = env_auth_password;
  }
  if (env_identity_file && env_identity_file[0] != '\0') {
    client_identity_file = env_identity_file;
  }
  if (env_auth_sig_algorithm && env_auth_sig_algorithm[0] != '\0') {
    client_auth_sig_algorithm = env_auth_sig_algorithm;
  }

  env_server_ip = getenv("NASFS_SERVER_IP");
  env_server_port = getenv("NASFS_SERVER_PORT");

  if (env_server_ip && env_server_ip[0] != '\0') {
    client_server_ip = env_server_ip;
  }
  if (env_server_port && env_server_port[0] != '\0') {
    client_server_port = atoi(env_server_port);
  }

  const char* env_file_cipher = getenv("NASFS_FILE_CIPHER");
  const char* env_file_hash = getenv("NASFS_FILE_HASH");
  const char* env_kdf = getenv("NASFS_KDF");
  file_cipher_algo = parse_cipher_algo(env_file_cipher);
  file_hash_algo = parse_hash_algo(env_file_hash);
  master_kdf_algo = parse_kdf_algo(env_kdf);

  const char* env_encryption_key = getenv("NASFS_ENCRYPTION_KEY");
  if (!env_encryption_key || env_encryption_key[0] == '\0') {
    fprintf(stderr, "\n[SECURITY AUDIT ENFORCEMENT]\n");
    fprintf(stderr, "NASFS is now Secure-by-Default.\n");
    fprintf(stderr, "Plaintext file transmission is strictly forbidden.\n");
    fprintf(stderr,
            "You MUST provide NASFS_ENCRYPTION_KEY environment variable.\n\n");
    return 1;
  }

  file_encryption_enabled = 1;
  raw_encryption_password = strdup(env_encryption_key);

  /*
   * Load or create a per-client random Argon2id salt stored in
   * ~/.nasfs/master.salt.  A fixed salt would allow precomputation attacks
   * against the master key; a random per-client salt prevents this.
   */
  uint8_t master_salt[crypto_pwhash_SALTBYTES];
  {
    const char* home = getenv("HOME");
    char salt_path[512] = {0};
    if (home && home[0] != '\0') {
      snprintf(salt_path, sizeof(salt_path), "%s/.nasfs/master.salt", home);
    }

    int loaded = 0;
    if (salt_path[0] != '\0') {
      FILE* sf = fopen(salt_path, "rb");
      if (sf) {
        if (fread(master_salt, 1, sizeof(master_salt), sf) ==
            sizeof(master_salt)) {
          loaded = 1;
        }
        fclose(sf);
      }

      if (!loaded) {
        randombytes_buf(master_salt, sizeof(master_salt));
        /* Create ~/.nasfs/ if it doesn't exist */
        char dir_path[512] = {0};
        if (home) {
          snprintf(dir_path, sizeof(dir_path), "%s/.nasfs", home);
          mkdir(dir_path, 0700);
        }
        FILE* wf = fopen(salt_path, "wb");
        if (wf) {
          (void)fwrite(master_salt, 1, sizeof(master_salt), wf);
          fclose(wf);
          chmod(salt_path, S_IRUSR | S_IWUSR);
        }
      }
    } else {
      /* Fallback: derive from env if no HOME (CI / containers) */
      memset(master_salt, 0x44, sizeof(master_salt));
    }
  }

  if (crypto_engine_derive_key(master_kdf_algo, raw_encryption_password,
                               master_salt, crypto_pwhash_SALTBYTES, master_key,
                               sizeof(master_key)) != 0) {
    fprintf(stderr, "Failed to derive master key\n");
    return 1;
  }

  if (env_auth_password && env_auth_password[0] != '\0') {
    client_auth_password = strdup(env_auth_password);
  }

  if (!auth_method_requires_password(client_auth_method) &&
      !auth_method_requires_publickey(client_auth_method)) {
    fprintf(stderr, "Invalid NASFS_AUTH_METHOD: %s\n", client_auth_method);
    return 1;
  }

  if (strcmp(argv[1], "put") == 0) {
    current_op = OP_PUT;
    local_filename = argv[2];
    remote_filename = (argc >= 4) ? argv[3] : get_basename(local_filename);
    struct stat put_st;
    if (stat(local_filename, &put_st) == 0) {
      put_plaintext_size = (uint64_t)put_st.st_size;
    }
  } else if (strcmp(argv[1], "get") == 0) {
    current_op = OP_GET;
    remote_filename = argv[2];
    local_filename = (argc >= 4) ? argv[3] : get_basename(remote_filename);
  } else {
    fprintf(stderr, "Invalid operation. Use 'put' or 'get'.\n");
    return 1;
  }

  loop = uv_default_loop();
  uv_tcp_t* socket = malloc(sizeof(uv_tcp_t));
  uv_tcp_init(loop, socket);
  struct sockaddr_in dest;
  uv_ip4_addr(client_server_ip, client_server_port, &dest);
  uv_connect_t* connect_req = malloc(sizeof(uv_connect_t));
  uv_tcp_connect(connect_req, socket, (const struct sockaddr*)&dest,
                 on_connect);
  printf("Connecting to %s:%d...\n", client_server_ip, client_server_port);

  int result = uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_close(loop);
  return client_exit_code != 0 ? client_exit_code : result;
}
