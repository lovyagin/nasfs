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
#include "handshake.h"
#include "protocol.h"

#define IO_CHUNK_SIZE (64 * 1024)
#define CLIENT_INITIAL_BUFFER 16384
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

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

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
  char public_hex[32768];
  char secret_hex[32768];

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
      !fgets(public_hex, sizeof(public_hex), file) ||
      !fgets(secret_hex, sizeof(secret_hex), file)) {
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

  auth.method = (char*)client_auth_method;
  auth.username = (char*)client_auth_user;
  if (auth_method_requires_password(client_auth_method)) {
    auth.password = (char*)client_auth_password;
  }

  if (auth_method_requires_publickey(client_auth_method) &&
      build_publickey_signature(&sig_algorithm, &auth.public_key,
                                &auth.public_key_len, &auth.signature,
                                &auth.signature_len) != 0) {
    client_exit_code = 1;
    uv_close((uv_handle_t*)stream, on_close);
    return;
  }
  auth.sig_algorithm = sig_algorithm;

  payload = nasfs_auth_pack(&auth, &payload_len);
  free(sig_algorithm);
  free(auth.public_key);
  free(auth.signature);
  if (!payload) {
    client_exit_code = 1;
    uv_close((uv_handle_t*)stream, on_close);
    return;
  }

  send_command(stream, NASFS_CMD_AUTH, payload, payload_len, 1);
  free(payload);
}

void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  (void)handle;
  if (client_recv_capacity - client_recv_length < suggested_size) {
    size_t new_cap = client_recv_capacity == 0 ? CLIENT_INITIAL_BUFFER
                                               : client_recv_capacity * 2;
    while (new_cap - client_recv_length < suggested_size) new_cap *= 2;
    uint8_t* new_buf = realloc(client_recv_buffer, new_cap);
    if (!new_buf) exit(1);
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
    send_command(stream, NASFS_CMD_PUT_DATA, (uint8_t*)ctx->buf.base,
                 bytes_read, 0);
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
                send_command(stream, NASFS_CMD_PUT_REQ,
                             (const uint8_t*)remote_filename,
                             strlen(remote_filename), 1);
              } else if (current_op == OP_GET) {
                send_command(stream, NASFS_CMD_GET_REQ,
                             (const uint8_t*)remote_filename,
                             strlen(remote_filename), 1);
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
              uv_fs_req_cleanup(&open_req);
              do_put_read_chunk(stream);
              break;
            }
            case NASFS_CMD_GET_ACK: {
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
              uv_fs_req_cleanup(&open_req);
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

              write_buf = uv_buf_init((char*)plain_frame.payload,
                                      plain_frame.payload_len);
              rc = uv_fs_write(loop, &write_req, local_fd, &write_buf, 1,
                               file_offset, NULL);
              if (rc < 0) {
                fprintf(stderr, "Failed to write downloaded data: %s\n",
                        uv_strerror(rc));
                client_exit_code = 1;
                uv_fs_req_cleanup(&write_req);
                if (decrypted_payload) free(decrypted_payload);
                uv_close((uv_handle_t*)stream, on_close);
                return;
              }
              file_offset += plain_frame.payload_len;
              uv_fs_req_cleanup(&write_req);
              printf("\rDownloaded %llu bytes...",
                     (unsigned long long)file_offset);
              fflush(stdout);
              break;
            }
            case NASFS_CMD_GET_DONE:
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

  if (!auth_method_requires_password(client_auth_method) &&
      !auth_method_requires_publickey(client_auth_method)) {
    fprintf(stderr, "Invalid NASFS_AUTH_METHOD: %s\n", client_auth_method);
    return 1;
  }

  if (strcmp(argv[1], "put") == 0) {
    current_op = OP_PUT;
    local_filename = argv[2];
    remote_filename = (argc >= 4) ? argv[3] : get_basename(local_filename);
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
  uv_ip4_addr(SERVER_IP, SERVER_PORT, &dest);
  uv_connect_t* connect_req = malloc(sizeof(uv_connect_t));
  uv_tcp_connect(connect_req, socket, (const struct sockaddr*)&dest,
                 on_connect);
  printf("Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);

  int result = uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_close(loop);
  return client_exit_code != 0 ? client_exit_code : result;
}
