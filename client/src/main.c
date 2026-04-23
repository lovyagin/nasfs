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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <uv.h>
#include <oqs/oqs.h>
#include <sodium.h>

#include "handshake.h"
#include "protocol.h"

#define IO_CHUNK_SIZE (64 * 1024)
#define CLIENT_INITIAL_BUFFER 16384
#define DEFAULT_KEX_ALGORITHMS "ML-KEM-512,Kyber512,ML-KEM-768,Kyber768"
#define DEFAULT_CIPHER_ALGORITHMS NASFS_CONTROL_CIPHER_XCHACHA20POLY1305

typedef enum {
    OP_NONE,
    OP_PUT,
    OP_GET
} client_op_t;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
    nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

typedef struct {
    uv_fs_t req;
    uv_buf_t buf;
    uv_stream_t *stream;
} nasfs_fs_ctx_t;

/* Global State */
uv_loop_t *loop;
client_op_t current_op = OP_NONE;
const char *local_filename = NULL;
const char *remote_filename = NULL;
uv_file local_fd = -1;
uint64_t file_offset = 0;

uint8_t *client_recv_buffer = NULL;
size_t client_recv_length = 0;
size_t client_recv_capacity = 0;

uint8_t *shared_secret = NULL;
int is_secure = 0;
crypto_secretstream_xchacha20poly1305_state send_crypto_state;
crypto_secretstream_xchacha20poly1305_state recv_crypto_state;
const char *client_kex_algorithms = DEFAULT_KEX_ALGORITHMS;
const char *client_cipher_algorithms = DEFAULT_CIPHER_ALGORITHMS;
char *negotiated_kex_algorithm = NULL;
char *negotiated_cipher_algorithm = NULL;

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

/* Forward Declarations */
void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len, int encrypt);
void do_put_read_chunk(uv_stream_t *stream);

static const char *get_basename(const char *path) {
    const char *base = strrchr(path, '/');
    if (!base) base = strrchr(path, '\\');
    return base ? base + 1 : path;
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    if (client_recv_capacity - client_recv_length < suggested_size) {
        size_t new_cap = client_recv_capacity == 0 ? CLIENT_INITIAL_BUFFER : client_recv_capacity * 2;
        while (new_cap - client_recv_length < suggested_size) new_cap *= 2;
        uint8_t *new_buf = realloc(client_recv_buffer, new_cap);
        if (!new_buf) exit(1);
        client_recv_buffer = new_buf;
        client_recv_capacity = new_cap;
    }
    buf->base = (char *)(client_recv_buffer + client_recv_length);
    buf->len = client_recv_capacity - client_recv_length;
}

void on_close(uv_handle_t *handle) {
    if (client_recv_buffer) free(client_recv_buffer);
    if (shared_secret) sodium_free(shared_secret);
    if (negotiated_kex_algorithm) free(negotiated_kex_algorithm);
    if (negotiated_cipher_algorithm) free(negotiated_cipher_algorithm);
    if (local_fd != -1) uv_fs_close(loop, &(uv_fs_t){}, local_fd, NULL);
    free(handle);
    printf("\nConnection closed.\n");
}

void on_write(uv_write_t *req, int status) {
    nasfs_write_ctx_t *ctx = (nasfs_write_ctx_t *)req;
    uv_stream_t *stream = req->handle;
    if (status) fprintf(stderr, "Write error: %s\n", uv_strerror(status));
    
    if (ctx->buf.base) free(ctx->buf.base);
    if (current_op == OP_PUT && status == 0) {
        if (local_fd != -1 && ctx->type == NASFS_CMD_PUT_DATA) {
            free(ctx);
            do_put_read_chunk(stream);
            return;
        }
        if (ctx->type == NASFS_CMD_PUT_DONE) {
            free(ctx);
            uv_close((uv_handle_t *)stream, on_close);
            return;
        }
    }

    free(ctx);
}

void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len, int encrypt) {
    uint8_t *payload_to_pack = (uint8_t *)payload;
    size_t payload_to_pack_len = payload_len;
    uint8_t *encrypted_payload = NULL;

    if (encrypt && is_secure) {
        payload_to_pack_len = payload_len + crypto_secretstream_xchacha20poly1305_ABYTES;
        encrypted_payload = malloc(payload_to_pack_len);
        if (!encrypted_payload) return;

        crypto_secretstream_xchacha20poly1305_push(&send_crypto_state, encrypted_payload, NULL, payload, payload_len, NULL, 0, 0);
        payload_to_pack = encrypted_payload;
    }

    size_t frame_size;
    uint8_t *frame_data = protocol_pack_frame(cmd, payload_to_pack, payload_to_pack_len, &frame_size);
    if (encrypted_payload) free(encrypted_payload);
    if (!frame_data) return;

    nasfs_write_ctx_t *ctx = malloc(sizeof(nasfs_write_ctx_t));
    if (!ctx) { free(frame_data); return; }

    ctx->buf = uv_buf_init((char *)frame_data, frame_size);
    ctx->type = cmd;
    if (uv_write(&ctx->req, stream, &ctx->buf, 1, on_write) < 0) {
        free(frame_data);
        free(ctx);
    }
}

void on_local_read(uv_fs_t *req) {
    nasfs_fs_ctx_t *ctx = (nasfs_fs_ctx_t *)req->data;
    uv_stream_t *stream = ctx->stream;

    if (req->result < 0) {
        fprintf(stderr, "\nRead error: %s\n", uv_strerror((int)req->result));
        uv_close((uv_handle_t *)stream, on_close);
    } else if (req->result == 0) {
        printf("\nFinished reading local file. Sending PUT_DONE.\n");
        send_command(stream, NASFS_CMD_PUT_DONE, NULL, 0, 1);
    } else {
        size_t bytes_read = req->result;
        file_offset += bytes_read;
        send_command(stream, NASFS_CMD_PUT_DATA, (uint8_t *)ctx->buf.base, bytes_read, 0);
        printf("\rUploaded %llu bytes...", (unsigned long long)file_offset);
        fflush(stdout);
    }
    if (ctx->buf.base) free(ctx->buf.base);
    uv_fs_req_cleanup(req);
    free(ctx);
}

void do_put_read_chunk(uv_stream_t *stream) {
    nasfs_fs_ctx_t *ctx = malloc(sizeof(nasfs_fs_ctx_t));
    if (!ctx) return;
    ctx->buf = uv_buf_init(malloc(IO_CHUNK_SIZE), IO_CHUNK_SIZE);
    ctx->stream = stream;
    ctx->req.data = ctx;
    if (uv_fs_read(loop, &ctx->req, local_fd, &ctx->buf, 1, file_offset, on_local_read) < 0) {
        free(ctx->buf.base);
        free(ctx);
    }
}

void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)buf; 

    if (nread > 0) {
        client_recv_length += nread;
        while (client_recv_length > 0) {
            nasfs_frame_t frame;
            int consumed = protocol_parse_frame(client_recv_buffer, client_recv_length, &frame);
            if (consumed > 0) {
                if (!is_secure) {
                    if (frame.type == NASFS_CMD_PQC_PUBLIC_KEY) {
                        OQS_KEM *kem;
                        uint8_t *public_key = NULL;
                        size_t public_key_len = 0;

                        if (nasfs_handshake_unpack_server_selection(frame.payload,
                                                                    frame.payload_len,
                                                                    &negotiated_kex_algorithm,
                                                                    &negotiated_cipher_algorithm,
                                                                    &public_key,
                                                                    &public_key_len) != 0) {
                            uv_close((uv_handle_t *)stream, on_close);
                            return;
                        }

                        if (strcmp(negotiated_cipher_algorithm, NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) != 0) {
                            free(public_key);
                            uv_close((uv_handle_t *)stream, on_close);
                            return;
                        }

                        kem = OQS_KEM_new(negotiated_kex_algorithm);
                        if (kem && public_key_len == kem->length_public_key) {
                            size_t payload_size = kem->length_ciphertext + crypto_secretstream_xchacha20poly1305_HEADERBYTES;
                            uint8_t *payload = malloc(payload_size);
                            shared_secret = sodium_malloc(kem->length_shared_secret);
                            if (payload &&
                                shared_secret &&
                                OQS_KEM_encaps(kem, payload, shared_secret, public_key) == OQS_SUCCESS &&
                                crypto_secretstream_xchacha20poly1305_init_push(&send_crypto_state,
                                                                                 payload + kem->length_ciphertext,
                                                                                 shared_secret) == 0) {
                                printf("Negotiated KEX %s with control cipher %s.\n",
                                       negotiated_kex_algorithm,
                                       negotiated_cipher_algorithm);
                                printf("Received public key. Sending ciphertext and stream header.\n");
                                send_command(stream, NASFS_CMD_PQC_CIPHERTEXT, payload, payload_size, 0);
                            } else {
                                uv_close((uv_handle_t *)stream, on_close);
                            }
                            free(payload);
                            OQS_KEM_free(kem);
                        } else {
                            if (kem) {
                                OQS_KEM_free(kem);
                            }
                            uv_close((uv_handle_t *)stream, on_close);
                        }
                        free(public_key);
                    } else if (frame.type == NASFS_CMD_SECURE_READY) {
                        if (crypto_secretstream_xchacha20poly1305_init_pull(&recv_crypto_state, frame.payload, shared_secret) != 0) {
                            uv_close((uv_handle_t *)stream, on_close);
                            return;
                        }
                        is_secure = 1;
                        printf("PQC Handshake successful. Channel is now secure. Sending AUTH...\n");
                        send_command(stream, NASFS_CMD_AUTH, (const uint8_t *)"user:pass", 9, 1);
                    }
                } else {
                    unsigned long long decrypted_len;
                    nasfs_frame_t plain_frame = frame;
                    unsigned char *decrypted_payload = NULL;

                    if (frame.type >= 0x10 && frame.type < 0x20) {
                        decrypted_payload = malloc(frame.payload_len);
                        if (!decrypted_payload) {
                            uv_close((uv_handle_t *)stream, on_close);
                            return;
                        }
                        if (crypto_secretstream_xchacha20poly1305_pull(&recv_crypto_state, decrypted_payload, &decrypted_len, NULL, frame.payload, frame.payload_len, NULL, 0) != 0) {
                            free(decrypted_payload);
                            uv_close((uv_handle_t *)stream, on_close);
                            return;
                        }
                        plain_frame.payload = decrypted_payload;
                        plain_frame.payload_len = decrypted_len;
                    }

                    switch (plain_frame.type) {
                        case NASFS_CMD_AUTH_ACK:
                            if (current_op == OP_PUT) {
                                send_command(stream, NASFS_CMD_PUT_REQ, (const uint8_t *)remote_filename, strlen(remote_filename), 1);
                            } else if (current_op == OP_GET) {
                                send_command(stream, NASFS_CMD_GET_REQ, (const uint8_t *)remote_filename, strlen(remote_filename), 1);
                            }
                            break;
                        case NASFS_CMD_PUT_ACK: {
                            uv_fs_t open_req;
                            int fd = uv_fs_open(loop, &open_req, local_filename, O_RDONLY, 0, NULL);
                            if (fd < 0) {
                                fprintf(stderr, "Failed to open local file for PUT: %s\n", uv_strerror(fd));
                                uv_fs_req_cleanup(&open_req);
                                if (decrypted_payload) free(decrypted_payload);
                                uv_close((uv_handle_t *)stream, on_close);
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
                            int fd = uv_fs_open(loop, &open_req, local_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644, NULL);
                            if (fd < 0) {
                                fprintf(stderr, "Failed to open local file for GET: %s\n", uv_strerror(fd));
                                uv_fs_req_cleanup(&open_req);
                                if (decrypted_payload) free(decrypted_payload);
                                uv_close((uv_handle_t *)stream, on_close);
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
                                uv_close((uv_handle_t *)stream, on_close);
                                return;
                            }

                            write_buf = uv_buf_init((char *)plain_frame.payload, plain_frame.payload_len);
                            rc = uv_fs_write(loop, &write_req, local_fd, &write_buf, 1, file_offset, NULL);
                            if (rc < 0) {
                                fprintf(stderr, "Failed to write downloaded data: %s\n", uv_strerror(rc));
                                uv_fs_req_cleanup(&write_req);
                                if (decrypted_payload) free(decrypted_payload);
                                uv_close((uv_handle_t *)stream, on_close);
                                return;
                            }
                            file_offset += plain_frame.payload_len;
                            uv_fs_req_cleanup(&write_req);
                            printf("\rDownloaded %llu bytes...", (unsigned long long)file_offset);
                            fflush(stdout);
                            break;
                        }
                        case NASFS_CMD_GET_DONE:
                            printf("\nDownload complete.\n");
                            uv_close((uv_handle_t *)stream, on_close);
                            break;
                        case NASFS_CMD_ERROR:
                            fprintf(stderr, "Server error: %.*s\n", (int)plain_frame.payload_len, (const char *)plain_frame.payload);
                            uv_close((uv_handle_t *)stream, on_close);
                            break;
                        default:
                            break;
                    }

                    if (decrypted_payload) free(decrypted_payload);
                }
                memmove(client_recv_buffer, client_recv_buffer + consumed, client_recv_length - consumed);
                client_recv_length -= consumed;
            } else {
                if (consumed < 0) uv_close((uv_handle_t *)stream, on_close);
                break;
            }
        }
    } else if (nread < 0) {
        uv_close((uv_handle_t *)stream, on_close);
    }
}

void on_connect(uv_connect_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "Connection error: %s\n", uv_strerror(status));
        free(req);
        return;
    }
    printf("Connected to server. Initiating PQC Handshake...\n");
    {
        uint8_t *hello_payload;
        size_t hello_payload_len = 0;

        hello_payload = nasfs_handshake_pack_client_hello(client_kex_algorithms,
                                                          client_cipher_algorithms,
                                                          &hello_payload_len);
        if (!hello_payload) {
            fprintf(stderr, "Failed to build PQC hello payload\n");
            free(req);
            return;
        }

        send_command(req->handle, NASFS_CMD_PQC_HELLO, hello_payload, hello_payload_len, 0);
        free(hello_payload);
    }
    uv_read_start(req->handle, alloc_buffer, on_read);
    free(req);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n  %s put <local_file> [remote_file]\n  %s get <remote_file> [local_file]\n", argv[0], argv[0]);
        return 1;
    }
    
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    if (getenv("NASFS_KEX_ALGORITHMS") && getenv("NASFS_KEX_ALGORITHMS")[0] != '\0') {
        client_kex_algorithms = getenv("NASFS_KEX_ALGORITHMS");
    }
    if (getenv("NASFS_CIPHER_ALGORITHMS") && getenv("NASFS_CIPHER_ALGORITHMS")[0] != '\0') {
        client_cipher_algorithms = getenv("NASFS_CIPHER_ALGORITHMS");
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
    uv_tcp_t *socket = malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, socket);
    struct sockaddr_in dest;
    uv_ip4_addr(SERVER_IP, SERVER_PORT, &dest);
    uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
    uv_tcp_connect(connect_req, socket, (const struct sockaddr *)&dest, on_connect);
    printf("Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);

    int result = uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    return result;
}
