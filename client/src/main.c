/**
 * @file main.c
 * @brief Main entry point for the NASFS client CLI with PQC handshake.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * Implements an asynchronous libuv-based client that supports
 * PQC key exchange, and subsequent PUT/GET file operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <uv.h>
#include <oqs/oqs.h>
#include <sodium.h>

#include "protocol.h"

#define IO_CHUNK_SIZE (64 * 1024)
#define CLIENT_INITIAL_BUFFER 16384
#define KEM_ALGORITHM OQS_KEM_alg_kyber_512

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

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

/* Forward Declarations */
void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len);
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
    if (shared_secret) free(shared_secret);
    if (local_fd != -1) uv_fs_close(loop, &(uv_fs_t){}, local_fd, NULL);
    free(handle);
    printf("\nConnection closed.\n");
}

void on_write(uv_write_t *req, int status) {
    nasfs_write_ctx_t *ctx = (nasfs_write_ctx_t *)req;
    if (status) fprintf(stderr, "Write error: %s\n", uv_strerror(status));

    if (ctx->buf.base) free(ctx->buf.base);
    free(ctx);

    if (current_op == OP_PUT && local_fd != -1 && status == 0 && ctx->type == NASFS_CMD_PUT_DATA) {
        do_put_read_chunk(req->handle);
    }
}

void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len) {
    size_t frame_size;
    uint8_t *frame_data = protocol_pack_frame(cmd, payload, payload_len, &frame_size);
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
        send_command(stream, NASFS_CMD_PUT_DONE, NULL, 0);
    } else {
        size_t bytes_read = req->result;
        file_offset += bytes_read;
        send_command(stream, NASFS_CMD_PUT_DATA, (uint8_t *)ctx->buf.base, bytes_read);
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
                        OQS_KEM *kem = OQS_KEM_new(KEM_ALGORITHM);
                        if (kem) {
                            uint8_t *ciphertext = malloc(kem->length_ciphertext);
                            shared_secret = malloc(kem->length_shared_secret);
                            if (ciphertext && shared_secret) {
                                OQS_KEM_encaps(kem, ciphertext, shared_secret, frame.payload);
                                printf("Received Public Key. Sending Ciphertext.\n");
                                send_command(stream, NASFS_CMD_PQC_CIPHERTEXT, ciphertext, kem->length_ciphertext);
                                is_secure = 1;
                                printf("PQC Handshake successful. Channel is now secure. Sending AUTH...\n");
                                send_command(stream, NASFS_CMD_AUTH, (const uint8_t *)"user:pass", 9);
                            }
                            free(ciphertext);
                            OQS_KEM_free(kem);
                        }
                    }
                } else {
                    /* Handle encrypted commands here */
                    switch (frame.type) {
                        case NASFS_CMD_AUTH_ACK:
                            if (current_op == OP_PUT) {
                                printf("Authenticated. Sending PUT_REQ for '%s'...\n", remote_filename);
                                send_command(stream, NASFS_CMD_PUT_REQ, (const uint8_t *)remote_filename, strlen(remote_filename));
                            } else if (current_op == OP_GET) {
                                printf("Authenticated. Sending GET_REQ for '%s'...\n", remote_filename);
                                send_command(stream, NASFS_CMD_GET_REQ, (const uint8_t *)remote_filename, strlen(remote_filename));
                            }
                            break;
                        /* ... other encrypted commands ... */
                    }
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
    const char* kem_name = KEM_ALGORITHM;
    send_command(req->handle, NASFS_CMD_PQC_HELLO, (const uint8_t*)kem_name, strlen(kem_name));
    uv_read_start(req->handle, alloc_buffer, on_read);
    free(req);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n  %s put <local_file> [remote_file]\n  %s get <remote_file> [local_file]\n", argv[0], argv[0]);
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