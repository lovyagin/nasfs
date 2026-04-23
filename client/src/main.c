/**
 * @file main.c
 * @brief Main entry point for the NASFS client CLI application.
 *
 * Implements an asynchronous libuv-based client that supports
 * PUT (upload) and GET (download) file operations over the NASFS protocol.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <uv.h>
#include "protocol.h"

/**
 * @brief Buffer size for file I/O operations.
 */
#define CHUNK_SIZE (64 * 1024)

/**
 * @brief Initial size for the network receive buffer.
 */
#define CLIENT_INITIAL_BUFFER 16384

/**
 * @enum client_op_t
 * @brief Operational modes for the client.
 */
typedef enum {
    OP_NONE,
    OP_PUT,
    OP_GET
} client_op_t;

/**
 * @struct nasfs_write_ctx_t
 * @brief Context for asynchronous socket writes.
 */
typedef struct {
    uv_write_t req;
    uv_buf_t buf;
    nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

/**
 * @struct nasfs_fs_ctx_t
 * @brief Context for asynchronous filesystem operations.
 */
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

/* Receive Buffer State */
uint8_t *client_recv_buffer = NULL;
size_t client_recv_length = 0;
size_t client_recv_capacity = 0;

/* Server connection info */
#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

/* Forward Declarations */
void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len);
void do_put_read_chunk(uv_stream_t *stream);

/**
 * @brief Extracts the filename from a file path.
 *
 * @param path The full path string.
 * @return Pointer to the character after the last slash.
 */
static const char *get_basename(const char *path) {
    const char *base = strrchr(path, '/');
    if (base) return base + 1;
    base = strrchr(path, '\\');
    if (base) return base + 1;
    return path;
}

/**
 * @brief Allocates buffer space for incoming data from the server.
 */
void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    if (client_recv_capacity - client_recv_length < suggested_size) {
        size_t new_cap = client_recv_capacity == 0 ? CLIENT_INITIAL_BUFFER : client_recv_capacity * 2;
        while (new_cap - client_recv_length < suggested_size) {
            new_cap *= 2;
        }
        uint8_t *new_buf = realloc(client_recv_buffer, new_cap);
        if (!new_buf) {
            fprintf(stderr, "Fatal: Out of memory during receive buffer allocation\n");
            exit(1);
        }
        client_recv_buffer = new_buf;
        client_recv_capacity = new_cap;
    }
    buf->base = (char *)(client_recv_buffer + client_recv_length);
    buf->len = client_recv_capacity - client_recv_length;
}

/**
 * @brief Handles closing of handles and cleanup of resources.
 */
void on_close(uv_handle_t *handle) {
    if (client_recv_buffer) {
        free(client_recv_buffer);
        client_recv_buffer = NULL;
    }
    if (local_fd != -1) {
        uv_fs_t close_req;
        uv_fs_close(loop, &close_req, local_fd, NULL);
        uv_fs_req_cleanup(&close_req);
        local_fd = -1;
    }
    free(handle);
    printf("\nConnection closed.\n");
}

/**
 * @brief Callback for completion of socket write operations.
 */
void on_write(uv_write_t *req, int status) {
    nasfs_write_ctx_t *ctx = (nasfs_write_ctx_t *)req;
    if (status) {
        fprintf(stderr, "Write error: %s\n", uv_strerror(status));
    }

    nasfs_cmd_type_t last_cmd = ctx->type;
    uv_stream_t *stream = req->handle;

    if (ctx->buf.base) {
        free(ctx->buf.base);
    }
    free(ctx);

    /* Chain next chunk for PUT only if we just sent data */
    if (current_op == OP_PUT && local_fd != -1 && status == 0) {
        if (last_cmd == NASFS_CMD_PUT_DATA) {
            do_put_read_chunk(stream);
        } else if (last_cmd == NASFS_CMD_PUT_DONE) {
            uv_close((uv_handle_t *)stream, on_close);
        }
    }
}

/**
 * @brief Serializes and sends a protocol command frame.
 */
void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len) {
    size_t frame_size = 0;
    uint8_t *frame_data = protocol_pack_frame(cmd, payload, payload_len, &frame_size);

    if (!frame_data) {
        return;
    }

    nasfs_write_ctx_t *ctx = malloc(sizeof(nasfs_write_ctx_t));
    if (!ctx) {
        free(frame_data);
        return;
    }

    ctx->buf = uv_buf_init((char *)frame_data, frame_size);
    ctx->type = cmd;

    int r = uv_write(&ctx->req, stream, &ctx->buf, 1, on_write);
    if (r < 0) {
        fprintf(stderr, "uv_write failed: %s\n", uv_strerror(r));
        free(frame_data);
        free(ctx);
    }
}

/**
 * @brief Handles completion of async reading from the local file (for PUT).
 */
void on_local_read(uv_fs_t *req) {
    nasfs_fs_ctx_t *ctx = (nasfs_fs_ctx_t *)req->data;
    uv_stream_t *stream = ctx->stream;

    if (req->result < 0) {
        fprintf(stderr, "\nRead error from local file: %s\n", uv_strerror((int)req->result));
        uv_close((uv_handle_t *)stream, on_close);
    } else if (req->result == 0) {
        /* EOF reached */
        printf("\nFinished reading local file. Sending PUT_DONE.\n");
        send_command(stream, NASFS_CMD_PUT_DONE, NULL, 0);
    } else {
        /* Send data chunk */
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

/**
 * @brief Initiates an asynchronous read of the next chunk from the local file.
 */
void do_put_read_chunk(uv_stream_t *stream) {
    nasfs_fs_ctx_t *ctx = malloc(sizeof(nasfs_fs_ctx_t));
    if (!ctx) return;

    ctx->buf.base = malloc(CHUNK_SIZE);
    ctx->buf.len = CHUNK_SIZE;
    ctx->stream = stream;
    ctx->req.data = ctx;

    int r = uv_fs_read(loop, &ctx->req, local_fd, &ctx->buf, 1, file_offset, on_local_read);
    if (r < 0) {
        fprintf(stderr, "uv_fs_read failed: %s\n", uv_strerror(r));
        free(ctx->buf.base);
        free(ctx);
    }
}

/**
 * @brief Handles data stream from the server.
 */
void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)buf; 

    if (nread > 0) {
        client_recv_length += nread;

        while (client_recv_length > 0) {
            nasfs_frame_t frame;
            int consumed = protocol_parse_frame(client_recv_buffer, client_recv_length, &frame);

            if (consumed > 0) {
                switch (frame.type) {
                    case NASFS_CMD_AUTH_ACK:
                        if (current_op == OP_PUT) {
                            printf("Sending PUT_REQ for '%s'...\n", remote_filename);
                            send_command(stream, NASFS_CMD_PUT_REQ, (const uint8_t *)remote_filename, strlen(remote_filename));
                        } else if (current_op == OP_GET) {
                            printf("Sending GET_REQ for '%s'...\n", remote_filename);
                            send_command(stream, NASFS_CMD_GET_REQ, (const uint8_t *)remote_filename, strlen(remote_filename));
                        }
                        break;

                    case NASFS_CMD_PUT_ACK:
                        printf("Server: PUT_ACK received. Starting upload...\n");
                        {
                            uv_fs_t open_req;
                            local_fd = uv_fs_open(loop, &open_req, local_filename, O_RDONLY, 0, NULL);
                            if (local_fd < 0) {
                                fprintf(stderr, "Failed to open local file '%s': %s\n", local_filename, uv_strerror((int)local_fd));
                                uv_close((uv_handle_t *)stream, on_close);
                            } else {
                                file_offset = 0;
                                do_put_read_chunk(stream);
                            }
                            uv_fs_req_cleanup(&open_req);
                        }
                        break;

                    case NASFS_CMD_GET_ACK:
                        printf("Server: GET_ACK received. Starting download...\n");
                        {
                            uv_fs_t open_req;
                            local_fd = uv_fs_open(loop, &open_req, local_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644, NULL);
                            if (local_fd < 0) {
                                fprintf(stderr, "Failed to open local file '%s' for writing: %s\n", local_filename, uv_strerror((int)local_fd));
                                uv_close((uv_handle_t *)stream, on_close);
                            } else {
                                file_offset = 0;
                            }
                            uv_fs_req_cleanup(&open_req);
                        }
                        break;

                    case NASFS_CMD_GET_DATA:
                        if (local_fd != -1) {
                            uv_fs_t write_req;
                            uv_buf_t write_buf = uv_buf_init((char *)frame.payload, frame.payload_len);
                            int res = uv_fs_write(loop, &write_req, local_fd, &write_buf, 1, file_offset, NULL);
                            if (res < 0) {
                                fprintf(stderr, "\nWrite error to local file: %s\n", uv_strerror(res));
                            } else {
                                file_offset += frame.payload_len;
                                printf("\rDownloaded %llu bytes...", (unsigned long long)file_offset);
                                fflush(stdout);
                            }
                            uv_fs_req_cleanup(&write_req);
                        }
                        break;

                    case NASFS_CMD_GET_DONE:
                        printf("\nServer: GET_DONE received. Download complete.\n");
                        uv_close((uv_handle_t *)stream, on_close);
                        break;

                    case NASFS_CMD_ERROR:
                        fprintf(stderr, "\nServer Error: %.*s\n", (int)frame.payload_len, (char *)frame.payload);
                        uv_close((uv_handle_t *)stream, on_close);
                        break;

                    default:
                        break;
                }

                size_t remaining = client_recv_length - consumed;
                if (remaining > 0) {
                    memmove(client_recv_buffer, client_recv_buffer + consumed, remaining);
                }
                client_recv_length = remaining;

            } else if (consumed == 0) {
                break; /* Need more data */
            } else {
                fprintf(stderr, "Protocol framing error. Closing connection.\n");
                uv_close((uv_handle_t *)stream, on_close);
                break;
            }
        }
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "\nRead error from socket: %s\n", uv_err_name((int)nread));
        }
        uv_close((uv_handle_t *)stream, on_close);
    }
}

/**
 * @brief Initiates connection and starts authentication.
 */
void on_connect(uv_connect_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "Connection error: %s\n", uv_strerror(status));
        uv_close((uv_handle_t *)req->handle, on_close);
        free(req);
        return;
    }

    printf("Connected to server.\n");
    uv_stream_t *stream = req->handle;
    uv_read_start(stream, alloc_buffer, on_read);

    send_command(stream, NASFS_CMD_AUTH, (const uint8_t *)"dummy_token_123", 15);
    free(req);
}

/**
 * @brief Entry point.
 */
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
        fprintf(stderr, "Invalid operation '%s'. Use 'put' or 'get'.\n", argv[1]);
        return 1;
    }

    loop = uv_default_loop();

    uv_tcp_t *socket = malloc(sizeof(uv_tcp_t));
    if (!socket) return 1;
    uv_tcp_init(loop, socket);

    struct sockaddr_in dest;
    uv_ip4_addr(SERVER_IP, SERVER_PORT, &dest);

    uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
    if (!connect_req) return 1;
    uv_tcp_connect(connect_req, socket, (const struct sockaddr *)&dest, on_connect);

    printf("Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);

    int result = uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    
    return result;
}