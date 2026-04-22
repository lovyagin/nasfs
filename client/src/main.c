/**
 * @file main.c
 * @brief Main entry point for the NASFS client CLI application.
 *
 * Implements an asynchronous libuv-based client that supports
 * PUT (upload) and GET (download) file operations over the NASFS protocol.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <uv.h>
#include "protocol.h"

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"
#define CHUNK_SIZE (64 * 1024)
#define CLIENT_INITIAL_BUFFER 8192

typedef enum {
    OP_NONE,
    OP_PUT,
    OP_GET
} client_op_t;

uv_loop_t *loop;
client_op_t current_op = OP_NONE;
const char *target_filename = NULL;
uv_file local_fd = -1;
uint64_t file_offset = 0;
uv_fs_t fs_req;

uint8_t *client_recv_buffer = NULL;
size_t client_recv_length = 0;
size_t client_recv_capacity = 0;

void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len);
void do_put_read_chunk(uv_stream_t *stream);

/**
 * @brief Allocates a buffer for reading data from a libuv stream.
 *
 * @param handle The libuv handle requesting the buffer.
 * @param suggested_size The size suggested by libuv.
 * @param buf Pointer to the uv_buf_t structure to populate.
 */
void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    if (client_recv_capacity - client_recv_length < suggested_size) {
        size_t new_cap = client_recv_capacity == 0 ? CLIENT_INITIAL_BUFFER : client_recv_capacity * 2;
        while (new_cap - client_recv_length < suggested_size) {
            new_cap *= 2;
        }
        client_recv_buffer = realloc(client_recv_buffer, new_cap);
        client_recv_capacity = new_cap;
    }
    buf->base = (char *)(client_recv_buffer + client_recv_length);
    buf->len = client_recv_capacity - client_recv_length;
}

/**
 * @brief Callback invoked when the connection to the server is closed.
 *
 * @param handle The libuv handle representing the connection.
 */
void on_close(uv_handle_t *handle) {
    printf("Connection closed.\n");
    if (client_recv_buffer) {
        free(client_recv_buffer);
        client_recv_buffer = NULL;
    }
    free(handle);
}

/**
 * @brief Callback invoked when an async write operation completes.
 *
 * @param req The write request.
 * @param status The status of the write operation (0 for success).
 */
void on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error: %s\n", uv_strerror(status));
    }
    
    uv_buf_t *buf = (uv_buf_t *)req->data;
    if (buf) {
        if (buf->base) free(buf->base);
        free(buf);
    }
    
    /* If this was a PUT_DATA frame, read and send the next chunk */
    if (current_op == OP_PUT && local_fd > 0 && status == 0) {
        do_put_read_chunk(req->handle);
    }
    
    free(req);
}

/**
 * @brief Packs and sends a protocol command to the server.
 *
 * @param stream The libuv stream to write to.
 * @param cmd The NASFS command type.
 * @param payload The payload data.
 * @param payload_len The length of the payload.
 */
void send_command(uv_stream_t *stream, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len) {
    size_t frame_size = 0;
    uint8_t *frame_data = protocol_pack_frame(cmd, payload, payload_len, &frame_size);

    if (!frame_data) {
        fprintf(stderr, "Failed to pack protocol frame\n");
        return;
    }

    uv_write_t *write_req = malloc(sizeof(uv_write_t));
    uv_buf_t *buf = malloc(sizeof(uv_buf_t));
    
    *buf = uv_buf_init((char *)frame_data, frame_size);
    write_req->data = buf;

    uv_write(write_req, stream, buf, 1, on_write);
}

/**
 * @brief Callback for local file read completion (PUT operation).
 */
void on_local_read(uv_fs_t *req) {
    uv_stream_t *stream = (uv_stream_t *)req->data;
    if (req->result < 0) {
        fprintf(stderr, "Read error: %s\n", uv_strerror((int)req->result));
        uv_close((uv_handle_t *)stream, on_close);
    } else if (req->result == 0) {
        /* EOF */
        printf("Finished reading local file. Sending PUT_DONE.\n");
        send_command(stream, NASFS_CMD_PUT_DONE, NULL, 0);
        
        uv_fs_t close_req;
        uv_fs_close(loop, &close_req, local_fd, NULL);
        uv_fs_req_cleanup(&close_req);
        local_fd = -1;
        
        /* Disconnect after successful upload */
        uv_close((uv_handle_t *)stream, on_close);
    } else {
        /* Send data chunk */
        size_t bytes_read = req->result;
        file_offset += bytes_read;
        send_command(stream, NASFS_CMD_PUT_DATA, (uint8_t *)req->bufs[0].base, bytes_read);
        printf("\rUploaded %llu bytes...", (unsigned long long)file_offset);
        fflush(stdout);
    }
    
    free(req->bufs[0].base);
    uv_fs_req_cleanup(req);
}

/**
 * @brief Reads a chunk from the local file to send to the server.
 */
void do_put_read_chunk(uv_stream_t *stream) {
    uv_buf_t iov;
    iov.base = malloc(CHUNK_SIZE);
    iov.len = CHUNK_SIZE;
    
    fs_req.data = stream;
    uv_fs_read(loop, &fs_req, local_fd, &iov, 1, file_offset, on_local_read);
}

/**
 * @brief Callback invoked when data is read from the server.
 *
 * @param stream The stream reading data from the server.
 * @param nread Number of bytes read, or negative on error/EOF.
 * @param buf The buffer containing the read data.
 */
void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)buf; // Buffer logic is managed in alloc_buffer

    if (nread > 0) {
        client_recv_length += nread;

        while (client_recv_length > 0) {
            nasfs_frame_t frame;
            int consumed = protocol_parse_frame(client_recv_buffer, client_recv_length, &frame);

            if (consumed > 0) {
                switch (frame.type) {
                    case NASFS_CMD_AUTH_ACK:
                        printf("Server: AUTH_ACK received.\n");
                        if (current_op == OP_PUT) {
                            printf("Sending PUT_REQ for '%s'...\n", target_filename);
                            send_command(stream, NASFS_CMD_PUT_REQ, (const uint8_t *)target_filename, strlen(target_filename));
                        } else if (current_op == OP_GET) {
                            printf("Sending GET_REQ for '%s'...\n", target_filename);
                            send_command(stream, NASFS_CMD_GET_REQ, (const uint8_t *)target_filename, strlen(target_filename));
                        }
                        break;
                        
                    case NASFS_CMD_PUT_ACK:
                        printf("Server: PUT_ACK received. Starting file upload...\n");
                        {
                            uv_fs_t open_req;
                            local_fd = uv_fs_open(loop, &open_req, target_filename, O_RDONLY, 0, NULL);
                            if (local_fd < 0) {
                                fprintf(stderr, "Failed to open local file '%s': %s\n", target_filename, uv_strerror((int)local_fd));
                                uv_close((uv_handle_t *)stream, on_close);
                            } else {
                                file_offset = 0;
                                do_put_read_chunk(stream);
                            }
                            uv_fs_req_cleanup(&open_req);
                        }
                        break;
                        
                    case NASFS_CMD_GET_ACK:
                        printf("Server: GET_ACK received. Starting file download...\n");
                        {
                            uv_fs_t open_req;
                            local_fd = uv_fs_open(loop, &open_req, target_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644, NULL);
                            if (local_fd < 0) {
                                fprintf(stderr, "Failed to open local file '%s' for writing: %s\n", target_filename, uv_strerror((int)local_fd));
                                uv_close((uv_handle_t *)stream, on_close);
                            } else {
                                file_offset = 0;
                            }
                            uv_fs_req_cleanup(&open_req);
                        }
                        break;
                        
                    case NASFS_CMD_GET_DATA:
                        if (local_fd > 0) {
                            uv_fs_t write_req;
                            uv_buf_t write_buf = uv_buf_init((char *)frame.payload, frame.payload_len);
                            /* Synchronous write for simplicity in the CLI client */
                            int res = uv_fs_write(loop, &write_req, local_fd, &write_buf, 1, file_offset, NULL);
                            if (res < 0) {
                                fprintf(stderr, "Write error: %s\n", uv_strerror(res));
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
                        if (local_fd > 0) {
                            uv_fs_t close_req;
                            uv_fs_close(loop, &close_req, local_fd, NULL);
                            uv_fs_req_cleanup(&close_req);
                            local_fd = -1;
                        }
                        uv_close((uv_handle_t *)stream, on_close);
                        break;
                        
                    case NASFS_CMD_ERROR:
                        fprintf(stderr, "\nServer Error: %.*s\n", (int)frame.payload_len, frame.payload);
                        uv_close((uv_handle_t *)stream, on_close);
                        break;
                        
                    default:
                        printf("\nReceived unexpected command: 0x%02X\n", frame.type);
                        break;
                }

                size_t remaining = client_recv_length - consumed;
                if (remaining > 0) {
                    memmove(client_recv_buffer, client_recv_buffer + consumed, remaining);
                }
                client_recv_length = remaining;

            } else if (consumed == 0) {
                /* Wait for more data */
                break;
            } else {
                fprintf(stderr, "Protocol framing error. Closing connection.\n");
                uv_close((uv_handle_t *)stream, on_close);
                break;
            }
        }
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error: %s\n", uv_err_name((int)nread));
        }
        uv_close((uv_handle_t *)stream, on_close);
    }
}

/**
 * @brief Callback invoked when a connection attempt to the server completes.
 *
 * @param req The connection request.
 * @param status The status of the connection attempt (0 for success).
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

    printf("Sending AUTH command...\n");
    send_command(stream, NASFS_CMD_AUTH, (const uint8_t *)"dummy_token_123", 15);

    free(req);
}

/**
 * @brief The main execution loop of the NASFS client.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status code.
 */
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <put|get> <filename>\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "put") == 0) {
        current_op = OP_PUT;
    } else if (strcmp(argv[1], "get") == 0) {
        current_op = OP_GET;
    } else {
        fprintf(stderr, "Invalid operation. Use 'put' or 'get'.\n");
        return 1;
    }
    
    target_filename = argv[2];

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