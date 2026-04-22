/**
 * @file main.c
 * @brief Main entry point for the NASFS client application.
 *
 * Initializes a libuv event loop, connects to the NASFS server, and
 * implements a simple echo mechanism for testing the basic protocol.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "protocol.h"

/**
 * @brief Default server port to connect to.
 */
#define SERVER_PORT 8080

/**
 * @brief Default server IP address to connect to.
 */
#define SERVER_IP "127.0.0.1"

/**
 * @brief Global libuv event loop for the client.
 */
uv_loop_t *loop;

/**
 * @brief Allocates a buffer for reading data from a libuv stream.
 *
 * @param handle The libuv handle requesting the buffer.
 * @param suggested_size The size suggested by libuv.
 * @param buf Pointer to the uv_buf_t structure to populate.
 */
void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

/**
 * @brief Callback invoked when the connection to the server is closed.
 *
 * @param handle The libuv handle representing the connection.
 */
void on_close(uv_handle_t *handle) {
    printf("Connection closed.\n");
    free(handle);
}

/**
 * @brief Callback invoked when data is read from the server.
 *
 * @param stream The stream reading data from the server.
 * @param nread Number of bytes read, or negative on error/EOF.
 * @param buf The buffer containing the read data.
 */
void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        printf("Received from server (%zd bytes): %.*s\n", nread, (int)nread, buf->base);
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error: %s\n", uv_err_name(nread));
        }
        uv_close((uv_handle_t *)stream, on_close);
    }

    if (buf->base) {
        free(buf->base);
    }
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
    } else {
        printf("Message sent to server.\n");
    }
    free(req);
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

    uv_write_t *write_req = malloc(sizeof(uv_write_t));
    char *message = "Hello, NASFS Server!";
    uv_buf_t buf = uv_buf_init(message, strlen(message));
    uv_write(write_req, stream, &buf, 1, on_write);

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
    (void)argc;
    (void)argv;

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