/**
 * @file main.c
 * @brief Main entry point for the NASFS server daemon.
 *
 * Initializes the configuration, logging, daemonizes if requested, and starts
 * the libuv event loop for handling incoming TCP connections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <signal.h>

#include "protocol.h"
#include "config/config.h"
#include "logging/log.h"
#include "utils/daemon.h"
#include "utils/pid_file.h"
#include "utils/signal_handler.h"

uv_loop_t *loop;
uv_tcp_t server;
uv_signal_t sigint_watcher;
uv_signal_t sigterm_watcher;

/**
 * @struct client_t
 * @brief Represents an active client connection.
 */
typedef struct {
    uv_tcp_t handle;
} client_t;

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
 * @brief Callback invoked when a client connection is fully closed.
 *
 * @param handle The libuv handle representing the client connection.
 */
void on_close(uv_handle_t *handle) {
    client_t *client = (client_t *)handle;
    free(client);
    log_all(LOG_INFO, "Client disconnected.");
}

/**
 * @brief Callback invoked when an async write operation completes.
 *
 * @param req The write request.
 * @param status The status of the write operation (0 for success).
 */
void echo_write(uv_write_t *req, int status) {
    if (status) {
        log_all(LOG_ERROR, "Write error: %s", uv_strerror(status));
    }
    free(req);
}

/**
 * @brief Callback invoked when data is read from a client stream.
 *
 * @param client_stream The client connection stream.
 * @param nread Number of bytes read, or negative on error/EOF.
 * @param buf The buffer containing the read data.
 */
void on_read(uv_stream_t *client_stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        log_all(LOG_DEBUG, "Received %zd bytes.", nread);

        uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
        uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
        uv_write(req, client_stream, &wrbuf, 1, echo_write);
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            log_all(LOG_ERROR, "Read error: %s", uv_err_name(nread));
        }
        uv_close((uv_handle_t *)client_stream, on_close);
    }

    if (buf->base) {
        free(buf->base);
    }
}

/**
 * @brief Callback invoked when a new incoming connection is received.
 *
 * @param server_stream The server stream that received the connection.
 * @param status The status of the connection attempt.
 */
void on_new_connection(uv_stream_t *server_stream, int status) {
    if (status < 0) {
        log_all(LOG_ERROR, "New connection error: %s", uv_strerror(status));
        return;
    }

    client_t *client = malloc(sizeof(client_t));
    uv_tcp_init(loop, &client->handle);

    if (uv_accept(server_stream, (uv_stream_t *)&client->handle) == 0) {
        log_all(LOG_INFO, "New client connected.");
        uv_read_start((uv_stream_t *)&client->handle, alloc_buffer, on_read);
    } else {
        uv_close((uv_handle_t *)&client->handle, on_close);
    }
}

/**
 * @brief Callback invoked when a system signal is received.
 *
 * @param watcher The signal watcher handle.
 * @param signum The signal number received.
 */
void on_signal(uv_signal_t *watcher, int signum) {
    signal_handler(signum);
    uv_stop(watcher->loop);
}

/**
 * @brief The main execution loop of the NASFS server.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status code.
 */
int main(int argc, char **argv) {
    server_config_t config;
    const char *config_file = (argc > 1) ? argv[1] : "config/nasfs.conf";

    set_defaults(&config);
    if (load_config(config_file, &config) != 0) {
        fprintf(stderr, "Warning: Failed to load config file '%s'. Using defaults.\n", config_file);
    }

    log_init(config.log_file, config.log_level);
    log_all(LOG_INFO, "Starting NASFS server...");

    if (config.daemon_mode) {
        log_all(LOG_INFO, "Daemonizing process...");
        daemonize();
    }

    if (config.pid_file && strlen(config.pid_file) > 0) {
        if (create_pid_file(config.pid_file) == 0) {
            set_pid_file_path(config.pid_file);
            atexit(cleanup_pid_file);
        } else {
            log_all(LOG_ERROR, "Failed to create PID file: %s", config.pid_file);
            return 1;
        }
    }

    loop = uv_default_loop();

    uv_signal_init(loop, &sigint_watcher);
    uv_signal_start(&sigint_watcher, on_signal, SIGINT);

    uv_signal_init(loop, &sigterm_watcher);
    uv_signal_start(&sigterm_watcher, on_signal, SIGTERM);

    uv_tcp_init(loop, &server);

    struct sockaddr_in addr;
    const char *bind_addr = config.bind_address ? config.bind_address : "0.0.0.0";
    int port = config.port > 0 ? config.port : 8080;
    
    uv_ip4_addr(bind_addr, port, &addr);

    uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    
    int max_conn = config.max_connections > 0 ? config.max_connections : 128;
    int r = uv_listen((uv_stream_t *)&server, max_conn, on_new_connection);
    
    if (r) {
        log_all(LOG_ERROR, "Listen error: %s", uv_strerror(r));
        return 1;
    }

    log_all(LOG_INFO, "nasfs_server listening on %s:%d...", bind_addr, port);
    
    uv_run(loop, UV_RUN_DEFAULT);

    log_all(LOG_INFO, "NASFS server shutting down cleanly...");

    uv_close((uv_handle_t *)&sigint_watcher, NULL);
    uv_close((uv_handle_t *)&sigterm_watcher, NULL);
    uv_close((uv_handle_t *)&server, NULL);
    
    uv_run(loop, UV_RUN_NOWAIT);
    uv_loop_close(loop);

    return 0;
}