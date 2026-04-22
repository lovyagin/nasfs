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
#include "network/session.h"

uv_loop_t *loop;
uv_tcp_t server;
uv_signal_t sigint_watcher;
uv_signal_t sigterm_watcher;

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
    int r = uv_listen((uv_stream_t *)&server, max_conn, session_on_new_connection);
    
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