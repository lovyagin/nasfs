/**
 * @file main.c
 * @brief Main entry point for the NASFS server daemon.
 *
 * Initializes the configuration, logging, daemonizes if requested, and starts
 * the libuv event loop for handling incoming TCP connections.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "config/config.h"
#include "logging/log.h"
#include "network/session.h"
#include "protocol.h"
#include "utils/daemon.h"
#include "utils/pid_file.h"
#include "utils/signal_handler.h"

uv_loop_t* loop;
uv_tcp_t server;
uv_signal_t sigint_watcher;
uv_signal_t sigterm_watcher;

/**
 * @brief Callback invoked when a system signal is received.
 *
 * @param watcher The signal watcher handle.
 * @param signum The signal number received.
 */
void on_signal(uv_signal_t* watcher, int signum) {
  signal_handler(signum);
  uv_stop(watcher->loop);
}

static void close_server_handle(uv_handle_t* handle, void* arg) {
  (void)arg;
  if (uv_is_closing(handle)) return;
  if (handle->type == UV_TCP && handle != (uv_handle_t*)&server) {
    session_close(handle);
  } else {
    uv_close(handle, NULL);
  }
}

/**
 * @brief The main execution loop of the NASFS server.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status code.
 */
int main(int argc, char** argv) {
  const char* config_file = (argc > 1) ? argv[1] : "config/nasfs.conf";
  int exit_code = 0;

  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to initialize libsodium\n");
    return 1;
  }

  memset(&global_config, 0, sizeof(global_config));
  if (load_config(config_file, &global_config) != 0) {
    fprintf(stderr,
            "Warning: Failed to load config file '%s'. Using defaults.\n",
            config_file);
    set_defaults(&global_config);
  }

  log_init(global_config.log_file, global_config.log_level);
  log_all(LOG_INFO, "Starting NASFS server...");

  if (global_config.daemon_mode) {
    log_all(LOG_INFO, "Daemonizing process...");
    daemonize();
  }

  if (global_config.pid_file && strlen(global_config.pid_file) > 0) {
    if (create_pid_file(global_config.pid_file) == 0) {
      set_pid_file_path(global_config.pid_file);
      atexit(cleanup_pid_file);
    } else {
      log_all(LOG_ERROR, "Failed to create PID file: %s",
              global_config.pid_file);
      exit_code = 1;
      goto cleanup;
    }
  }

  loop = uv_default_loop();

  int r = uv_signal_init(loop, &sigint_watcher);
  if (r == 0) r = uv_signal_start(&sigint_watcher, on_signal, SIGINT);
  if (r == 0) r = uv_signal_init(loop, &sigterm_watcher);
  if (r == 0) r = uv_signal_start(&sigterm_watcher, on_signal, SIGTERM);
  if (r == 0) r = uv_tcp_init(loop, &server);
  if (r < 0) {
    log_all(LOG_ERROR, "Event loop setup failed: %s", uv_strerror(r));
    exit_code = 1;
    goto close_handles;
  }

  struct sockaddr_in addr;
  const char* bind_addr =
      global_config.bind_address ? global_config.bind_address : "0.0.0.0";
  int port = global_config.port >= 0 ? global_config.port : 8080;

  int max_conn =
      global_config.max_connections > 0 ? global_config.max_connections : 128;
  r = uv_ip4_addr(bind_addr, port, &addr);
  if (r == 0) r = uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
  if (r == 0) {
    r = uv_listen((uv_stream_t*)&server, max_conn, session_on_new_connection);
  }

  if (r) {
    log_all(LOG_ERROR, "Listen error: %s", uv_strerror(r));
    exit_code = 1;
    goto close_handles;
  }

  struct sockaddr_in bound_addr;
  int bound_addr_len = sizeof(bound_addr);
  r = uv_tcp_getsockname(&server, (struct sockaddr*)&bound_addr,
                         &bound_addr_len);
  if (r) {
    log_all(LOG_ERROR, "Cannot determine listening port: %s", uv_strerror(r));
    exit_code = 1;
    goto close_handles;
  }
  log_all(LOG_INFO, "nasfs_server listening on %s:%d...", bind_addr,
          ntohs(bound_addr.sin_port));

  uv_run(loop, UV_RUN_DEFAULT);

  log_all(LOG_INFO, "NASFS server shutting down cleanly...");

close_handles:
  uv_walk(loop, close_server_handle, NULL);
  uv_run(loop, UV_RUN_DEFAULT);
  r = uv_loop_close(loop);
  if (r < 0) {
    log_all(LOG_ERROR, "Event loop close failed: %s", uv_strerror(r));
    exit_code = 1;
  }

cleanup:
  free_config(&global_config);
  return exit_code;
}
