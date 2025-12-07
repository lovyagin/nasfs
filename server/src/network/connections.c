/* server/src/network/connections.c -- Client connection handling
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles client socket connections and implements the echo protocol.  */

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/syslimits.h>
#elif defined(__linux__)
#include <linux/limits.h>
#else
// Fallback for unsupported platforms
#define PATH_MAX 4096
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config/config.h"
#include "logging/log.h"
#include "network/connections.h"
#include "utils/signal_handler.h"

/* Maximum amount of data to send in one chunk.  */
#define MAX_SEND_CHUNK 1048576 /* 1MB */

/* USER COMMANDS MACROS.  */
#define GET_COMMAND "GET"
#define PUT_COMMAND "PUT"
#define BUFFER_SIZE 4096 /* Increased buffer size for better performance */

/* Handle a client connection in a separate thread.
   Accepts a client socket descriptor via CLIENT_SOCKET_PTR (which is freed),
   sends a greeting message, then processes commands until the client
   disconnects or a timeout/error occurs.

   This function runs in its own thread for each client connection.
   The thread is set to detach mode before termination.  */
void *handle_client(void *client_ctx_ptr) {
  client_context_t *ctx = (client_context_t *)client_ctx_ptr;
  int client_sock = ctx->client_socket;
  server_config_t *config = ctx->config;
  free(client_ctx_ptr);

  char buffer[BUFFER_SIZE];
  ssize_t bytes_received;

  /* Send greeting message to client */
  const char *greeting = "Welcome to NASFS server!\n";
  send(client_sock, greeting, strlen(greeting), 0);

  while (server_running) {
    bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);

    if (bytes_received < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        log_all(LOG_WARNING, "Client timeout reached");
        break;
      }
      log_all(LOG_ERROR, "Receive error: %s", strerror(errno));
      break;
    }

    if (bytes_received == 0) {
      log_all(LOG_INFO, "Client disconnected");
      break;
    }

    buffer[bytes_received] = '\0';
    log_all(LOG_DEBUG, "Received from client: '%s'", buffer);

    /* Debug: Print each byte received to identify invisible characters */
    log_all(LOG_DEBUG, "Received bytes in hex:");
    for (int i = 0; i < bytes_received; i++) {
      log_all(LOG_DEBUG, "[%d]: %02X (%c)", i, buffer[i],
              isprint(buffer[i]) ? buffer[i] : '.');
    }

    /* Trim any leading whitespace manually */
    int start_idx = 0;
    while (start_idx < bytes_received &&
           (buffer[start_idx] == ' ' || buffer[start_idx] == '\t' ||
            buffer[start_idx] == '\r' || buffer[start_idx] == '\n')) {
      start_idx++;
    }

    char *command = strtok(buffer + start_idx, " \t\n\r");
    if (command) {
      log_all(LOG_DEBUG, "Parsed command: '%s'", command);

      if (strcmp(command, "GET") == 0) {
        char *filepath = strtok(NULL, " \t\n\r");
        log_all(LOG_DEBUG, "%s", filepath);
        if (filepath) {
          log_all(LOG_INFO, "Client requested file: %s", filepath);

          /* Build full path using config->storage_dir */
          char full_path[PATH_MAX];
          if (config->storage_dir) {
            snprintf(full_path, sizeof(full_path), "%s/%s", config->storage_dir,
                     filepath);
            log_all(LOG_DEBUG, "Full path: %s", full_path);
          } else {
            strncpy(full_path, filepath, sizeof(full_path) - 1);
            full_path[sizeof(full_path) - 1] = '\0';
            log_all(LOG_WARNING, "FileDir not set, using relative path: %s",
                    full_path);
          }

          FILE *file = fopen(full_path, "rb");

          if (file) {
            log_all(LOG_INFO, "Sending file: %s (from %s)", filepath,
                    config->storage_dir ? config->storage_dir
                                        : "current directory");

            /* Get file size for logging */
            struct stat file_stat;
            fstat(fileno(file), &file_stat);
            size_t file_size = file_stat.st_size;
            log_all(LOG_INFO, "Starting to send file: %s (%zu bytes)",
                    full_path, file_size);

            /* Send OK response */
            const char *response_ok = "OK\n";
            send(client_sock, response_ok, strlen(response_ok), 0);

            /* Send file in chunks */
            char file_buffer[BUFFER_SIZE];
            size_t bytes_read;
            size_t total_sent = 0;
            size_t last_progress = 0;

            while ((bytes_read =
                        fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
              ssize_t bytes_sent =
                  send(client_sock, file_buffer, bytes_read, 0);
              if (bytes_sent < 0) {
                log_all(LOG_ERROR, "Failed to send data: %s", strerror(errno));
                break;
              }
              total_sent += bytes_sent;

              /* Log progress for large files */
              if (file_size > 1048576 &&
                  (total_sent - last_progress) > 1048576) {
                log_all(LOG_DEBUG, "Sent %zu of %zu bytes (%.1f%%)", total_sent,
                        file_size, (double)total_sent / file_size * 100);
                last_progress = total_sent;
              }
            }

            /* Make sure all data is sent before closing */
            fsync(fileno(file));
            fclose(file);

            /* Signal end of transfer with a properly closed connection */
            shutdown(client_sock, SHUT_WR);
            log_all(LOG_INFO, "Finished sending file: %s (%zu of %zu bytes)",
                    full_path, total_sent, file_size);
          } else {
            log_all(LOG_ERROR, "Failed to open file: %s (full path: %s)",
                    filepath, full_path);
            const char *response_error = "ERROR: Failed to open file\n";
            send(client_sock, response_error, strlen(response_error), 0);
          }
        } else {
          log_all(LOG_WARNING, "GET command received without filepath");
          const char *response_error = "ERROR: No filepath provided\n";
          send(client_sock, response_error, strlen(response_error), 0);
        }
      } else if (strcmp(command, "PUT") == 0 ||
                 strncmp(command, "PUT", 3) == 0) {
        /* Format: PUT filename filesize */
        /* Handle case where the PUT command might have extra characters */
        if (strcmp(command, "PUT") != 0) {
          log_all(LOG_WARNING,
                  "Detected malformed PUT command, trying to correct");
        }

        char *filepath = strtok(NULL, " \t\n\r");
        char *filesizeStr = strtok(NULL, " \t\n\r");

        if (filepath && filesizeStr) {
          long filesize = atol(filesizeStr);
          log_all(LOG_INFO, "Client wants to upload file: %s (%ld bytes)",
                  filepath, filesize);

          /* Build full path using config->storage_dir */
          char full_path[PATH_MAX];
          if (config->storage_dir) {
            snprintf(full_path, sizeof(full_path), "%s/%s", config->storage_dir,
                     filepath);
            log_all(LOG_DEBUG, "Full path: %s", full_path);
          } else {
            strncpy(full_path, filepath, sizeof(full_path) - 1);
            full_path[sizeof(full_path) - 1] = '\0';
            log_all(LOG_WARNING, "FileDir not set, using relative path: %s",
                    full_path);
          }

          /* Log directory information */
          char dir_path[PATH_MAX];
          strncpy(dir_path, full_path, sizeof(dir_path) - 1);
          dir_path[sizeof(dir_path) - 1] = '\0';

          char *dir_slash = strrchr(dir_path, '/');
          if (dir_slash) {
            *dir_slash = '\0';
            log_all(LOG_DEBUG, "Directory path: %s", dir_path);

            /* Check if directory exists */
            struct stat st;
            if (stat(dir_path, &st) == 0 && S_ISDIR(st.st_mode)) {
              log_all(LOG_DEBUG, "Directory exists with permissions: %o",
                      st.st_mode & 0777);
            } else {
              log_all(LOG_WARNING,
                      "Directory does not exist or is not accessible: %s",
                      dir_path);
            }
          }

          /* Create directories if they don't exist */
          char *last_slash = strrchr(full_path, '/');
          if (last_slash) {
            *last_slash = '\0';
            /* Create directories recursively with mode 0755 */
            char *p = full_path;
            while ((p = strchr(p + 1, '/'))) {
              *p = '\0';
              int mkdir_result = mkdir(full_path, 0755);
              log_all(LOG_DEBUG,
                      "Creating directory: %s (result: %d, errno: %s)",
                      full_path, mkdir_result,
                      mkdir_result < 0 ? strerror(errno) : "success");
              *p = '/';
            }
            int mkdir_result = mkdir(full_path, 0755);
            log_all(LOG_DEBUG,
                    "Creating final directory: %s (result: %d, errno: %s)",
                    full_path, mkdir_result,
                    mkdir_result < 0 ? strerror(errno) : "success");
            *last_slash = '/';
          }

          log_all(LOG_DEBUG, "Attempting to create file: %s", full_path);
          FILE *file = fopen(full_path, "wb");

          if (file == NULL) {
            log_all(LOG_ERROR, "Failed to create file: %s - Error: %s",
                    full_path, strerror(errno));

            /* Check file path permissions */
            char parent_dir[PATH_MAX];
            char *last_dir_slash = strrchr(full_path, '/');
            if (last_dir_slash) {
              strncpy(parent_dir, full_path, last_dir_slash - full_path);
              parent_dir[last_dir_slash - full_path] = '\0';

              struct stat st;
              if (stat(parent_dir, &st) == 0) {
                log_all(LOG_DEBUG,
                        "Parent directory %s exists with permissions: %o",
                        parent_dir, st.st_mode & 0777);
              } else {
                log_all(
                    LOG_ERROR,
                    "Parent directory %s does not exist or not accessible: %s",
                    parent_dir, strerror(errno));
              }
            }
          }

          if (file) {
            /* Send READY to client */
            const char *ready_response = "READY\n";
            send(client_sock, ready_response, strlen(ready_response), 0);

            /* Read data from client and write to file */
            char file_buffer[BUFFER_SIZE];
            size_t total_received = 0;
            ssize_t bytes_read;
            size_t last_progress = 0;

            while (total_received < filesize) {
              size_t to_read = BUFFER_SIZE;
              if (filesize - total_received < BUFFER_SIZE)
                to_read = filesize - total_received;

              bytes_read = recv(client_sock, file_buffer, to_read, 0);

              if (bytes_read <= 0) {
                if (bytes_read == 0) {
                  log_all(LOG_WARNING,
                          "Client closed connection before finishing upload");
                } else {
                  log_all(LOG_ERROR, "Error receiving file data: %s",
                          strerror(errno));
                }
                break;
              }

              size_t bytes_written = fwrite(file_buffer, 1, bytes_read, file);
              if (bytes_written != bytes_read) {
                log_all(LOG_ERROR, "Error writing to file: %s",
                        strerror(errno));
                break;
              }

              total_received += bytes_read;

              /* Log progress for large files */
              if (filesize > 1048576 &&
                  (total_received - last_progress) > 1048576) {
                log_all(LOG_DEBUG, "Received %zu/%ld bytes (%.1f%%)",
                        total_received, filesize,
                        (double)total_received / filesize * 100);
                last_progress = total_received;
              }
            }

            fclose(file);

            if (total_received == filesize) {
              log_all(LOG_INFO, "Successfully received file: %s (%zu bytes)",
                      filepath, total_received);
              const char *ok_response = "OK\n";
              send(client_sock, ok_response, strlen(ok_response), 0);
            } else {
              log_all(LOG_ERROR, "Incomplete file transfer: %zu/%ld bytes",
                      total_received, filesize);
              const char *error_response = "ERROR: Incomplete transfer\n";
              send(client_sock, error_response, strlen(error_response), 0);
              unlink(full_path);  // Delete incomplete file
            }
          } else {
            log_all(LOG_ERROR, "Failed to create file: %s (full path: %s): %s",
                    filepath, full_path, strerror(errno));
            const char *error_response = "ERROR: Failed to create file\n";
            send(client_sock, error_response, strlen(error_response), 0);
          }
        } else {
          log_all(LOG_WARNING, "PUT command with invalid parameters");
          const char *error_response = "ERROR: Invalid PUT parameters\n";
          send(client_sock, error_response, strlen(error_response), 0);
        }
      } else {
        /* Check if command starts with P, U, T and might be intended as PUT */
        if ((command[0] == 'P' || command[0] == 'p') &&
            (strlen(command) > 1 && (command[1] == 'U' || command[1] == 'u')) &&
            (strlen(command) > 2 && (command[2] == 'T' || command[2] == 't'))) {
          log_all(LOG_WARNING,
                  "Received possible PUT variant, trying to process as PUT");

          /* Try to process as PUT command */
          char *filepath = strtok(NULL, " \t\n\r");
          char *filesizeStr = strtok(NULL, " \t\n\r");

          if (filepath && filesizeStr) {
            /* Redirect to PUT command handling by re-running with corrected
             * command */
            log_all(LOG_INFO, "Treating '%s' as PUT command", command);

            /* Build full path using config->storage_dir */
            char full_path[PATH_MAX];
            if (config->storage_dir) {
              snprintf(full_path, sizeof(full_path), "%s/%s",
                       config->storage_dir, filepath);
              log_all(LOG_DEBUG, "Full path: %s", full_path);
            } else {
              strncpy(full_path, filepath, sizeof(full_path) - 1);
              full_path[sizeof(full_path) - 1] = '\0';
              log_all(LOG_WARNING, "FileDir not set, using relative path: %s",
                      full_path);
            }

            /* Continue with PUT command handling */
            long filesize = atol(filesizeStr);
            log_all(LOG_INFO, "Client wants to upload file: %s (%ld bytes)",
                    filepath, filesize);

            /* The rest of PUT handling... */
            FILE *file = fopen(full_path, "wb");
            if (file) {
              /* Send READY to client */
              const char *ready_response = "READY\n";
              send(client_sock, ready_response, strlen(ready_response), 0);

              /* Continue with existing PUT implementation... */
              char file_buffer[BUFFER_SIZE];
              size_t total_received = 0;
              ssize_t bytes_read;
              size_t last_progress = 0;

              while (total_received < filesize) {
                size_t to_read = BUFFER_SIZE;
                if (filesize - total_received < BUFFER_SIZE)
                  to_read = filesize - total_received;

                bytes_read = recv(client_sock, file_buffer, to_read, 0);

                if (bytes_read <= 0) {
                  if (bytes_read == 0) {
                    log_all(LOG_WARNING,
                            "Client closed connection before finishing upload");
                  } else {
                    log_all(LOG_ERROR, "Error receiving file data: %s",
                            strerror(errno));
                  }
                  break;
                }

                size_t bytes_written = fwrite(file_buffer, 1, bytes_read, file);
                if (bytes_written != bytes_read) {
                  log_all(LOG_ERROR, "Error writing to file: %s",
                          strerror(errno));
                  break;
                }

                total_received += bytes_read;

                /* Log progress for large files */
                if (filesize > 1048576 &&
                    (total_received - last_progress) > 1048576) {
                  log_all(LOG_DEBUG, "Received %zu/%ld bytes (%.1f%%)",
                          total_received, filesize,
                          (double)total_received / filesize * 100);
                  last_progress = total_received;
                }
              }

              fclose(file);

              if (total_received == filesize) {
                log_all(LOG_INFO, "Successfully received file: %s (%zu bytes)",
                        filepath, total_received);
                const char *ok_response = "OK\n";
                send(client_sock, ok_response, strlen(ok_response), 0);
              } else {
                log_all(LOG_ERROR, "Incomplete file transfer: %zu/%ld bytes",
                        total_received, filesize);
                const char *error_response = "ERROR: Incomplete transfer\n";
                send(client_sock, error_response, strlen(error_response), 0);
                unlink(full_path);  // Delete incomplete file
              }
            } else {
              log_all(LOG_ERROR,
                      "Failed to create file: %s (full path: %s): %s", filepath,
                      full_path, strerror(errno));
              const char *error_response = "ERROR: Failed to create file\n";
              send(client_sock, error_response, strlen(error_response), 0);
            }
            continue;  // Skip the error message below
          }
        }

        log_all(LOG_WARNING, "Unknown command received: '%s'", command);
        log_all(LOG_DEBUG, "Command length: %zu bytes", strlen(command));
        log_all(LOG_DEBUG, "Command in hex:");
        for (size_t i = 0; i < strlen(command); i++) {
          log_all(LOG_DEBUG, "[%zu]: %02X (%c)", i, command[i],
                  isprint(command[i]) ? command[i] : '.');
        }
        log_all(LOG_DEBUG, "Expected 'PUT' in hex: %02X %02X %02X", 'P', 'U',
                'T');

        const char *response_error = "ERROR: Unknown command\n";
        send(client_sock, response_error, strlen(response_error), 0);
      }
    }
  }

  close(client_sock);
  log_all(LOG_INFO, "Connection closed");

  pthread_detach(pthread_self());
  pthread_exit(NULL);
}
