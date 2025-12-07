/* server/src/network/server.c -- Network server implementation
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Implements TCP server socket setup and client connection handling.  */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config/config.h"
#include "logging/log.h"
#include "network/connections.h"
#include "network/server.h"
#include "utils/signal_handler.h"

/* Set up the server socket.
   Creates, binds, and starts listening on the socket according to CONFIG.

   Returns the socket file descriptor on success, or -1 on failure.  */
int
server_socket_setup (server_config_t *config)
{
  int server_socket = socket (AF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      log_all (LOG_ERROR, "Socket creation failed: %s", strerror (errno));
      return -1;
    }

  /* Allow reuse of address */
  int opt = 1;
  if (setsockopt (server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt))
      < 0)
    {
      log_all (LOG_ERROR, "setsockopt(SO_REUSEADDR) failed: %s",
               strerror (errno));
      close (server_socket);
      return -1;
    }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons (config->port);

  if (strcmp (config->bind_address, "0.0.0.0") == 0)
    {
      server_addr.sin_addr.s_addr = INADDR_ANY;
    }
  else
    {
      if (inet_pton (AF_INET, config->bind_address, &server_addr.sin_addr)
          <= 0)
        {
          log_all (LOG_ERROR, "Invalid address: %s", config->bind_address);
          close (server_socket);
          return -1;
        }
    }

  if (bind (server_socket, (struct sockaddr *)&server_addr,
            sizeof (server_addr))
      < 0)
    {
      log_all (LOG_ERROR, "Bind failed: %s", strerror (errno));
      close (server_socket);
      return -1;
    }

  if (listen (server_socket, config->max_connections) < 0)
    {
      log_all (LOG_ERROR, "Listen failed: %s", strerror (errno));
      close (server_socket);
      return -1;
    }

  log_all (LOG_INFO, "Server listening on %s:%d", config->bind_address,
           config->port);
  return server_socket;
}

/* Run the server main loop.
   Accepts client connections on SERVER_SOCKET and spawns threads to handle
   them according to CONFIG settings. Continues until the server_running flag
   is set to 0 (typically by a signal handler).  */
void
server_run (int server_socket, server_config_t *config)
{
  while (server_running)
    {
      struct sockaddr_in client_addr;
      socklen_t client_len = sizeof (client_addr);

      fd_set readfds;
      FD_ZERO (&readfds);
      FD_SET (server_socket, &readfds);

      struct timeval timeout;
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      int ready = select (server_socket + 1, &readfds, NULL, NULL, &timeout);
      if (ready < 0)
        {
          if (!server_running)
            break;
          log_all (LOG_ERROR, "Select error: %s", strerror (errno));
          server_running = 0;
          break;
        }

      if (ready == 0)
        continue;

      if (FD_ISSET (server_socket, &readfds))
        {
          int client_socket = accept (
              server_socket, (struct sockaddr *)&client_addr, &client_len);

          if (client_socket == -1)
            {
              if (!server_running)
                break;
              log_all (LOG_ERROR, "Accept error: %s", strerror (errno));
              continue;
            }

          /* Log client connection info */
          char client_ip[INET_ADDRSTRLEN];
          inet_ntop (AF_INET, &client_addr.sin_addr, client_ip,
                     INET_ADDRSTRLEN);
          int client_port = ntohs (client_addr.sin_port);
          log_all (LOG_INFO, "Accepted connection from %s:%d", client_ip,
                   client_port);

          /* Set client timeout */
          struct timeval client_timeout;
          client_timeout.tv_sec = config->client_timeout;
          client_timeout.tv_usec = 0;

          if (setsockopt (client_socket, SOL_SOCKET, SO_RCVTIMEO,
                          &client_timeout, sizeof client_timeout)
              < 0)
            {
              log_all (LOG_ERROR, "Set timeout error: %s", strerror (errno));
              close (client_socket);
              continue;
            }

          /* Create thread to handle client */
          client_context_t *client_ctx = malloc (sizeof (client_context_t));
          if (!client_ctx)
            {
              log_all (LOG_ERROR, "Memory allocation failed");
              close (client_socket);
              continue;
            }
          client_ctx->client_socket = client_socket;
          client_ctx->config = config;

          pthread_t client_thread;
          if (pthread_create (&client_thread, NULL, handle_client,
                              client_ctx)
              != 0)
            {
              log_all (LOG_ERROR, "Failed to create client thread: %s",
                       strerror (errno));
              free (client_ctx);
              close (client_socket);
            }
        }
    }

  close (server_socket);
  log_all (LOG_INFO, "Server shutdown complete");
}
