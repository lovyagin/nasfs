/* server/src/network/connections.c -- Client connection handling
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles client socket connections and implements the echo protocol.  */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logging/log.h"
#include "network/connections.h"
#include "utils/signal_handler.h"

/* Size of the buffer used for receiving client data.  */
#define BUFFER_SIZE 1024

/* Handle a client connection in a separate thread.
   Accepts a client socket descriptor via CLIENT_SOCKET_PTR (which is freed),
   sends a greeting message, then enters an echo loop until the client
   disconnects or a timeout/error occurs.

   This function runs in its own thread for each client connection.
   The thread is set to detach mode before termination.  */
void *
handle_client (void *client_socket_ptr)
{
  int client_sock = *((int *)client_socket_ptr);
  free (client_socket_ptr);

  char buffer[BUFFER_SIZE];
  ssize_t bytes_received;

  /* Send greeting message to client */
  const char *greeting = "Welcome to NASFS server!\n";
  send (client_sock, greeting, strlen (greeting), 0);

  while (server_running)
    {
      bytes_received = recv (client_sock, buffer, sizeof (buffer) - 1, 0);

      if (bytes_received < 0)
        {
          if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
              log_all (LOG_WARNING, "Client timeout reached");
              break;
            }
          log_all (LOG_ERROR, "Receive error: %s", strerror (errno));
          break;
        }

      if (bytes_received == 0)
        {
          log_all (LOG_INFO, "Client disconnected");
          break;
        }

      buffer[bytes_received] = '\0';
      log_all (LOG_DEBUG, "Received from client: '%s'", buffer);

      /* Echo the received data back to client */
      send (client_sock, buffer, bytes_received, 0);
      log_all (LOG_INFO, "Response sent");
    }

  close (client_sock);
  log_all (LOG_INFO, "Connection closed");

  pthread_detach (pthread_self ());
  pthread_exit (NULL);
}
