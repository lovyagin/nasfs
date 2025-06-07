/* server/src/network/connections.c -- Client connection handling
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles client socket connections and implements the echo protocol.  */

#include <_string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <unistd.h>

#include "logging/log.h"
#include "network/connections.h"
#include "utils/signal_handler.h"

/* Size of the buffer used for receiving client data.  */
#define BUFFER_SIZE 1024

/* USER COMMANDS MACROSES.  */
#define GET_COMMAND "GET"

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

      char *command = strtok (buffer, " \t\n");
      if (command)
        {
          if (strcmp (command, "GET") == 0)
            {
              char *filepath = strtok (NULL, " \t\n\r");
              log_all (LOG_DEBUG, "%s", filepath);
              if (filepath)
                {
                  log_all (LOG_INFO, "Client requested file: %s", filepath);
                  FILE *file = fopen (filepath, "rb");

                  if (file)
                    {
                      log_all (LOG_INFO, "Sending file: %s", filepath);

                      const char *response_ok = "OK\n";
                      send (client_sock, response_ok, strlen (response_ok), 0);

                      char file_buffer[BUFFER_SIZE];
                      size_t bytes_read;
                      while ((bytes_read = fread (file_buffer, 1,
                                                  sizeof (file_buffer), file))
                             > 0)
                        {
                          send (client_sock, file_buffer, bytes_read, 0);
                        }
                      fclose (file);
                      log_all (LOG_INFO, "Finished sending file: %s",
                               filepath);
                    }
                  else
                    {
                      log_all (LOG_ERROR, "Failed to open file: %s", filepath);
                      const char *response_error
                          = "ERROR: Failed to open file\n";
                      send (client_sock, response_error,
                            strlen (response_error), 0);
                    }
                }
              else
                {
                  log_all (LOG_WARNING,
                           "GET command received without filepath");
                  const char *response_error = "ERROR: No filepath provided\n";
                  send (client_sock, response_error, strlen (response_error),
                        0);
                }
            }
          else
            {

              log_all (LOG_WARNING, "Unknown command received: %s", command);
              const char *response_error = "ERROR: Unknown command\n";
              send (client_sock, response_error, strlen (response_error), 0);
            }
        }
    }

  close (client_sock);
  log_all (LOG_INFO, "Connection closed");

  pthread_detach (pthread_self ());
  pthread_exit (NULL);
}
