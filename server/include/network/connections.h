/* server/include/network/connections.h -- Client connection handling
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Declares the interface for client connection handling.  */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "config/config.h"

/* Client connection context structure
   Contains all the data needed for the connection handler thread */
typedef struct client_context
{
  int client_socket;
  server_config_t *config;
} client_context_t;

/* Handle a client connection in a separate thread.
   CLIENT_CTX_PTR is a pointer to a client_context_t structure containing
   the socket file descriptor and server configuration.

   This function is designed to be called by pthread_create and runs
   in its own thread for each client connection.

   Returns NULL when the client disconnects or on error.  */
void *handle_client (void *client_ctx_ptr);

#endif /* CONNECTIONS_H */
