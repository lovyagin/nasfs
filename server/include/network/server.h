/* server/include/network/server.h -- Network server interface
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Declares functions for server socket setup and operation.  */

#ifndef SERVER_H
#define SERVER_H

#include "config/config.h"

/* Set up the server socket.
   Creates, binds, and starts listening on a socket according to CONFIG.

   Returns the socket file descriptor on success, or -1 on failure.  */
int server_socket_setup(server_config_t *config);

/* Run the server main loop.
   Accepts connections on SERVER_SOCKET and handles them according to CONFIG.
   Continues running until a termination signal is received.  */
void server_run(int server_socket, server_config_t *config);

#endif /* SERVER_H */
