/* server/include/network/connections.h -- Client connection handling
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Declares the interface for client connection handling.  */

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

/* Handle a client connection in a separate thread.
   CLIENT_SOCKET_PTR is a pointer to the socket file descriptor.

   This function is designed to be called by pthread_create and runs
   in its own thread for each client connection.

   Returns NULL when the client disconnects or on error.  */
void *handle_client (void *client_socket_ptr);

#endif /* CONNECTIONS_H */
