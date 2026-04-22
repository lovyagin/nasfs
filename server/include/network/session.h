/**
 * @file session.h
 * @brief Client session and state management for NASFS server.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS server.
 * Defines structures and functions for handling client connections,
 * TCP stream buffering, and protocol state machine transitions.
 */

#ifndef NASFS_SESSION_H
#define NASFS_SESSION_H

#include <uv.h>
#include <stdint.h>
#include <stddef.h>

#include "protocol.h"

/**
 * @enum session_state_t
 * @brief Defines the current operational state of a client session.
 */
typedef enum {
    SESSION_STATE_NEW = 0,         /**< Newly connected, awaiting authentication. */
    SESSION_STATE_AUTHENTICATED,   /**< Authenticated, waiting for commands. */
    SESSION_STATE_RECEIVING_FILE,  /**< Currently receiving file data (PUT). */
    SESSION_STATE_SENDING_FILE,    /**< Currently sending file data (GET). */
    SESSION_STATE_ERROR            /**< Terminal error state, pending closure. */
} session_state_t;

/**
 * @struct client_session_t
 * @brief Context and state for an active client connection.
 */
typedef struct {
    uv_tcp_t handle;               /**< libuv TCP handle for the connection. */
    session_state_t state;         /**< Current state of the session. */
    uint8_t *recv_buffer;          /**< Buffer for accumulating incomplete TCP frames. */
    size_t recv_length;            /**< Current number of bytes in the receive buffer. */
    size_t recv_capacity;          /**< Total allocated capacity of the receive buffer. */
    uv_file active_fd;             /**< File descriptor for active transfers (PUT/GET). */
    uv_fs_t fs_req;                /**< Filesystem request handle for async operations. */
    uint64_t file_offset;          /**< Current offset in the active file. */
} client_session_t;

/**
 * @brief Callback for accepting new incoming client connections.
 *
 * @param server The listening server stream.
 * @param status The connection attempt status (0 for success).
 */
void session_on_new_connection(uv_stream_t *server, int status);

/**
 * @brief Gracefully closes a client session and frees associated resources.
 *
 * @param handle The libuv handle representing the client connection.
 */
void session_close(uv_handle_t *handle);

#endif /* NASFS_SESSION_H */