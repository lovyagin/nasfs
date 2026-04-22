/**
 * @file session.c
 * @brief Client session management and protocol dispatcher.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS server.
 * Implements connection lifecycle, reading from TCP streams, buffering fragments,
 * parsing protocol frames, and dispatching to correct command handlers.
 */

#include "network/session.h"
#include "logging/log.h"
#include <stdlib.h>
#include <string.h>

#define INITIAL_RECV_BUFFER_SIZE 8192
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024) /* Max frame 64MB */

/**
 * @brief Allocates buffer space for libuv read operations.
 *
 * @param handle The libuv stream handle.
 * @param suggested_size Suggested size from libuv.
 * @param buf Output buffer structure.
 */
static void session_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    client_session_t *session = (client_session_t *)handle->data;

    if (session->recv_capacity - session->recv_length < suggested_size) {
        size_t new_cap = session->recv_capacity * 2;
        if (new_cap == 0) new_cap = INITIAL_RECV_BUFFER_SIZE;
        while (new_cap - session->recv_length < suggested_size) {
            new_cap *= 2;
        }

        if (new_cap > MAX_RECV_BUFFER_SIZE) {
            log_all(LOG_ERROR, "Client exceeded maximum buffer size. Closing.");
            uv_close((uv_handle_t *)&session->handle, session_close);
            buf->base = NULL;
            buf->len = 0;
            return;
        }

        uint8_t *new_buf = realloc(session->recv_buffer, new_cap);
        if (!new_buf) {
            log_all(LOG_ERROR, "Failed to reallocate receive buffer");
            uv_close((uv_handle_t *)&session->handle, session_close);
            buf->base = NULL;
            buf->len = 0;
            return;
        }

        session->recv_buffer = new_buf;
        session->recv_capacity = new_cap;
    }

    buf->base = (char *)(session->recv_buffer + session->recv_length);
    buf->len = session->recv_capacity - session->recv_length;
}

/**
 * @brief Dispatches a fully parsed protocol frame to its handler.
 *
 * @param session The client session.
 * @param frame The parsed protocol frame.
 */
static void session_dispatch_frame(client_session_t *session, nasfs_frame_t *frame) {
    switch (frame->type) {
        case NASFS_CMD_AUTH:
            log_all(LOG_INFO, "Received AUTH command");
            session->state = SESSION_STATE_AUTHENTICATED;
            break;

        case NASFS_CMD_PUT_REQ:
            log_all(LOG_INFO, "Received PUT_REQ command");
            session->state = SESSION_STATE_RECEIVING_FILE;
            break;

        case NASFS_CMD_PUT_DATA:
            log_all(LOG_DEBUG, "Received PUT_DATA chunk (%zu bytes)", frame->payload_len);
            break;

        case NASFS_CMD_GET_REQ:
            log_all(LOG_INFO, "Received GET_REQ command");
            session->state = SESSION_STATE_SENDING_FILE;
            break;

        case NASFS_CMD_GET_DATA:
            log_all(LOG_WARNING, "Server received GET_DATA which makes no sense.");
            break;

        default:
            log_all(LOG_WARNING, "Unknown command type: 0x%02X", frame->type);
            break;
    }
}

/**
 * @brief Reads data from the TCP stream and processes complete frames.
 *
 * @param stream The libuv stream.
 * @param nread Number of bytes read.
 * @param buf The libuv buffer containing the data.
 */
static void session_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_session_t *session = (client_session_t *)stream->data;
    (void)buf; // Buffer logic is managed in session_alloc_buffer

    if (nread > 0) {
        session->recv_length += nread;

        while (session->recv_length > 0) {
            nasfs_frame_t frame;
            int consumed = protocol_parse_frame(session->recv_buffer, session->recv_length, &frame);

            if (consumed > 0) {
                // Complete frame parsed
                session_dispatch_frame(session, &frame);

                // Shift remaining data in the buffer
                size_t remaining = session->recv_length - consumed;
                if (remaining > 0) {
                    memmove(session->recv_buffer, session->recv_buffer + consumed, remaining);
                }
                session->recv_length = remaining;

            } else if (consumed == 0) {
                // Incomplete frame, wait for more data
                break;
            } else {
                // Framing error
                log_all(LOG_ERROR, "Protocol framing error. Closing connection.");
                uv_close((uv_handle_t *)&session->handle, session_close);
                break;
            }
        }
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            log_all(LOG_ERROR, "Read error: %s", uv_err_name(nread));
        } else {
            log_all(LOG_INFO, "Client cleanly disconnected (EOF).");
        }
        uv_close((uv_handle_t *)stream, session_close);
    }
}

void session_on_new_connection(uv_stream_t *server, int status) {
    if (status < 0) {
        log_all(LOG_ERROR, "New connection error: %s", uv_strerror(status));
        return;
    }

    client_session_t *session = calloc(1, sizeof(client_session_t));
    if (!session) {
        log_all(LOG_ERROR, "Failed to allocate memory for new session");
        return;
    }

    uv_tcp_init(server->loop, &session->handle);
    session->handle.data = session;
    session->state = SESSION_STATE_NEW;

    session->recv_capacity = INITIAL_RECV_BUFFER_SIZE;
    session->recv_buffer = malloc(session->recv_capacity);
    session->recv_length = 0;

    if (!session->recv_buffer) {
        log_all(LOG_ERROR, "Failed to allocate session receive buffer");
        free(session);
        return;
    }

    if (uv_accept(server, (uv_stream_t *)&session->handle) == 0) {
        log_all(LOG_INFO, "New client connected. Waiting for authentication.");
        uv_read_start((uv_stream_t *)&session->handle, session_alloc_buffer, session_on_read);
    } else {
        uv_close((uv_handle_t *)&session->handle, session_close);
    }
}

void session_close(uv_handle_t *handle) {
    client_session_t *session = (client_session_t *)handle->data;
    if (session) {
        if (session->recv_buffer) {
            free(session->recv_buffer);
        }
        free(session);
        log_all(LOG_DEBUG, "Session resources cleaned up.");
    }
}