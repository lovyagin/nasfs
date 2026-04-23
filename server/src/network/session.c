/**
 * @file session.c
 * @brief Stable implementation of NASFS server session and async I/O.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file provides robust, asynchronous handling of client sessions,
 * including binary protocol parsing and high-performance file transfers
 * using libuv and state-machine transitions.
 */

#include "network/session.h"
#include "logging/log.h"
#include "config/config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#define INITIAL_RECV_BUFFER_SIZE 16384
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024)
#define IO_CHUNK_SIZE (64 * 1024)

/**
 * @struct nasfs_write_ctx_t
 * @brief Context for tracking asynchronous socket write operations.
 */
typedef struct {
    uv_write_t req;
    uv_buf_t buf;
    nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

/**
 * @struct nasfs_fs_ctx_t
 * @brief Context for tracking asynchronous filesystem operations.
 */
typedef struct {
    uv_fs_t req;
    uv_buf_t buf;
    client_session_t *session;
} nasfs_fs_ctx_t;

/* Forward declarations */
static void do_get_next_chunk(client_session_t *session);

/**
 * @brief Cleanup callback for when a libuv handle is fully closed.
 */
static void on_session_handle_closed(uv_handle_t *handle) {
    client_session_t *session = (client_session_t *)handle->data;
    if (session) {
        if (session->recv_buffer) free(session->recv_buffer);
        free(session);
        log_all(LOG_DEBUG, "Session resources deallocated.");
    }
}

/**
 * @brief Triggers session teardown and ensures file descriptors are released.
 */
void session_close(uv_handle_t *handle) {
    client_session_t *session = (client_session_t *)handle->data;
    if (!session || session->state == SESSION_STATE_ERROR) return;

    session->state = SESSION_STATE_ERROR;
    log_all(LOG_INFO, "Closing session for client.");

    if (session->active_fd != -1) {
        uv_fs_t close_req;
        uv_fs_close(handle->loop, &close_req, session->active_fd, NULL);
        uv_fs_req_cleanup(&close_req);
        session->active_fd = -1;
    }

    if (!uv_is_closing(handle)) {
        uv_close(handle, on_session_handle_closed);
    }
}

/**
 * @brief Shared callback for completion of socket write operations.
 */
static void on_socket_write_done(uv_write_t *req, int status) {
    nasfs_write_ctx_t *ctx = (nasfs_write_ctx_t *)req;
    client_session_t *session = (client_session_t *)req->handle->data;

    if (status < 0) {
        log_all(LOG_ERROR, "Socket write failed: %s", uv_strerror(status));
    } else if (session && session->state == SESSION_STATE_SENDING_FILE && ctx->type == NASFS_CMD_GET_DATA) {
        /* Backpressure: Read next chunk only after the current one is sent */
        do_get_next_chunk(session);
    }

    if (ctx->buf.base) free(ctx->buf.base);
    free(ctx);
}

/**
 * @brief Packs and sends a protocol frame to the client.
 */
static void session_send_frame(client_session_t *session, nasfs_cmd_type_t type, const uint8_t *payload, size_t payload_len) {
    size_t frame_size = 0;
    uint8_t *frame_data = protocol_pack_frame(type, payload, payload_len, &frame_size);
    if (!frame_data) return;

    nasfs_write_ctx_t *ctx = malloc(sizeof(nasfs_write_ctx_t));
    if (!ctx) {
        free(frame_data);
        return;
    }

    ctx->buf = uv_buf_init((char *)frame_data, frame_size);
    ctx->type = type;
    int r = uv_write(&ctx->req, (uv_stream_t *)&session->handle, &ctx->buf, 1, on_socket_write_done);
    if (r < 0) {
        free(frame_data);
        free(ctx);
    }
}

/**
 * @brief Extracts the basename from a client-provided path to prevent traversal.
 */
static const char *sanitize_path(const char *path) {
    const char *base = strrchr(path, '/');
    if (!base) base = strrchr(path, '\\');
    return base ? base + 1 : path;
}

/* --- PUT Flow (Client -> Server) --- */

static void on_put_fs_write(uv_fs_t *req) {
    nasfs_fs_ctx_t *ctx = (nasfs_fs_ctx_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "PUT: Write error: %s", uv_strerror((int)req->result));
    }
    if (ctx->buf.base) free(ctx->buf.base);
    uv_fs_req_cleanup(req);
    free(ctx);
}

static void on_put_fs_open(uv_fs_t *req) {
    client_session_t *session = (client_session_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "PUT: Open failed: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Open failed", 11);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else {
        session->active_fd = (uv_file)req->result;
        session->file_offset = 0;
        session_send_frame(session, NASFS_CMD_PUT_ACK, NULL, 0);
    }
    uv_fs_req_cleanup(req);
}

/* --- GET Flow (Server -> Client) --- */

static void on_get_fs_read(uv_fs_t *req) {
    nasfs_fs_ctx_t *ctx = (nasfs_fs_ctx_t *)req->data;
    client_session_t *session = ctx->session;

    if (req->result < 0) {
        log_all(LOG_ERROR, "GET: Read failed: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Read failed", 11);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else if (req->result == 0) {
        /* EOF */
        session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0);
        session->state = SESSION_STATE_AUTHENTICATED;
        if (session->active_fd != -1) {
            uv_fs_t close_req;
            uv_fs_close(session->handle.loop, &close_req, session->active_fd, NULL);
            uv_fs_req_cleanup(&close_req);
            session->active_fd = -1;
        }
    } else {
        /* Success, stream to socket */
        size_t bytes = req->result;
        session->file_offset += bytes;
        session_send_frame(session, NASFS_CMD_GET_DATA, (uint8_t *)ctx->buf.base, bytes);
    }

    if (ctx->buf.base) free(ctx->buf.base);
    uv_fs_req_cleanup(req);
    free(ctx);
}

static void do_get_next_chunk(client_session_t *session) {
    if (session->state != SESSION_STATE_SENDING_FILE || session->active_fd == -1) return;

    nasfs_fs_ctx_t *ctx = malloc(sizeof(nasfs_fs_ctx_t));
    if (!ctx) return;

    ctx->buf = uv_buf_init(malloc(IO_CHUNK_SIZE), IO_CHUNK_SIZE);
    ctx->session = session;
    ctx->req.data = ctx;

    int r = uv_fs_read(session->handle.loop, &ctx->req, session->active_fd, &ctx->buf, 1, session->file_offset, on_get_fs_read);
    if (r < 0) {
        free(ctx->buf.base);
        free(ctx);
    }
}

static void on_get_fs_open(uv_fs_t *req) {
    client_session_t *session = (client_session_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "GET: Open failed: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"File not found", 14);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else {
        session->active_fd = (uv_file)req->result;
        session->file_offset = 0;
        session_send_frame(session, NASFS_CMD_GET_ACK, NULL, 0);
        /* Trigger the read loop */
        do_get_next_chunk(session);
    }
    uv_fs_req_cleanup(req);
}

/**
 * @brief Dispatches a fully assembled protocol frame to the appropriate handler.
 */
static void session_dispatch_frame(client_session_t *session, nasfs_frame_t *frame) {
    switch (frame->type) {
        case NASFS_CMD_AUTH:
            log_all(LOG_INFO, "Client authenticated.");
            session->state = SESSION_STATE_AUTHENTICATED;
            session_send_frame(session, NASFS_CMD_AUTH_ACK, NULL, 0);
            break;

        case NASFS_CMD_PUT_REQ: {
            char raw[256] = {0};
            memcpy(raw, frame->payload, frame->payload_len < 255 ? frame->payload_len : 255);
            const char *filename = sanitize_path(raw);
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", global_config.storage_dir ? global_config.storage_dir : ".", filename);
            log_all(LOG_INFO, "Opening file for upload: %s", path);
            session->state = SESSION_STATE_RECEIVING_FILE;
            session->fs_req.data = session;
            uv_fs_open(session->handle.loop, &session->fs_req, path, O_WRONLY | O_CREAT | O_TRUNC, 0644, on_put_fs_open);
            break;
        }

        case NASFS_CMD_PUT_DATA: {
            if (session->state == SESSION_STATE_RECEIVING_FILE && session->active_fd != -1) {
                nasfs_fs_ctx_t *ctx = malloc(sizeof(nasfs_fs_ctx_t));
                if (ctx) {
                    ctx->buf = uv_buf_init(malloc(frame->payload_len), frame->payload_len);
                    memcpy(ctx->buf.base, frame->payload, frame->payload_len);
                    ctx->req.data = ctx;
                    uv_fs_write(session->handle.loop, &ctx->req, session->active_fd, &ctx->buf, 1, session->file_offset, on_put_fs_write);
                    session->file_offset += frame->payload_len;
                }
            }
            break;
        }

        case NASFS_CMD_PUT_DONE:
            if (session->state == SESSION_STATE_RECEIVING_FILE) {
                log_all(LOG_INFO, "Upload complete.");
                if (session->active_fd != -1) {
                    uv_fs_t close_req;
                    uv_fs_close(session->handle.loop, &close_req, session->active_fd, NULL);
                    uv_fs_req_cleanup(&close_req);
                    session->active_fd = -1;
                }
                session->state = SESSION_STATE_AUTHENTICATED;
            }
            break;

        case NASFS_CMD_GET_REQ: {
            char raw[256] = {0};
            memcpy(raw, frame->payload, frame->payload_len < 255 ? frame->payload_len : 255);
            const char *filename = sanitize_path(raw);
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", global_config.storage_dir ? global_config.storage_dir : ".", filename);
            log_all(LOG_INFO, "Opening file for download: %s", path);
            session->state = SESSION_STATE_SENDING_FILE;
            session->fs_req.data = session;
            uv_fs_open(session->handle.loop, &session->fs_req, path, O_RDONLY, 0, on_get_fs_open);
            break;
        }

        default:
            log_all(LOG_WARNING, "Received unsupported command type: 0x%02X", frame->type);
            break;
    }
}

/**
 * @brief libuv allocation callback for managing session receive buffer.
 */
static void session_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    client_session_t *session = (client_session_t *)handle->data;
    if (!session) { buf->base = NULL; buf->len = 0; return; }

    if (session->recv_capacity - session->recv_length < suggested_size) {
        size_t new_cap = session->recv_capacity == 0 ? INITIAL_RECV_BUFFER_SIZE : session->recv_capacity * 2;
        while (new_cap - session->recv_length < suggested_size) new_cap *= 2;
        if (new_cap > MAX_RECV_BUFFER_SIZE) { session_close(handle); buf->base = NULL; buf->len = 0; return; }
        uint8_t *new_buf = realloc(session->recv_buffer, new_cap);
        if (!new_buf) { session_close(handle); buf->base = NULL; buf->len = 0; return; }
        session->recv_buffer = new_buf;
        session->recv_capacity = new_cap;
    }
    buf->base = (char *)(session->recv_buffer + session->recv_length);
    buf->len = session->recv_capacity - session->recv_length;
}

/**
 * @brief libuv read callback for incoming socket data.
 */
static void session_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_session_t *session = (client_session_t *)stream->data;
    if (!session) return;

    if (nread > 0) {
        session->recv_length += nread;
        while (session->recv_length > 0) {
            nasfs_frame_t frame;
            int consumed = protocol_parse_frame(session->recv_buffer, session->recv_length, &frame);
            if (consumed > 0) {
                session_dispatch_frame(session, &frame);
                size_t remaining = session->recv_length - consumed;
                if (remaining > 0) memmove(session->recv_buffer, session->recv_buffer + consumed, remaining);
                session->recv_length = remaining;
            } else {
                if (consumed < 0) session_close((uv_handle_t *)stream);
                break;
            }
        }
    } else if (nread < 0) {
        session_close((uv_handle_t *)stream);
    }
}

/**
 * @brief Accepts a new client connection and initializes the session structure.
 */
void session_on_new_connection(uv_stream_t *server_stream, int status) {
    if (status < 0) return;

    client_session_t *session = calloc(1, sizeof(client_session_t));
    if (!session) return;

    uv_tcp_init(server_stream->loop, &session->handle);
    session->handle.data = session;
    session->state = SESSION_STATE_NEW;
    session->active_fd = -1;
    session->recv_capacity = INITIAL_RECV_BUFFER_SIZE;
    session->recv_buffer = malloc(session->recv_capacity);

    if (uv_accept(server_stream, (uv_stream_t *)&session->handle) == 0) {
        log_all(LOG_INFO, "New client connected.");
        uv_read_start((uv_stream_t *)&session->handle, session_alloc_buffer, session_on_read);
    } else {
        session_close((uv_handle_t *)&session->handle);
    }
}