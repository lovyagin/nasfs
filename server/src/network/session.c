/**
 * @file session.c
 * @brief Client session management and protocol dispatcher.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS server.
 * Implements connection lifecycle, reading from TCP streams, buffering fragments,
 * parsing protocol frames, and dispatching to correct command handlers for
 * asynchronous PUT and GET file operations.
 */

#include "network/session.h"
#include "logging/log.h"
#include "config/config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#define INITIAL_RECV_BUFFER_SIZE 8192
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024) /* Max frame 64MB */
#define GET_CHUNK_SIZE (64 * 1024)

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

static void session_on_write(uv_write_t *req, int status) {
    if (status < 0) {
        log_all(LOG_ERROR, "Write error: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)req->data;
    if (buf) {
        if (buf->base) free(buf->base);
        free(buf);
    }
    free(req);
}

static void session_send_frame(client_session_t *session, nasfs_cmd_type_t cmd, const uint8_t *payload, size_t payload_len) {
    size_t frame_size;
    uint8_t *frame_data = protocol_pack_frame(cmd, payload, payload_len, &frame_size);
    if (!frame_data) return;

    uv_write_t *req = malloc(sizeof(uv_write_t));
    uv_buf_t *buf = malloc(sizeof(uv_buf_t));
    *buf = uv_buf_init((char *)frame_data, frame_size);
    req->data = buf;

    uv_write(req, (uv_stream_t *)&session->handle, buf, 1, session_on_write);
}

static void on_fs_open(uv_fs_t *req) {
    client_session_t *session = (client_session_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "Failed to open file: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Open failed", 11);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else {
        session->active_fd = (uv_file)req->result;
        session->file_offset = 0;
        log_all(LOG_INFO, "File opened successfully, sending PUT_ACK.");
        session_send_frame(session, NASFS_CMD_PUT_ACK, NULL, 0);
    }
    uv_fs_req_cleanup(req);
}

typedef struct {
    uv_fs_t fs_req;
    uv_buf_t buf;
} fs_write_ctx_t;

static void on_fs_write(uv_fs_t *req) {
    fs_write_ctx_t *ctx = (fs_write_ctx_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "Write error: %s", uv_strerror((int)req->result));
    }
    uv_fs_req_cleanup(req);
    free(ctx->buf.base);
    free(ctx);
}

static void on_fs_close(uv_fs_t *req) {
    uv_fs_req_cleanup(req);
}

/* GET Flow Forward Declarations */
static void on_get_fs_read(uv_fs_t *req);
static void do_get_read_chunk(client_session_t *session);

typedef struct {
    uv_write_t req;
    client_session_t *session;
    uv_buf_t buf;
} get_write_req_t;

static void on_get_write(uv_write_t *req, int status) {
    get_write_req_t *wr = (get_write_req_t *)req;
    if (status < 0) {
        log_all(LOG_ERROR, "Failed to write GET_DATA chunk to socket: %s", uv_strerror(status));
    } else if (wr->session->state == SESSION_STATE_SENDING_FILE && wr->session->active_fd > 0) {
        /* Continue reading the next chunk once the socket write finishes to prevent buffering too much in memory */
        do_get_read_chunk(wr->session);
    }
    
    if (wr->buf.base) {
        free(wr->buf.base);
    }
    free(wr);
}

static void do_get_read_chunk(client_session_t *session) {
    uv_buf_t iov;
    iov.base = malloc(GET_CHUNK_SIZE);
    iov.len = GET_CHUNK_SIZE;
    
    session->fs_req.data = session;
    uv_fs_read(session->handle.loop, &session->fs_req, session->active_fd, &iov, 1, session->file_offset, on_get_fs_read);
}

static void on_get_fs_read(uv_fs_t *req) {
    client_session_t *session = (client_session_t *)req->data;
    
    if (req->result < 0) {
        log_all(LOG_ERROR, "Read error during GET: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Read failed", 11);
        uv_fs_close(session->handle.loop, &session->fs_req, session->active_fd, on_fs_close);
        session->active_fd = 0;
        session->state = SESSION_STATE_AUTHENTICATED;
        free(req->bufs[0].base);
    } else if (req->result == 0) {
        /* EOF reached */
        log_all(LOG_INFO, "GET file read complete, sending GET_DONE.");
        session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0);
        uv_fs_close(session->handle.loop, &session->fs_req, session->active_fd, on_fs_close);
        session->active_fd = 0;
        session->state = SESSION_STATE_AUTHENTICATED;
        free(req->bufs[0].base);
    } else {
        /* Read successful, send data to client */
        size_t bytes_read = req->result;
        session->file_offset += bytes_read;
        
        size_t frame_size;
        uint8_t *frame_data = protocol_pack_frame(NASFS_CMD_GET_DATA, (uint8_t*)req->bufs[0].base, bytes_read, &frame_size);
        free(req->bufs[0].base); /* We copied the payload to the frame buffer */
        
        if (frame_data) {
            get_write_req_t *wr = malloc(sizeof(get_write_req_t));
            wr->session = session;
            wr->buf = uv_buf_init((char *)frame_data, frame_size);
            uv_write((uv_write_t*)&wr->req, (uv_stream_t*)&session->handle, &wr->buf, 1, on_get_write);
        } else {
            /* Fallback error if out of memory */
            uv_fs_close(session->handle.loop, &session->fs_req, session->active_fd, on_fs_close);
            session->active_fd = 0;
            session->state = SESSION_STATE_AUTHENTICATED;
        }
    }
    uv_fs_req_cleanup(req);
}

static void on_get_fs_open(uv_fs_t *req) {
    client_session_t *session = (client_session_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "Failed to open file for GET: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"File not found", 14);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else {
        session->active_fd = (uv_file)req->result;
        session->file_offset = 0;
        log_all(LOG_INFO, "File opened for GET successfully, sending GET_ACK and starting read.");
        session_send_frame(session, NASFS_CMD_GET_ACK, NULL, 0);
        
        /* Start reading and streaming the file */
        do_get_read_chunk(session);
    }
    uv_fs_req_cleanup(req);
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
            session_send_frame(session, NASFS_CMD_AUTH_ACK, NULL, 0);
            break;

        case NASFS_CMD_PUT_REQ: {
            if (session->state != SESSION_STATE_AUTHENTICATED) {
                log_all(LOG_WARNING, "PUT_REQ received in invalid state.");
                session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Invalid state", 13);
                break;
            }
            
            char raw_filename[256] = {0};
            size_t name_len = frame->payload_len < 255 ? frame->payload_len : 255;
            memcpy(raw_filename, frame->payload, name_len);

            /* Extract basename to prevent path traversal and missing directory issues */
            char *filename = strrchr(raw_filename, '/');
            if (filename) {
                filename++;
            } else {
                filename = raw_filename;
            }
            char *backslash = strrchr(filename, '\\');
            if (backslash) {
                filename = backslash + 1;
            }

            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", global_config.storage_dir ? global_config.storage_dir : ".", filename);

            log_all(LOG_INFO, "Opening file for PUT: %s", filepath);
            
            session->state = SESSION_STATE_RECEIVING_FILE;
            session->fs_req.data = session;
            uv_fs_open(session->handle.loop, &session->fs_req, filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644, on_fs_open);
            break;
        }

        case NASFS_CMD_PUT_DATA: {
            if (session->state != SESSION_STATE_RECEIVING_FILE || session->active_fd <= 0) {
                log_all(LOG_WARNING, "PUT_DATA received without active file.");
                break;
            }
            
            log_all(LOG_DEBUG, "Writing %zu bytes to file.", frame->payload_len);
            
            fs_write_ctx_t *ctx = malloc(sizeof(fs_write_ctx_t));
            ctx->buf.base = malloc(frame->payload_len);
            ctx->buf.len = frame->payload_len;
            memcpy(ctx->buf.base, frame->payload, frame->payload_len);
            ctx->fs_req.data = ctx;
            
            uv_fs_write(session->handle.loop, &ctx->fs_req, session->active_fd, &ctx->buf, 1, session->file_offset, on_fs_write);
            session->file_offset += frame->payload_len;
            break;
        }

        case NASFS_CMD_PUT_DONE: {
            if (session->state == SESSION_STATE_RECEIVING_FILE && session->active_fd > 0) {
                log_all(LOG_INFO, "File upload complete.");
                uv_fs_close(session->handle.loop, &session->fs_req, session->active_fd, on_fs_close);
                session->active_fd = 0;
                session->state = SESSION_STATE_AUTHENTICATED;
            }
            break;
        }

        case NASFS_CMD_GET_REQ: {
            if (session->state != SESSION_STATE_AUTHENTICATED) {
                log_all(LOG_WARNING, "GET_REQ received in invalid state.");
                session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Invalid state", 13);
                break;
            }
            
            char raw_filename[256] = {0};
            size_t name_len = frame->payload_len < 255 ? frame->payload_len : 255;
            memcpy(raw_filename, frame->payload, name_len);

            /* Extract basename to prevent path traversal and missing directory issues */
            char *filename = strrchr(raw_filename, '/');
            if (filename) {
                filename++;
            } else {
                filename = raw_filename;
            }
            char *backslash = strrchr(filename, '\\');
            if (backslash) {
                filename = backslash + 1;
            }

            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", global_config.storage_dir ? global_config.storage_dir : ".", filename);

            log_all(LOG_INFO, "Opening file for GET: %s", filepath);
            
            session->state = SESSION_STATE_SENDING_FILE;
            session->fs_req.data = session;
            uv_fs_open(session->handle.loop, &session->fs_req, filepath, O_RDONLY, 0, on_get_fs_open);
            break;
        }

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
    session->active_fd = 0;
    session->file_offset = 0;

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
        if (session->active_fd > 0) {
            uv_fs_t close_req;
            uv_fs_close(handle->loop, &close_req, session->active_fd, NULL);
            uv_fs_req_cleanup(&close_req);
        }
        if (session->recv_buffer) {
            free(session->recv_buffer);
        }
        free(session);
        log_all(LOG_DEBUG, "Session resources cleaned up.");
    }
}