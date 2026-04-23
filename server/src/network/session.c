/**
 * @file session.c
 * @brief Server-side session management with PQC handshake.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file implements the complete lifecycle for a client connection,
 * including the post-quantum key exchange (PQC KEX) handshake,
 * protocol frame dispatching, and asynchronous file I/O operations.
 */

#include "network/session.h"
#include "logging/log.h"
#include "config/config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <oqs/oqs.h>
#include <sodium.h>

#define INITIAL_RECV_BUFFER_SIZE 16384
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024)
#define IO_CHUNK_SIZE (64 * 1024)
#define KEM_ALGORITHM OQS_KEM_alg_kyber_512

/* --- Forward Declarations --- */
static void on_socket_write_done(uv_write_t *req, int status);
static void session_send_frame(client_session_t *session, nasfs_cmd_type_t type, const uint8_t *payload, size_t payload_len);
static void do_get_next_chunk(client_session_t *session);

/**
 * @brief Context for tracking asynchronous socket write operations.
 */
typedef struct {
    uv_write_t req;
    uv_buf_t buf;
    nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

/**
 * @brief Context for tracking asynchronous filesystem operations.
 */
typedef struct {
    uv_fs_t req;
    uv_buf_t buf;
    client_session_t *session;
} nasfs_fs_ctx_t;


/* --- Core Session Lifecycle --- */

/**
 * @brief Cleanup callback for when a libuv handle is fully closed.
 */
static void on_session_handle_closed(uv_handle_t *handle) {
    client_session_t *session = (client_session_t *)handle->data;
    if (session) {
        if (session->recv_buffer) free(session->recv_buffer);
        if (session->kem) OQS_KEM_free(session->kem);
        if (session->kem_secret_key) free(session->kem_secret_key);
        if (session->shared_secret) free(session->shared_secret);
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

/* --- Handshake & Protocol Logic --- */

static void session_dispatch_frame(client_session_t *session, nasfs_frame_t *frame);

/**
 * @brief libuv read callback for incoming socket data.
 */
static void session_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_session_t *session = (client_session_t *)stream->data;
    if (!session) return;
    (void)buf; // Buffer logic is managed in alloc_buffer

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
    session->is_secure = 0;
    session->recv_capacity = INITIAL_RECV_BUFFER_SIZE;
    session->recv_buffer = malloc(session->recv_capacity);

    if (uv_accept(server_stream, (uv_stream_t *)&session->handle) == 0) {
        log_all(LOG_INFO, "New client connected. Awaiting PQC handshake.");
        uv_read_start((uv_stream_t *)&session->handle, session_alloc_buffer, session_on_read);
    } else {
        session_close((uv_handle_t *)&session->handle);
    }
}


/* --- Handshake Implementation --- */

/**
 * @brief Dispatches a fully assembled protocol frame to the appropriate handler.
 */
static void session_dispatch_frame(client_session_t *session, nasfs_frame_t *frame) {
    /* Handle unencrypted handshake commands */
    if (!session->is_secure) {
        switch(frame->type) {
            case NASFS_CMD_PQC_HELLO:
                if (session->state != SESSION_STATE_NEW) return;
                log_all(LOG_INFO, "PQC_HELLO received, starting KEM.");

                session->kem = OQS_KEM_new(KEM_ALGORITHM);
                if (!session->kem) {
                    log_all(LOG_ERROR, "Failed to initialize KEM: %s", KEM_ALGORITHM);
                    session_close((uv_handle_t *)&session->handle);
                    return;
                }

                uint8_t *public_key = malloc(session->kem->length_public_key);
                session->kem_secret_key = malloc(session->kem->length_secret_key);
                if (!public_key || !session->kem_secret_key) {
                    free(public_key);
                    session_close((uv_handle_t *)&session->handle);
                    return;
                }

                if (OQS_KEM_keypair(session->kem, public_key, session->kem_secret_key) != OQS_SUCCESS) {
                    log_all(LOG_ERROR, "Failed to generate KEM keypair.");
                    free(public_key);
                    session_close((uv_handle_t *)&session->handle);
                    return;
                }
                
                log_all(LOG_DEBUG, "Generated Kyber keypair, sending public key.");
                session_send_frame(session, NASFS_CMD_PQC_PUBLIC_KEY, public_key, session->kem->length_public_key);
                session->state = SESSION_STATE_HANDSHAKE;
                free(public_key);
                return;

            case NASFS_CMD_PQC_CIPHERTEXT:
                if (session->state != SESSION_STATE_HANDSHAKE) return;

                session->shared_secret = malloc(session->kem->length_shared_secret);
                if (!session->shared_secret) {
                    session_close((uv_handle_t *)&session->handle);
                    return;
                }

                if (OQS_KEM_decaps(session->kem, session->shared_secret, frame->payload, session->kem_secret_key) != OQS_SUCCESS) {
                    log_all(LOG_ERROR, "Failed to decapsulate shared secret.");
                    session_close((uv_handle_t *)&session->handle);
                    return;
                }

                log_all(LOG_INFO, "PQC Handshake successful. Channel is now secure.");
                session->is_secure = 1;
                session->state = SESSION_STATE_AUTHENTICATED;

                /* --- HASH TEST --- */
                unsigned char hash[crypto_hash_sha256_BYTES];
                crypto_hash_sha256(hash, session->shared_secret, session->kem->length_shared_secret);
                char hex_hash[crypto_hash_sha256_BYTES * 2 + 1];
                sodium_bin2hex(hex_hash, sizeof(hex_hash), hash, sizeof(hash));
                log_all(LOG_INFO, "Handshake test: Shared secret hash = %s", hex_hash);
                /* --- END HASH TEST --- */

                // Secret key is no longer needed, free it.
                OQS_KEM_free(session->kem);
                session->kem = NULL;
                free(session->kem_secret_key);
                session->kem_secret_key = NULL;
                return;

            default:
                log_all(LOG_WARNING, "Received unencrypted command 0x%02X before handshake. Closing.", frame->type);
                session_close((uv_handle_t *)&session->handle);
                return;
        }
    }
    
    /* TODO: Handle encrypted commands here (Kommit 4) */
}