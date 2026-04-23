/**
 * @file session.c
 * @brief Server-side session management with PQC handshake and encrypted channel.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file implements the complete lifecycle for a client connection,
 * including the post-quantum key exchange (PQC KEX) handshake,
 * protocol frame dispatching, and asynchronous file I/O operations.
 * Control commands are encrypted using libsodium's secretstream API,
 * while bulk data is transferred unencrypted for performance.
 */

#include "network/session.h"
#include "logging/log.h"
#include "config/config.h"
#include "handshake.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include <oqs/oqs.h>
#include <sodium.h>

#define INITIAL_RECV_BUFFER_SIZE 16384
#define MAX_RECV_BUFFER_SIZE (64 * 1024 * 1024)
#define IO_CHUNK_SIZE (64 * 1024)
/* --- Context Structs for Async Operations --- */
typedef struct {
    uv_write_t req;
    uv_buf_t buf;
    nasfs_cmd_type_t type;
} nasfs_write_ctx_t;

typedef struct {
    uv_fs_t req;
    uv_buf_t buf;
    client_session_t *session;
} nasfs_fs_ctx_t;


/* --- Forward Declarations --- */
static void session_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void session_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void on_socket_write_done(uv_write_t *req, int status);
static void session_send_frame(client_session_t *session, nasfs_cmd_type_t type, const uint8_t *payload, size_t payload_len, int encrypt);
static void do_get_next_chunk(client_session_t *session);
static void session_dispatch_frame(client_session_t *session, nasfs_frame_t *frame);

/**
 * @brief Checks whether a comma-separated list contains a given token.
 *
 * @param csv_list Comma-separated list to search.
 * @param candidate Candidate token to match.
 * @return 1 if the token exists in the list, otherwise 0.
 */
static int csv_list_contains(const char *csv_list, const char *candidate) {
    const char *cursor;
    size_t candidate_len;

    if (!csv_list || !candidate) {
        return 0;
    }

    candidate_len = strlen(candidate);
    cursor = csv_list;

    while (*cursor != '\0') {
        const char *start = cursor;
        const char *end;

        while (*start != '\0' && isspace((unsigned char)*start)) {
            start++;
        }

        end = start;
        while (*end != '\0' && *end != ',') {
            end++;
        }

        while (end > start && isspace((unsigned char)end[-1])) {
            end--;
        }

        if ((size_t)(end - start) == candidate_len && strncmp(start, candidate, candidate_len) == 0) {
            return 1;
        }

        cursor = (*end == ',') ? end + 1 : end;
    }

    return 0;
}

/**
 * @brief Selects the first mutually supported and enabled KEX algorithm.
 *
 * The client preference order wins, while the server configuration constrains
 * the admissible algorithms.
 *
 * @param client_kex_list Client-supplied KEX preference list.
 * @param server_kex_list Server-configured KEX allow-list.
 * @return Newly allocated selected KEX identifier, or NULL if none match.
 */
static char *select_kex_algorithm(const char *client_kex_list, const char *server_kex_list) {
    const char *cursor;

    if (!client_kex_list || !server_kex_list) {
        return NULL;
    }

    cursor = client_kex_list;
    while (*cursor != '\0') {
        const char *start = cursor;
        const char *end;
        size_t len;
        char *candidate;

        while (*start != '\0' && isspace((unsigned char)*start)) {
            start++;
        }

        end = start;
        while (*end != '\0' && *end != ',') {
            end++;
        }

        while (end > start && isspace((unsigned char)end[-1])) {
            end--;
        }

        len = (size_t)(end - start);
        if (len > 0) {
            candidate = malloc(len + 1);
            if (!candidate) {
                return NULL;
            }
            memcpy(candidate, start, len);
            candidate[len] = '\0';

            if (csv_list_contains(server_kex_list, candidate) && OQS_KEM_alg_is_enabled(candidate)) {
                return candidate;
            }
            free(candidate);
        }

        cursor = (*end == ',') ? end + 1 : end;
    }

    return NULL;
}

/**
 * @brief Selects the first mutually supported control-channel cipher.
 *
 * @param client_cipher_list Client-supplied cipher preference list.
 * @param server_cipher_list Server-configured cipher allow-list.
 * @return Newly allocated selected cipher identifier, or NULL if none match.
 */
static char *select_cipher_algorithm(const char *client_cipher_list, const char *server_cipher_list) {
    if (csv_list_contains(client_cipher_list, NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) &&
        csv_list_contains(server_cipher_list, NASFS_CONTROL_CIPHER_XCHACHA20POLY1305)) {
        return strdup(NASFS_CONTROL_CIPHER_XCHACHA20POLY1305);
    }

    return NULL;
}


/* --- Core Session Lifecycle --- */

static void on_session_handle_closed(uv_handle_t *handle) {
    client_session_t *session = (client_session_t *)handle->data;
    if (session) {
        if (session->recv_buffer) free(session->recv_buffer);
        if (session->kem) OQS_KEM_free(session->kem);
        if (session->kem_secret_key) free(session->kem_secret_key);
        if (session->shared_secret) {
            sodium_free(session->shared_secret);
        }
        if (session->kex_algorithm) free(session->kex_algorithm);
        if (session->cipher_algorithm) free(session->cipher_algorithm);
        free(session);
        log_all(LOG_DEBUG, "Session resources deallocated.");
    }
}

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


/* --- Protocol & Crypto Implementation --- */

static void session_send_frame(client_session_t *session, nasfs_cmd_type_t type, const uint8_t *payload, size_t payload_len, int encrypt) {
    uint8_t *payload_to_pack = (uint8_t *)payload;
    size_t payload_to_pack_len = payload_len;
    uint8_t *encrypted_payload = NULL;

    if (encrypt && session->is_secure) {
        payload_to_pack_len = payload_len + crypto_secretstream_xchacha20poly1305_ABYTES;
        encrypted_payload = malloc(payload_to_pack_len);
        if (!encrypted_payload) return;

        crypto_secretstream_xchacha20poly1305_push(&session->send_crypto_state, encrypted_payload, NULL, payload, payload_len, NULL, 0, 0);
        payload_to_pack = encrypted_payload;
    }

    size_t frame_size;
    uint8_t *frame_data = protocol_pack_frame(type, payload_to_pack, payload_to_pack_len, &frame_size);
    if (encrypted_payload) free(encrypted_payload);
    if (!frame_data) return;

    nasfs_write_ctx_t *ctx = malloc(sizeof(nasfs_write_ctx_t));
    if (!ctx) { free(frame_data); return; }

    ctx->buf = uv_buf_init((char *)frame_data, frame_size);
    ctx->type = type;
    if (uv_write(&ctx->req, (uv_stream_t *)&session->handle, &ctx->buf, 1, on_socket_write_done) < 0) {
        free(frame_data);
        free(ctx);
    }
}

static const char *sanitize_path(const char *path) {
    const char *base = strrchr(path, '/');
    if (!base) base = strrchr(path, '\\');
    return base ? base + 1 : path;
}


/* --- File I/O Callbacks --- */

static void on_put_fs_write(uv_fs_t *req) {
    nasfs_fs_ctx_t *ctx = (nasfs_fs_ctx_t *)req->data;
    if (req->result < 0) log_all(LOG_ERROR, "PUT: Write error: %s", uv_strerror((int)req->result));
    if (ctx->buf.base) free(ctx->buf.base);
    uv_fs_req_cleanup(req);
    free(ctx);
}

static void on_put_fs_open(uv_fs_t *req) {
    client_session_t *session = (client_session_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "PUT: Open failed: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Open failed", 11, 1);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else {
        session->active_fd = (uv_file)req->result;
        session->file_offset = 0;
        session_send_frame(session, NASFS_CMD_PUT_ACK, NULL, 0, 1);
    }
    uv_fs_req_cleanup(req);
}

static void on_get_fs_read(uv_fs_t *req) {
    nasfs_fs_ctx_t *ctx = (nasfs_fs_ctx_t *)req->data;
    client_session_t *session = ctx->session;

    if (req->result < 0) {
        log_all(LOG_ERROR, "GET: Read failed: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"Read failed", 11, 1);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else if (req->result == 0) { // EOF
        session_send_frame(session, NASFS_CMD_GET_DONE, NULL, 0, 1);
        session->state = SESSION_STATE_AUTHENTICATED;
        if (session->active_fd != -1) {
            uv_fs_close(session->handle.loop, &(uv_fs_t){}, session->active_fd, NULL);
            session->active_fd = -1;
        }
    } else {
        size_t bytes = req->result;
        session->file_offset += bytes;
        session_send_frame(session, NASFS_CMD_GET_DATA, (uint8_t *)ctx->buf.base, bytes, 0);
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
    if (uv_fs_read(session->handle.loop, &ctx->req, session->active_fd, &ctx->buf, 1, session->file_offset, on_get_fs_read) < 0) {
        free(ctx->buf.base);
        free(ctx);
    }
}

static void on_get_fs_open(uv_fs_t *req) {
    client_session_t *session = (client_session_t *)req->data;
    if (req->result < 0) {
        log_all(LOG_ERROR, "GET: Open failed: %s", uv_strerror((int)req->result));
        session_send_frame(session, NASFS_CMD_ERROR, (const uint8_t *)"File not found", 14, 1);
        session->state = SESSION_STATE_AUTHENTICATED;
    } else {
        session->active_fd = (uv_file)req->result;
        session->file_offset = 0;
        session_send_frame(session, NASFS_CMD_GET_ACK, NULL, 0, 1);
        do_get_next_chunk(session);
    }
    uv_fs_req_cleanup(req);
}


/* --- Main Dispatcher & Network Callbacks --- */

static void session_dispatch_frame(client_session_t *session, nasfs_frame_t *frame) {
    /* Handle unencrypted handshake commands */
    if (!session->is_secure) {
        switch(frame->type) {
            case NASFS_CMD_PQC_HELLO:
                if (session->state != SESSION_STATE_NEW) return;
                {
                    char *client_kex_list = NULL;
                    char *client_cipher_list = NULL;
                    uint8_t *pk = NULL;
                    uint8_t *selection_payload = NULL;
                    size_t selection_payload_len = 0;

                    if (nasfs_handshake_unpack_client_hello(frame->payload,
                                                            frame->payload_len,
                                                            &client_kex_list,
                                                            &client_cipher_list) != 0) {
                        session_close((uv_handle_t *)&session->handle);
                        return;
                    }

                    session->kex_algorithm = select_kex_algorithm(client_kex_list, global_config.kex_algorithms);
                    session->cipher_algorithm = select_cipher_algorithm(client_cipher_list, global_config.cipher_algorithms);
                    free(client_kex_list);
                    free(client_cipher_list);

                    if (!session->kex_algorithm || !session->cipher_algorithm) {
                        log_all(LOG_WARNING, "Handshake failed: no compatible algorithm suite.");
                        session_send_frame(session,
                                           NASFS_CMD_ERROR,
                                           (const uint8_t *)"No compatible KEX/cipher suite",
                                           strlen("No compatible KEX/cipher suite"),
                                           0);
                        session_close((uv_handle_t *)&session->handle);
                        return;
                    }

                    session->kem = OQS_KEM_new(session->kex_algorithm);
                    if (!session->kem) {
                        session_close((uv_handle_t *)&session->handle);
                        return;
                    }

                    pk = malloc(session->kem->length_public_key);
                    session->kem_secret_key = malloc(session->kem->length_secret_key);
                    if (!pk || !session->kem_secret_key ||
                        OQS_KEM_keypair(session->kem, pk, session->kem_secret_key) != OQS_SUCCESS) {
                        free(pk);
                        session_close((uv_handle_t *)&session->handle);
                        return;
                    }

                    selection_payload = nasfs_handshake_pack_server_selection(session->kex_algorithm,
                                                                              session->cipher_algorithm,
                                                                              pk,
                                                                              session->kem->length_public_key,
                                                                              &selection_payload_len);
                    free(pk);
                    if (!selection_payload) {
                        session_close((uv_handle_t *)&session->handle);
                        return;
                    }

                    session_send_frame(session,
                                       NASFS_CMD_PQC_PUBLIC_KEY,
                                       selection_payload,
                                       selection_payload_len,
                                       0);
                    free(selection_payload);
                    log_all(LOG_INFO,
                            "Negotiated KEX: %s; control cipher: %s",
                            session->kex_algorithm,
                            session->cipher_algorithm);
                    session->state = SESSION_STATE_HANDSHAKE;
                }
                return;

            case NASFS_CMD_PQC_CIPHERTEXT:
                if (session->state != SESSION_STATE_HANDSHAKE) return;
                if (frame->payload_len < session->kem->length_ciphertext + crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
                    session_close((uv_handle_t *)&session->handle);
                    return;
                }

                session->shared_secret = sodium_malloc(session->kem->length_shared_secret);
                if (!session->shared_secret ||
                    OQS_KEM_decaps(session->kem, session->shared_secret, frame->payload, session->kem_secret_key) != OQS_SUCCESS) {
                    session_close((uv_handle_t *)&session->handle); return;
                }

                {
                    const uint8_t *client_header = frame->payload + session->kem->length_ciphertext;
                    uint8_t server_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

                    if (crypto_secretstream_xchacha20poly1305_init_pull(&session->recv_crypto_state, client_header, session->shared_secret) != 0 ||
                        crypto_secretstream_xchacha20poly1305_init_push(&session->send_crypto_state, server_header, session->shared_secret) != 0) {
                        session_close((uv_handle_t *)&session->handle);
                        return;
                    }

                    log_all(LOG_INFO, "PQC Handshake successful. Channel is now secure.");
                    session->is_secure = 1;
                    session->state = SESSION_STATE_AUTHENTICATED;
                    OQS_KEM_free(session->kem); session->kem = NULL;
                    free(session->kem_secret_key); session->kem_secret_key = NULL;
                    session_send_frame(session, NASFS_CMD_SECURE_READY, server_header, sizeof(server_header), 0);
                }
                return;

            default:
                session_close((uv_handle_t *)&session->handle);
                return;
        }
    }

    /* Handle encrypted and unencrypted commands post-handshake */
    unsigned long long decrypted_len;
    nasfs_frame_t plain_frame = *frame;
    unsigned char *decrypted_payload = NULL;

    if (frame->type >= 0x10 && frame->type < 0x20) { // Encrypted command range
        decrypted_payload = malloc(frame->payload_len);
        if (!decrypted_payload) {
            session_close((uv_handle_t *)&session->handle);
            return;
        }
        if (crypto_secretstream_xchacha20poly1305_pull(&session->recv_crypto_state, decrypted_payload, &decrypted_len, NULL, frame->payload, frame->payload_len, NULL, 0) != 0) {
            free(decrypted_payload);
            log_all(LOG_ERROR, "Corrupted encrypted frame received. Closing.");
            session_close((uv_handle_t *)&session->handle);
            return;
        }
        plain_frame.payload = decrypted_payload;
        plain_frame.payload_len = decrypted_len;
    }
    
    switch (plain_frame.type) {
        case NASFS_CMD_AUTH:
            log_all(LOG_INFO, "Client authenticated.");
            session->state = SESSION_STATE_AUTHENTICATED;
            session_send_frame(session, NASFS_CMD_AUTH_ACK, NULL, 0, 1);
            break;

        case NASFS_CMD_PUT_REQ: {
            char raw[256] = {0};
            memcpy(raw, plain_frame.payload, plain_frame.payload_len < 255 ? plain_frame.payload_len : 255);
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", global_config.storage_dir ? global_config.storage_dir : ".", sanitize_path(raw));
            session->state = SESSION_STATE_RECEIVING_FILE;
            session->fs_req.data = session;
            uv_fs_open(session->handle.loop, &session->fs_req, path, O_WRONLY | O_CREAT | O_TRUNC, 0644, on_put_fs_open);
            break;
        }

        case NASFS_CMD_PUT_DATA: { // Unencrypted
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
                    uv_fs_close(session->handle.loop, &(uv_fs_t){}, session->active_fd, NULL);
                    session->active_fd = -1;
                }
                session->state = SESSION_STATE_AUTHENTICATED;
            }
            break;

        case NASFS_CMD_GET_REQ: {
            char raw[256] = {0};
            memcpy(raw, plain_frame.payload, plain_frame.payload_len < 255 ? plain_frame.payload_len : 255);
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", global_config.storage_dir ? global_config.storage_dir : ".", sanitize_path(raw));
            session->state = SESSION_STATE_SENDING_FILE;
            session->fs_req.data = session;
            uv_fs_open(session->handle.loop, &session->fs_req, path, O_RDONLY, 0, on_get_fs_open);
            break;
        }
        default: break;
    }

    if (decrypted_payload) free(decrypted_payload);
}

static void on_socket_write_done(uv_write_t *req, int status) {
    nasfs_write_ctx_t *ctx = (nasfs_write_ctx_t *)req;
    client_session_t *session = (client_session_t *)req->handle->data;
    if (status < 0) log_all(LOG_ERROR, "Socket write failed: %s", uv_strerror(status));
    else if (session && session->state == SESSION_STATE_SENDING_FILE && ctx->type == NASFS_CMD_GET_DATA) {
        do_get_next_chunk(session);
    }
    if (ctx->buf.base) free(ctx->buf.base);
    free(ctx);
}

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

static void session_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_session_t *session = (client_session_t *)stream->data;
    (void)buf;

    if (!session) {
        return;
    }

    if (nread > 0) {
        session->recv_length += (size_t)nread;

        while (session->recv_length > 0) {
            nasfs_frame_t frame;
            int consumed = protocol_parse_frame(session->recv_buffer, session->recv_length, &frame);
            if (consumed > 0) {
                session_dispatch_frame(session, &frame);
                if (session->state == SESSION_STATE_ERROR) {
                    return;
                }
                memmove(session->recv_buffer, session->recv_buffer + consumed, session->recv_length - (size_t)consumed);
                session->recv_length -= (size_t)consumed;
            } else {
                if (consumed < 0) {
                    session_close((uv_handle_t *)&session->handle);
                }
                break;
            }
        }
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            log_all(LOG_ERROR, "Read error: %s", uv_strerror((int)nread));
        }
        session_close((uv_handle_t *)&session->handle);
    }
}

void session_on_new_connection(uv_stream_t *server, int status) {
    client_session_t *session;

    if (status < 0) {
        log_all(LOG_ERROR, "New connection error: %s", uv_strerror(status));
        return;
    }

    session = calloc(1, sizeof(*session));
    if (!session) {
        log_all(LOG_ERROR, "Failed to allocate session context.");
        return;
    }

    session->state = SESSION_STATE_NEW;
    session->active_fd = -1;

    if (uv_tcp_init(server->loop, &session->handle) != 0) {
        free(session);
        return;
    }

    session->handle.data = session;
    if (uv_accept(server, (uv_stream_t *)&session->handle) != 0) {
        uv_close((uv_handle_t *)&session->handle, on_session_handle_closed);
        return;
    }

    log_all(LOG_INFO, "Accepted new client connection.");
    if (uv_read_start((uv_stream_t *)&session->handle, session_alloc_buffer, session_on_read) != 0) {
        session_close((uv_handle_t *)&session->handle);
    }
}
