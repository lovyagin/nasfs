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

#include <oqs/oqs.h>
#include <pthread.h>
#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <uv.h>

#include "crypto_engine.h"
#include "pake.h"
#include "protocol.h"

/**
 * @enum session_state_t
 * @brief Defines the current operational state of a client session.
 */
typedef enum {
  SESSION_STATE_NEW = 0,        /**< Newly connected, connection established. */
  SESSION_STATE_HANDSHAKE,      /**< PQC key exchange in progress. */
  SESSION_STATE_AUTHENTICATED,  /**< Authenticated, waiting for commands. */
  SESSION_STATE_RECEIVING_FILE, /**< Currently receiving file data (PUT). */
  SESSION_STATE_SENDING_FILE,   /**< Currently sending file data (GET). */
  SESSION_STATE_ERROR           /**< Terminal error state, pending closure. */
} session_state_t;

/**
 * @struct client_session_t
 * @brief Context and state for an active client connection.
 */
typedef struct {
  uv_tcp_t handle;       /**< libuv TCP handle for the connection. */
  session_state_t state; /**< Current state of the session. */

  /* Receive Buffer */
  uint8_t* recv_buffer; /**< Buffer for accumulating incomplete TCP frames. */
  size_t recv_length;   /**< Current number of bytes in the receive buffer. */
  size_t recv_capacity; /**< Total allocated capacity of the receive buffer. */

  /* File Transfer State */
  uv_file active_fd;    /**< File descriptor for active transfers (PUT/GET). */
  uv_fs_t fs_req;       /**< Filesystem request handle for async operations. */
  uint64_t file_offset; /**< Current offset in the active file. */

  /* Crypto State */
  OQS_KEM* kem;            /**< OQS Key Encapsulation Mechanism instance. */
  uint8_t* kem_secret_key; /**< The server's secret key for this session. */
  uint8_t*
      shared_secret; /**< The derived shared secret for symmetric crypto. */
  size_t shared_secret_len; /**< Length of @p shared_secret. */
  char* kex_algorithm;      /**< Negotiated KEX algorithm for this session. */
  char* cipher_algorithm;   /**< Negotiated control-channel cipher for this
                               session. */
  int is_secure;            /**< Flag indicating if the channel is encrypted. */
  int is_authenticated;     /**< Flag indicating successful user auth. */
  crypto_secretstream_xchacha20poly1305_state
      send_crypto_state; /**< Server->client control channel state. */
  crypto_secretstream_xchacha20poly1305_state
      recv_crypto_state; /**< Client->server control channel state. */

  /* Block Integrity Verification / Encryption info */
  int file_encryption_enabled; /**< Flag indicating if the current file transfer
                                  has encryption/integrity enabled. */
  int has_pending_block_meta; /**< Flag indicating if we received block metadata
                                 but not yet the data. */
  uint64_t
      expected_block_seq; /**< Expected sequence number of the next block. */
  uint32_t
      expected_block_size; /**< Expected size of the next block's ciphertext. */
  uint8_t expected_block_hash[32]; /**< Expected hash of the next block's
                                      ciphertext. */
  uint64_t
      server_block_seq; /**< Current block sequence counter on the server. */
  uint8_t file_salt[crypto_pwhash_SALTBYTES]; /**< Per-file random salt used for
                                                 key derivation. */
  uint64_t expected_plaintext_size; /**< Plaintext file size announced by the
                                       client on PUT; returned on GET so the
                                       client can verify no truncation. */
  uint8_t file_cipher_algo; /**< nasfs_cipher_algo_t for this file's blocks. */
  uint8_t file_hash_algo;   /**< nasfs_hash_algo_t for block integrity. */

  /* Async write tracking — prevents closing the fd before queued writes land. */
  int pending_writes;     /**< Number of outstanding async uv_fs_write calls. */
  int close_after_writes; /**< Set by PUT_DONE when writes are still in flight. */
  int pending_close;      /**< Set by close callback if writes were still in
                               flight; the last write callback frees the session. */

  /* PAKE (SPAKE2) auth state — valid only during pake auth handshake. */
  uint8_t pake_y[32];      /**< Server ephemeral scalar y. */
  uint8_t pake_X[32];      /**< Client share X received in CMD_PAKE_HELLO. */
  uint8_t pake_w[32];      /**< Password scalar w derived from server password. */
  int pake_hello_received; /**< Set when CMD_PAKE_HELLO has been processed. */

} client_session_t;

/**
 * @brief Callback for accepting new incoming client connections.
 *
 * @param server The listening server stream.
 * @param status The connection attempt status (0 for success).
 */
void session_on_new_connection(uv_stream_t* server, int status);

/**
 * @brief Gracefully closes a client session and frees associated resources.
 *
 * @param handle The libuv handle representing the client connection.
 */
void session_close(uv_handle_t* handle);

#endif /* NASFS_SESSION_H */
