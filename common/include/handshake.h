/**
 * @file handshake.h
 * @brief Helpers for NASFS secure-channel negotiation payloads.
 *
 * This module provides a compact binary format for exchanging
 * algorithm preference lists and the server's final algorithm
 * selection during the PQC handshake.
 */

#ifndef NASFS_HANDSHAKE_H
#define NASFS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

/**
 * @def NASFS_CONTROL_CIPHER_XCHACHA20POLY1305
 * @brief Identifier for the encrypted control-channel cipher suite.
 */
#define NASFS_CONTROL_CIPHER_XCHACHA20POLY1305 "xchacha20poly1305"

/**
 * @brief Packs client preference lists for the handshake hello.
 *
 * The encoded payload layout is:
 * `uint16_t kex_len || uint16_t cipher_len || kex_csv || cipher_csv`.
 *
 * @param kex_list Comma-separated client KEX preferences.
 * @param cipher_list Comma-separated client control-cipher preferences.
 * @param out_size Output total size of the encoded payload.
 * @return Newly allocated payload buffer, or NULL on failure.
 */
uint8_t *nasfs_handshake_pack_client_hello(const char *kex_list,
                                           const char *cipher_list,
                                           size_t *out_size);

/**
 * @brief Unpacks client preference lists from a hello payload.
 *
 * @param payload Encoded handshake payload.
 * @param payload_len Length of @p payload.
 * @param kex_list_out Output duplicated KEX CSV string.
 * @param cipher_list_out Output duplicated cipher CSV string.
 * @return 0 on success, -1 on parse or allocation failure.
 */
int nasfs_handshake_unpack_client_hello(const uint8_t *payload,
                                        size_t payload_len,
                                        char **kex_list_out,
                                        char **cipher_list_out);

/**
 * @brief Packs the server's chosen suite together with the KEM public key.
 *
 * The encoded payload layout is:
 * `uint16_t kex_len || uint16_t cipher_len || kex_name || cipher_name || public_key`.
 *
 * @param kex_name Negotiated KEX identifier.
 * @param cipher_name Negotiated control-cipher identifier.
 * @param public_key KEM public key bytes.
 * @param public_key_len Length of @p public_key.
 * @param out_size Output total size of the encoded payload.
 * @return Newly allocated payload buffer, or NULL on failure.
 */
uint8_t *nasfs_handshake_pack_server_selection(const char *kex_name,
                                               const char *cipher_name,
                                               const uint8_t *public_key,
                                               size_t public_key_len,
                                               size_t *out_size);

/**
 * @brief Unpacks the server's negotiated suite and public key payload.
 *
 * @param payload Encoded handshake payload.
 * @param payload_len Length of @p payload.
 * @param kex_name_out Output duplicated negotiated KEX identifier.
 * @param cipher_name_out Output duplicated negotiated cipher identifier.
 * @param public_key_out Output duplicated KEM public key buffer.
 * @param public_key_len_out Output length of @p public_key_out.
 * @return 0 on success, -1 on parse or allocation failure.
 */
int nasfs_handshake_unpack_server_selection(const uint8_t *payload,
                                            size_t payload_len,
                                            char **kex_name_out,
                                            char **cipher_name_out,
                                            uint8_t **public_key_out,
                                            size_t *public_key_len_out);

#endif /* NASFS_HANDSHAKE_H */
