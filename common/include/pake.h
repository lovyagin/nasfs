/**
 * @file pake.h
 * @brief SPAKE2 Password-Authenticated Key Exchange over Ristretto255.
 */

#ifndef NASFS_PAKE_H
#define NASFS_PAKE_H

#include <stddef.h>
#include <stdint.h>

#define NASFS_PAKE_POINTBYTES 32
#define NASFS_PAKE_SCALARBYTES 32
#define NASFS_PAKE_KEYBYTES 32

/**
 * @brief Derives a Ristretto255 scalar from a password.
 *
 * @param password The low-entropy password.
 * @param out_w Buffer to store the derived 32-byte scalar.
 */
int pake_derive_scalar(const char* password, uint8_t* out_w);

/**
 * @brief Computes the Client's public share X.
 *
 * X = x * G + w * M
 *
 * @param w The derived password scalar.
 * @param x The client's private random scalar.
 * @param out_X Buffer to store the 32-byte client public share.
 * @return 0 on success, non-zero on failure.
 */
int pake_client_compute_share(const uint8_t* w, const uint8_t* x,
                              uint8_t* out_X);

/**
 * @brief Computes the Server's public share Y.
 *
 * Y = y * G + w * N
 *
 * @param w The derived password scalar.
 * @param y The server's private random scalar.
 * @param out_Y Buffer to store the 32-byte server public share.
 * @return 0 on success, non-zero on failure.
 */
int pake_server_compute_share(const uint8_t* w, const uint8_t* y,
                              uint8_t* out_Y);

/**
 * @brief Computes the shared session key on the Client side.
 *
 * K_client = x * (Y - w * N)
 *
 * @param w The derived password scalar.
 * @param x The client's private random scalar.
 * @param Y The server's public share.
 * @param out_key Buffer to store the derived 32-byte session key.
 * @return 0 on success, non-zero on failure.
 */
int pake_client_derive_key(const uint8_t* w, const uint8_t* x, const uint8_t* Y,
                           uint8_t* out_key);

/**
 * @brief Computes the shared session key on the Server side.
 *
 * K_server = y * (X - w * M)
 *
 * @param w The derived password scalar.
 * @param y The server's private random scalar.
 * @param X The client's public share.
 * @param out_key Buffer to store the derived 32-byte session key.
 * @return 0 on success, non-zero on failure.
 */
int pake_server_derive_key(const uint8_t* w, const uint8_t* y, const uint8_t* X,
                           uint8_t* out_key);

#endif /* NASFS_PAKE_H */
