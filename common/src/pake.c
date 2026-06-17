/**
 * @file pake.c
 * @brief Implementation of SPAKE2 Password-Authenticated Key Exchange over
 * Ristretto255.
 */

#include "pake.h"

#include <sodium.h>
#include <string.h>

// Static string seeds for deterministic public generators M and N
#define SPAKE2_SEED_M \
  "nasfs-spake2-generator-M-ristretto255-prime-order-group-seed"
#define SPAKE2_SEED_N \
  "nasfs-spake2-generator-N-ristretto255-prime-order-group-seed"

/**
 * @brief Helper to derive a deterministic Ristretto255 point from a seed
 * string.
 */
static int get_generator_point(const char* seed, uint8_t* out_point) {
  uint8_t hash[64];
  if (crypto_generichash(hash, sizeof(hash), (const uint8_t*)seed, strlen(seed),
                         NULL, 0) != 0) {
    return -1;
  }
  // Maps 64-byte uniform hash directly to a valid point in the prime-order
  // Ristretto255 group
  return crypto_core_ristretto255_from_hash(out_point, hash);
}

int pake_derive_scalar(const char* password, uint8_t* out_w) {
  if (!password || !out_w) return -1;

  uint8_t hash[64];
  // 1. Hash password to 64 bytes
  if (crypto_generichash(hash, sizeof(hash), (const uint8_t*)password,
                         strlen(password), NULL, 0) != 0) {
    return -1;
  }

  // 2. Reduce the 64-byte hash to a valid scalar mod L (order of Ristretto255)
  crypto_core_ristretto255_scalar_reduce(out_w, hash);
  return 0;
}

int pake_client_compute_share(const uint8_t* w, const uint8_t* x,
                              uint8_t* out_X) {
  if (!w || !x || !out_X) return -1;

  uint8_t M[crypto_core_ristretto255_BYTES];
  if (get_generator_point(SPAKE2_SEED_M, M) != 0) {
    return -1;
  }

  uint8_t x_G[crypto_core_ristretto255_BYTES];
  uint8_t w_M[crypto_core_ristretto255_BYTES];

  // 1. Compute x * G (standard base scalar multiplication)
  if (crypto_scalarmult_ristretto255_base(x_G, x) != 0) {
    return -1;
  }

  // 2. Compute w * M (arbitrary scalar multiplication)
  if (crypto_scalarmult_ristretto255(w_M, w, M) != 0) {
    return -1;
  }

  // 3. Compute X = x * G + w * M (point addition)
  crypto_core_ristretto255_add(out_X, x_G, w_M);
  return 0;
}

int pake_server_compute_share(const uint8_t* w, const uint8_t* y,
                              uint8_t* out_Y) {
  if (!w || !y || !out_Y) return -1;

  uint8_t N[crypto_core_ristretto255_BYTES];
  if (get_generator_point(SPAKE2_SEED_N, N) != 0) {
    return -1;
  }

  uint8_t y_G[crypto_core_ristretto255_BYTES];
  uint8_t w_N[crypto_core_ristretto255_BYTES];

  // 1. Compute y * G (standard base multiplication)
  if (crypto_scalarmult_ristretto255_base(y_G, y) != 0) {
    return -1;
  }

  // 2. Compute w * N
  if (crypto_scalarmult_ristretto255(w_N, w, N) != 0) {
    return -1;
  }

  // 3. Compute Y = y * G + w * N
  crypto_core_ristretto255_add(out_Y, y_G, w_N);
  return 0;
}

int pake_client_derive_key(const uint8_t* w, const uint8_t* x, const uint8_t* Y,
                           uint8_t* out_key) {
  if (!w || !x || !Y || !out_key) return -1;

  uint8_t N[crypto_core_ristretto255_BYTES];
  if (get_generator_point(SPAKE2_SEED_N, N) != 0) {
    return -1;
  }

  uint8_t w_N[crypto_core_ristretto255_BYTES];
  uint8_t Y_minus_wN[crypto_core_ristretto255_BYTES];
  uint8_t K[crypto_core_ristretto255_BYTES];

  // 1. Compute w * N
  if (crypto_scalarmult_ristretto255(w_N, w, N) != 0) {
    return -1;
  }

  // 2. Compute Y - w * N (point subtraction)
  crypto_core_ristretto255_sub(Y_minus_wN, Y, w_N);

  // 3. Compute K_client = x * (Y - w * N) = x * y * G
  if (crypto_scalarmult_ristretto255(K, x, Y_minus_wN) != 0) {
    return -1;
  }

  // 4. Hash shared point K to derive final 32-byte symmetric session key
  return crypto_generichash(out_key, 32, K, sizeof(K), NULL, 0) == 0 ? 0 : -1;
}

int pake_server_derive_key(const uint8_t* w, const uint8_t* y, const uint8_t* X,
                           uint8_t* out_key) {
  if (!w || !y || !X || !out_key) return -1;

  uint8_t M[crypto_core_ristretto255_BYTES];
  if (get_generator_point(SPAKE2_SEED_M, M) != 0) {
    return -1;
  }

  uint8_t w_M[crypto_core_ristretto255_BYTES];
  uint8_t X_minus_wM[crypto_core_ristretto255_BYTES];
  uint8_t K[crypto_core_ristretto255_BYTES];

  // 1. Compute w * M
  if (crypto_scalarmult_ristretto255(w_M, w, M) != 0) {
    return -1;
  }

  // 2. Compute X - w * M (point subtraction)
  crypto_core_ristretto255_sub(X_minus_wM, X, w_M);

  // 3. Compute K_server = y * (X - w * M) = y * x * G
  if (crypto_scalarmult_ristretto255(K, y, X_minus_wM) != 0) {
    return -1;
  }

  // 4. Hash shared point K to derive final 32-byte symmetric session key
  return crypto_generichash(out_key, 32, K, sizeof(K), NULL, 0) == 0 ? 0 : -1;
}
