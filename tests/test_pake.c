/**
 * @file test_pake.c
 * @brief Unit test verifying SPAKE2 Password-Authenticated Key Exchange over
 * Ristretto255.
 */

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pake.h"

int main(void) {
  printf("Starting SPAKE2 over Ristretto255 unit tests...\n");

  if (sodium_init() < 0) {
    fprintf(stderr, "libsodium initialization failed\n");
    return 1;
  }

  const char* correct_password = "nasfs-pake-super-secret-password-123";
  const char* wrong_password = "wrong-password-hacking-attempt";

  // Derive password scalars
  uint8_t w_client[NASFS_PAKE_SCALARBYTES];
  uint8_t w_server[NASFS_PAKE_SCALARBYTES];
  uint8_t w_wrong[NASFS_PAKE_SCALARBYTES];

  if (pake_derive_scalar(correct_password, w_client) != 0 ||
      pake_derive_scalar(correct_password, w_server) != 0 ||
      pake_derive_scalar(wrong_password, w_wrong) != 0) {
    fprintf(stderr, "Failed to derive password scalars\n");
    return 1;
  }

  // Generate ephemeral private scalars (x for Client, y for Server)
  uint8_t x[NASFS_PAKE_SCALARBYTES];
  uint8_t y[NASFS_PAKE_SCALARBYTES];

  crypto_core_ristretto255_scalar_random(x);
  crypto_core_ristretto255_scalar_random(y);

  // Compute public shares (X for Client, Y for Server)
  uint8_t X[NASFS_PAKE_POINTBYTES];
  uint8_t Y[NASFS_PAKE_POINTBYTES];

  if (pake_client_compute_share(w_client, x, X) != 0 ||
      pake_server_compute_share(w_server, y, Y) != 0) {
    fprintf(stderr, "Failed to compute public shares\n");
    return 1;
  }

  // Derive session keys
  uint8_t key_client[NASFS_PAKE_KEYBYTES];
  uint8_t key_server[NASFS_PAKE_KEYBYTES];

  if (pake_client_derive_key(w_client, x, Y, key_client) != 0 ||
      pake_server_derive_key(w_server, y, X, key_server) != 0) {
    fprintf(stderr, "Failed to derive session keys\n");
    return 1;
  }

  // 1. Verify that both Client and Server derived the EXACT SAME session key!
  if (memcmp(key_client, key_server, NASFS_PAKE_KEYBYTES) != 0) {
    fprintf(stderr, "PAKE Error: Key mismatch on matching passwords!\n");
    return 1;
  }
  printf(
      "PAKE Success: Client and Server negotiated the exact same strong "
      "session key using SPAKE2!\n");

  // 2. Try the exchange with an incorrect password on the server-side (Active
  // hacking attempt)
  uint8_t key_server_wrong[NASFS_PAKE_KEYBYTES];
  if (pake_server_derive_key(w_wrong, y, X, key_server_wrong) != 0) {
    fprintf(stderr, "Failed to compute key for wrong password\n");
    return 1;
  }

  // Verify that they derived DIFFERENT keys (Active dictionary hacking/mitm
  // fails!)
  if (memcmp(key_client, key_server_wrong, NASFS_PAKE_KEYBYTES) == 0) {
    fprintf(stderr,
            "PAKE Security Failure: Negotiated same key even with WRONG "
            "password!\n");
    return 1;
  }
  printf(
      "PAKE Security Success: Dictionary attack rejected. Keys did not match "
      "when wrong password was used!\n");

  printf("All SPAKE2 over Ristretto255 unit tests passed successfully.\n");
  return 0;
}
