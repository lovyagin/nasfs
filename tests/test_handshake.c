/**
 * @file test_handshake.c
 * @brief Unit tests for NASFS handshake payload helpers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "handshake.h"

static int test_client_hello_round_trip(void) {
  uint8_t* payload;
  size_t payload_len = 0;
  char* kex = NULL;
  char* cipher = NULL;

  payload = nasfs_handshake_pack_client_hello(
      "Kyber512,ML-KEM-512", NASFS_CONTROL_CIPHER_XCHACHA20POLY1305,
      &payload_len);
  if (!payload) {
    return 1;
  }

  if (nasfs_handshake_unpack_client_hello(payload, payload_len, &kex,
                                          &cipher) != 0) {
    free(payload);
    return 1;
  }

  if (strcmp(kex, "Kyber512,ML-KEM-512") != 0 ||
      strcmp(cipher, NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) != 0) {
    free(payload);
    free(kex);
    free(cipher);
    return 1;
  }

  free(payload);
  free(kex);
  free(cipher);
  return 0;
}

static int test_server_selection_round_trip(void) {
  static const uint8_t public_key[] = {1, 2, 3, 4, 5, 6};
  uint8_t* payload;
  size_t payload_len = 0;
  char* kex = NULL;
  char* cipher = NULL;
  uint8_t* decoded_key = NULL;
  size_t decoded_key_len = 0;

  payload = nasfs_handshake_pack_server_selection(
      "Kyber512", NASFS_CONTROL_CIPHER_XCHACHA20POLY1305, public_key,
      sizeof(public_key), &payload_len);
  if (!payload) {
    return 1;
  }

  if (nasfs_handshake_unpack_server_selection(payload, payload_len, &kex,
                                              &cipher, &decoded_key,
                                              &decoded_key_len) != 0) {
    free(payload);
    return 1;
  }

  if (strcmp(kex, "Kyber512") != 0 ||
      strcmp(cipher, NASFS_CONTROL_CIPHER_XCHACHA20POLY1305) != 0 ||
      decoded_key_len != sizeof(public_key) ||
      memcmp(decoded_key, public_key, sizeof(public_key)) != 0) {
    free(payload);
    free(kex);
    free(cipher);
    free(decoded_key);
    return 1;
  }

  free(payload);
  free(kex);
  free(cipher);
  free(decoded_key);
  return 0;
}

int main(void) {
  if (test_client_hello_round_trip() != 0) {
    fprintf(stderr, "test_client_hello_round_trip failed\n");
    return 1;
  }

  if (test_server_selection_round_trip() != 0) {
    fprintf(stderr, "test_server_selection_round_trip failed\n");
    return 1;
  }

  return 0;
}
