/**
 * @file test_auth.c
 * @brief Unit tests for NASFS authentication payload helpers.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"

static int test_password_payload_round_trip(void) {
  nasfs_auth_payload_t input = {0};
  nasfs_auth_payload_t output = {0};
  uint8_t* packed;
  size_t packed_len = 0;
  int rc = 1;

  input.method = NASFS_AUTH_METHOD_PASSWORD;
  input.username = "alice";
  input.password = "secret";

  packed = nasfs_auth_pack(&input, &packed_len);
  if (!packed || packed_len == 0) {
    goto out;
  }

  if (nasfs_auth_unpack(packed, packed_len, &output) != 0) {
    goto out;
  }

  rc = strcmp(output.method, NASFS_AUTH_METHOD_PASSWORD) == 0 &&
               strcmp(output.username, "alice") == 0 &&
               strcmp(output.password, "secret") == 0 &&
               !output.sig_algorithm && !output.public_key &&
               output.public_key_len == 0 && !output.signature &&
               output.signature_len == 0
           ? 0
           : 1;

out:
  free(packed);
  nasfs_auth_payload_free(&output);
  return rc;
}

static int test_publickey_payload_round_trip(void) {
  uint8_t public_key[] = {0x01, 0x02, 0x03, 0x04};
  uint8_t signature[] = {0xaa, 0xbb, 0xcc};
  nasfs_auth_payload_t input = {0};
  nasfs_auth_payload_t output = {0};
  uint8_t* packed;
  size_t packed_len = 0;
  int rc = 1;

  input.method = NASFS_AUTH_METHOD_PUBLICKEY;
  input.username = "bob";
  input.sig_algorithm = NASFS_AUTH_DEFAULT_SIG_ALGORITHM;
  input.public_key = public_key;
  input.public_key_len = sizeof(public_key);
  input.signature = signature;
  input.signature_len = sizeof(signature);

  packed = nasfs_auth_pack(&input, &packed_len);
  if (!packed || nasfs_auth_unpack(packed, packed_len, &output) != 0) {
    goto out;
  }

  rc = strcmp(output.method, NASFS_AUTH_METHOD_PUBLICKEY) == 0 &&
               strcmp(output.username, "bob") == 0 &&
               strcmp(output.sig_algorithm, NASFS_AUTH_DEFAULT_SIG_ALGORITHM) ==
                   0 &&
               output.public_key_len == sizeof(public_key) &&
               memcmp(output.public_key, public_key, sizeof(public_key)) == 0 &&
               output.signature_len == sizeof(signature) &&
               memcmp(output.signature, signature, sizeof(signature)) == 0
           ? 0
           : 1;

out:
  free(packed);
  nasfs_auth_payload_free(&output);
  return rc;
}

static int test_hex_round_trip(void) {
  uint8_t input[] = {0x00, 0x10, 0xab, 0xff};
  uint8_t* decoded;
  char* encoded;
  size_t decoded_len = 0;
  int rc;

  encoded = nasfs_hex_encode(input, sizeof(input));
  decoded = nasfs_hex_decode(encoded, &decoded_len);
  rc = encoded && strcmp(encoded, "0010abff") == 0 && decoded &&
               decoded_len == sizeof(input) &&
               memcmp(decoded, input, sizeof(input)) == 0
           ? 0
           : 1;

  free(encoded);
  free(decoded);
  return rc;
}

static int test_empty_hex_decode(void) {
  size_t decoded_len = 1;

  return nasfs_hex_decode("", &decoded_len) == NULL && decoded_len == 0 ? 0 : 1;
}

static int test_auth_message_shape(void) {
  uint8_t secret[] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t* message;
  size_t message_len = 0;
  int rc;

  message =
      nasfs_auth_build_message(NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY, "carol",
                               secret, sizeof(secret), &message_len);
  rc = message && message_len > sizeof(secret) &&
               memcmp(message + message_len - sizeof(secret), secret,
                      sizeof(secret)) == 0
           ? 0
           : 1;

  free(message);
  return rc;
}

int main(void) {
  if (test_password_payload_round_trip() != 0) {
    fprintf(stderr, "password auth payload round-trip failed\n");
    return 1;
  }
  if (test_publickey_payload_round_trip() != 0) {
    fprintf(stderr, "publickey auth payload round-trip failed\n");
    return 1;
  }
  if (test_hex_round_trip() != 0) {
    fprintf(stderr, "hex round-trip failed\n");
    return 1;
  }
  if (test_empty_hex_decode() != 0) {
    fprintf(stderr, "empty hex decode failed\n");
    return 1;
  }
  if (test_auth_message_shape() != 0) {
    fprintf(stderr, "auth message shape test failed\n");
    return 1;
  }
  return 0;
}
