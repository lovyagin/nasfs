/**
 * @file test_encryption.c
 * @brief Unit tests for NASFS file encryption and block integrity verification
 * helpers.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_engine.h"
#include "protocol.h"

static int test_key_derivation_and_encryption_round_trip(void) {
  if (sodium_init() < 0) {
    return 1;
  }

  const char* passphrase = "extremely-secure-password-1337!";
  uint8_t derived_key[crypto_secretbox_KEYBYTES];

  // Derive 32-byte key using BLAKE2b hash of the passphrase
  if (crypto_generichash(derived_key, sizeof(derived_key),
                         (const uint8_t*)passphrase, strlen(passphrase), NULL,
                         0) != 0) {
    return 1;
  }

  // Generate a mock plaintext of 100 bytes
  uint8_t plaintext[100];
  for (size_t i = 0; i < sizeof(plaintext); i++) {
    plaintext[i] = (uint8_t)(i & 0xFF);
  }

  // Set up sequential nonce
  uint64_t seq_num = 42;
  uint8_t nonce[crypto_secretbox_NONCEBYTES] = {0};
  memcpy(nonce, &seq_num, sizeof(seq_num));

  // Perform encryption
  size_t ciphertext_len = sizeof(plaintext) + crypto_secretbox_MACBYTES;
  uint8_t* ciphertext = malloc(ciphertext_len);
  if (!ciphertext) {
    return 1;
  }

  if (crypto_secretbox_easy(ciphertext, plaintext, sizeof(plaintext), nonce,
                            derived_key) != 0) {
    free(ciphertext);
    return 1;
  }

  // Verify ciphertext is different from plaintext
  if (memcmp(ciphertext + crypto_secretbox_MACBYTES, plaintext,
             sizeof(plaintext)) == 0) {
    free(ciphertext);
    return 1;
  }

  // Perform decryption
  uint8_t* decrypted = malloc(sizeof(plaintext));
  if (!decrypted) {
    free(ciphertext);
    return 1;
  }

  if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce,
                                 derived_key) != 0) {
    free(ciphertext);
    free(decrypted);
    return 1;
  }

  // Verify round-trip matches original plaintext
  if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
    free(ciphertext);
    free(decrypted);
    return 1;
  }

  free(ciphertext);
  free(decrypted);
  return 0;
}

static int test_decryption_failure_cases(void) {
  const char* passphrase = "secure-password";
  uint8_t key[crypto_secretbox_KEYBYTES];
  uint8_t wrong_key[crypto_secretbox_KEYBYTES];

  crypto_generichash(key, sizeof(key), (const uint8_t*)passphrase,
                     strlen(passphrase), NULL, 0);
  crypto_generichash(wrong_key, sizeof(wrong_key),
                     (const uint8_t*)"wrong-password", strlen("wrong-password"),
                     NULL, 0);

  uint8_t plaintext[50] = {0};
  uint64_t seq = 0;
  uint8_t nonce[crypto_secretbox_NONCEBYTES] = {0};
  memcpy(nonce, &seq, sizeof(seq));

  size_t ciphertext_len = sizeof(plaintext) + crypto_secretbox_MACBYTES;
  uint8_t* ciphertext = malloc(ciphertext_len);
  crypto_secretbox_easy(ciphertext, plaintext, sizeof(plaintext), nonce, key);

  uint8_t* decrypted = malloc(sizeof(plaintext));

  // 1. Decrypt with WRONG key (should fail)
  if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce,
                                 wrong_key) == 0) {
    free(ciphertext);
    free(decrypted);
    return 1;
  }

  // 2. Decrypt with WRONG nonce (should fail)
  uint8_t wrong_nonce[crypto_secretbox_NONCEBYTES] = {0};
  uint64_t wrong_seq = 999;
  memcpy(wrong_nonce, &wrong_seq, sizeof(wrong_seq));
  if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len,
                                 wrong_nonce, key) == 0) {
    free(ciphertext);
    free(decrypted);
    return 1;
  }

  // 3. Decrypt with TAMPERED ciphertext (should fail)
  ciphertext[10] ^= 0xFF;  // Flip a bit
  if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce,
                                 key) == 0) {
    free(ciphertext);
    free(decrypted);
    return 1;
  }

  free(ciphertext);
  free(decrypted);
  return 0;
}

static int test_block_metadata_integrity(void) {
  uint8_t mock_ciphertext[256];
  for (size_t i = 0; i < sizeof(mock_ciphertext); i++) {
    mock_ciphertext[i] = (uint8_t)i;
  }

  nasfs_block_meta_t meta = {0};
  meta.seq_num = 1337;
  meta.size = sizeof(mock_ciphertext);

  // Compute BLAKE2b hash of the ciphertext
  if (crypto_generichash(meta.hash, sizeof(meta.hash), mock_ciphertext,
                         sizeof(mock_ciphertext), NULL, 0) != 0) {
    return 1;
  }

  uint8_t bytes[NASFS_BLOCK_META_SIZE];
  protocol_encode_block_meta(bytes, &meta);
  const uint8_t expected_prefix[] = {0, 0, 0, 0, 0, 0, 5, 57, 0, 0, 1, 0};
  if (memcmp(bytes, expected_prefix, sizeof(expected_prefix)) != 0) return 1;

  nasfs_block_meta_t decoded;
  if (protocol_decode_block_meta(bytes, sizeof(bytes) - 1, &decoded) == 0 ||
      protocol_decode_block_meta(bytes, sizeof(bytes), &decoded) != 0 ||
      decoded.seq_num != meta.seq_num || decoded.size != meta.size ||
      memcmp(decoded.hash, meta.hash, sizeof(meta.hash)) != 0) {
    return 1;
  }

  return 0;
}

static int test_block_checksum_encoding(void) {
  const uint8_t input[] = "123456789";
  const struct {
    nasfs_hash_algo_t algorithm;
    const char* name;
    uint8_t expected[4];
  } cases[] = {
      {NASFS_HASH_CRC32, "CRC32", {0xcb, 0xf4, 0x39, 0x26}},
      {NASFS_HASH_ADLER32, "Adler32", {0x09, 0x1e, 0x01, 0xde}},
  };
  int result = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    nasfs_block_meta_t meta = {0};
    size_t hash_len;
    if (crypto_engine_hash(cases[i].algorithm, input, sizeof(input) - 1,
                           meta.hash, &hash_len) != 0 ||
        hash_len != sizeof(cases[i].expected)) {
      fprintf(stderr, "%s produced an invalid checksum length\n",
              cases[i].name);
      result = 1;
      continue;
    }

    uint8_t encoded[NASFS_BLOCK_META_SIZE];
    protocol_encode_block_meta(encoded, &meta);
    if (memcmp(encoded + 12, cases[i].expected, sizeof(cases[i].expected)) !=
        0) {
      fprintf(stderr, "%s block metadata checksum is not in big-endian order\n",
              cases[i].name);
      result = 1;
    }
  }
  return result;
}

static int test_frame_codec(void) {
  nasfs_frame_t frame;
  const uint8_t zero_length[] = {0, 0, 0, 0, NASFS_CMD_HELLO};
  const uint8_t oversized[] = {1, 0, 0, 1};
  uint8_t buffers[] = {0, 0, 0, 2, NASFS_CMD_PUT_RESULT, NASFS_PUT_PUBLISHED,
                       0, 0, 0, 1, NASFS_CMD_GET_DONE};
  if (protocol_parse_frame(zero_length, sizeof(zero_length), &frame) >= 0 ||
      protocol_parse_frame(oversized, sizeof(oversized), &frame) >= 0 ||
      protocol_parse_frame(buffers, 5, &frame) != 0 ||
      protocol_parse_frame(buffers, sizeof(buffers), &frame) != 6 ||
      frame.type != NASFS_CMD_PUT_RESULT || frame.payload_len != 1 ||
      frame.payload[0] != NASFS_PUT_PUBLISHED ||
      protocol_parse_frame(buffers + 6, sizeof(buffers) - 6, &frame) != 5 ||
      frame.type != NASFS_CMD_GET_DONE || frame.payload_len != 0) {
    return 1;
  }
  size_t size;
  uint8_t* packed =
      protocol_pack_frame(NASFS_CMD_PUT_RESULT, buffers + 5, 1, &size);
  int result = !packed || size != 6 || memcmp(packed, buffers, 6) != 0;
  free(packed);
  return result;
}

static int test_portable_file_encoding(void) {
  const uint64_t value = UINT64_C(0x0102030405060708);
  const uint8_t expected[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t encoded[8];
  protocol_store_u64(encoded, value);
  if (memcmp(encoded, expected, sizeof(expected)) != 0 ||
      protocol_load_u64(expected) != value) {
    return 1;
  }

  const uint8_t file_key[32] = {0x42};
  const uint8_t salt[16] = {0x24};
  uint8_t input[sizeof(file_key) + sizeof(salt) + sizeof(expected)];
  memcpy(input, file_key, sizeof(file_key));
  memcpy(input + sizeof(file_key), salt, sizeof(salt));
  memcpy(input + sizeof(file_key) + sizeof(salt), expected, sizeof(expected));
  uint8_t expected_key[32];
  uint8_t block_key[32];
  if (crypto_generichash(expected_key, sizeof(expected_key), input,
                         sizeof(input), NULL, 0) != 0) {
    return 1;
  }
  crypto_engine_derive_block_key(block_key, file_key, salt, value, 0);
  if (memcmp(block_key, expected_key, sizeof(block_key)) != 0) return 1;

  const uint8_t nonce[crypto_secretbox_NONCEBYTES] = {1, 2, 3, 4, 5, 6, 7, 8};
  const uint8_t plaintext[] = {9, 10, 11};
  uint8_t ciphertext[sizeof(plaintext) + crypto_secretbox_MACBYTES];
  uint8_t expected_ciphertext[sizeof(ciphertext)];
  size_t ciphertext_len;
  return crypto_secretbox_easy(expected_ciphertext, plaintext,
                               sizeof(plaintext), nonce, expected_key) != 0 ||
         crypto_engine_encrypt_block(NASFS_CIPHER_XSALSA20_POLY1305, plaintext,
                                     sizeof(plaintext), block_key, value,
                                     ciphertext, &ciphertext_len) != 0 ||
         ciphertext_len != sizeof(ciphertext) ||
         memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) != 0;
}

int main(void) {
  if (sodium_init() < 0) {
    fprintf(stderr, "libsodium initialization failed\n");
    return 1;
  }

  if (test_key_derivation_and_encryption_round_trip() != 0) {
    fprintf(stderr, "test_key_derivation_and_encryption_round_trip failed\n");
    return 1;
  }

  if (test_decryption_failure_cases() != 0) {
    fprintf(stderr, "test_decryption_failure_cases failed\n");
    return 1;
  }

  if (test_block_metadata_integrity() != 0) {
    fprintf(stderr, "test_block_metadata_integrity failed\n");
    return 1;
  }

  if (test_block_checksum_encoding() != 0) return 1;

  if (test_frame_codec() != 0) {
    fprintf(stderr, "test_frame_codec failed\n");
    return 1;
  }

  if (test_portable_file_encoding() != 0) {
    fprintf(stderr, "test_portable_file_encoding failed\n");
    return 1;
  }

  printf("All encryption unit tests passed successfully.\n");
  return 0;
}
