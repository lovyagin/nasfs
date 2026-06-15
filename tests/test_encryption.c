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

  // Verify struct packing size (must be 8 + 4 + 32 = 44 bytes exactly)
  if (sizeof(nasfs_block_meta_t) != 44) {
    return 1;
  }

  // Re-verify computed hash
  uint8_t computed[32];
  crypto_generichash(computed, sizeof(computed), mock_ciphertext,
                     sizeof(mock_ciphertext), NULL, 0);
  if (memcmp(meta.hash, computed, 32) != 0) {
    return 1;
  }

  return 0;
}

static int test_request_payload_parsing_backward_compatibility(void) {
  // Scenario 1: New client with encryption enabled (prefix 0x01 + 24-byte salt)
  {
    uint8_t payload[1 + 24 + 8] = {0};
    payload[0] = 0x01;              // encrypted
    memset(payload + 1, 0xAB, 24);  // mock salt
    memcpy(payload + 25, "file.txt", 8);
    size_t payload_len = sizeof(payload);

    int is_enc = 0;
    const uint8_t* filename_ptr = payload;
    size_t filename_len = payload_len;
    uint8_t extracted_salt[24] = {0};

    if (payload_len > 1 && (payload[0] == 0 || payload[0] == 1)) {
      is_enc = payload[0];
      if (is_enc && payload_len >= 25) {
        memcpy(extracted_salt, payload + 1, 24);
        filename_ptr = payload + 25;
        filename_len = payload_len - 25;
      } else {
        filename_ptr = payload + 1;
        filename_len = payload_len - 1;
      }
    }

    if (is_enc != 1 || filename_len != 8 ||
        memcmp(filename_ptr, "file.txt", 8) != 0 || extracted_salt[0] != 0xAB) {
      return 1;
    }
  }

  // Scenario 2: New client with encryption disabled (prefix 0x00)
  {
    uint8_t payload[] = {0x00, 'f', 'i', 'l', 'e', '.', 't', 'x', 't'};
    size_t payload_len = sizeof(payload);

    int is_enc = 0;
    const uint8_t* filename_ptr = payload;
    size_t filename_len = payload_len;
    uint8_t extracted_salt[24] = {0};

    if (payload_len > 1 && (payload[0] == 0 || payload[0] == 1)) {
      is_enc = payload[0];
      if (is_enc && payload_len >= 25) {
        memcpy(extracted_salt, payload + 1, 24);
        filename_ptr = payload + 25;
        filename_len = payload_len - 25;
      } else {
        filename_ptr = payload + 1;
        filename_len = payload_len - 1;
      }
    }

    if (is_enc != 0 || filename_len != 8 ||
        memcmp(filename_ptr, "file.txt", 8) != 0) {
      return 1;
    }
  }

  // Scenario 3: Legacy client with no prefix (plain filename starting with 'f'
  // = 0x66)
  {
    uint8_t payload[] = {'f', 'i', 'l', 'e', '.', 't', 'x', 't'};
    size_t payload_len = sizeof(payload);

    int is_enc = 0;
    const uint8_t* filename_ptr = payload;
    size_t filename_len = payload_len;
    uint8_t extracted_salt[24] = {0};

    if (payload_len > 1 && (payload[0] == 0 || payload[0] == 1)) {
      is_enc = payload[0];
      if (is_enc && payload_len >= 25) {
        memcpy(extracted_salt, payload + 1, 24);
        filename_ptr = payload + 25;
        filename_len = payload_len - 25;
      } else {
        filename_ptr = payload + 1;
        filename_len = payload_len - 1;
      }
    }

    if (is_enc != 0 || filename_len != 8 ||
        memcmp(filename_ptr, "file.txt", 8) != 0) {
      return 1;
    }
  }

  return 0;
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

  if (test_request_payload_parsing_backward_compatibility() != 0) {
    fprintf(stderr,
            "test_request_payload_parsing_backward_compatibility failed\n");
    return 1;
  }

  printf("All encryption unit tests passed successfully.\n");
  return 0;
}
