/**
 * @file crypto_engine.c
 * @brief Implementation of the modular Crypto Engine.
 */

#include "crypto_engine.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <sodium.h>
#include <string.h>

/* --- Custom high-speed non-crypto checksum implementations --- */

static uint32_t calc_adler32(const uint8_t* data, size_t len) {
  uint32_t s1 = 1;
  uint32_t s2 = 0;
  for (size_t i = 0; i < len; i++) {
    s1 = (s1 + data[i]) % 65521;
    s2 = (s2 + s1) % 65521;
  }
  return (s2 << 16) | s1;
}

static uint32_t calc_crc32(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < len; i++) {
    uint8_t byte = data[i];
    crc ^= byte;
    for (int j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xEDB88320;
      } else {
        crc >>= 1;
      }
    }
  }
  return ~crc;
}

/* --- KDF interface --- */

int crypto_engine_derive_key(nasfs_kdf_algo_t algo, const char* password,
                             size_t password_len, const uint8_t* salt,
                             size_t salt_len, uint8_t* out_key,
                             size_t out_key_len) {
  if (!password || !salt || !out_key) return -1;

  switch (algo) {
    case NASFS_KDF_ARGON2ID:
      if (salt_len != crypto_pwhash_SALTBYTES) return -1;
      return crypto_pwhash(out_key, out_key_len, password, password_len, salt,
                           crypto_pwhash_OPSLIMIT_INTERACTIVE,
                           crypto_pwhash_MEMLIMIT_INTERACTIVE,
                           crypto_pwhash_ALG_ARGON2ID13);

    case NASFS_KDF_PBKDF2_SHA256:
      // Traditional industry-standard key derivation using OpenSSL PKCS5 PBKDF2
      if (PKCS5_PBKDF2_HMAC(password, (int)password_len, salt, salt_len, 4096,
                            EVP_sha256(), out_key_len, out_key) != 1) {
        return -1;
      }
      return 0;

    case NASFS_KDF_HKDF_SHA256: {
      // Modern fast key extraction using HKDF-SHA256 implemented via standard
      // HMAC (fully portable across OpenSSL 1.1.1 & 3.x)
      uint8_t prk[32];
      unsigned int prk_len = 32;

      // Step 1: Extract (PRK = HMAC-Hash(Salt, IKM))
      if (!HMAC(EVP_sha256(), salt, salt_len, (const unsigned char*)password,
                password_len, prk, &prk_len)) {
        return -1;
      }

      // Step 2: Expand (T(1) = HMAC-Hash(PRK, info | 0x01))
      uint8_t t[32];
      unsigned int t_len = 0;
      size_t bytes_written = 0;
      uint8_t counter = 1;
      const char* info = "nasfs-hkdf";
      size_t info_len = strlen(info);

      while (bytes_written < out_key_len) {
        HMAC_CTX* ctx = HMAC_CTX_new();
        if (!ctx) return -1;

        if (HMAC_Init_ex(ctx, prk, prk_len, EVP_sha256(), NULL) != 1) {
          HMAC_CTX_free(ctx);
          return -1;
        }

        if (t_len > 0) {
          if (HMAC_Update(ctx, t, t_len) != 1) {
            HMAC_CTX_free(ctx);
            return -1;
          }
        }

        if (HMAC_Update(ctx, (const unsigned char*)info, info_len) != 1 ||
            HMAC_Update(ctx, &counter, 1) != 1) {
          HMAC_CTX_free(ctx);
          return -1;
        }

        if (HMAC_Final(ctx, t, &t_len) != 1) {
          HMAC_CTX_free(ctx);
          return -1;
        }
        HMAC_CTX_free(ctx);

        size_t to_write = out_key_len - bytes_written;
        if (to_write > 32) {
          to_write = 32;
        }
        memcpy(out_key + bytes_written, t, to_write);
        bytes_written += to_write;
        counter++;
      }
      return 0;
    }
  }
  return -1;
}

/* --- Block Encryption interface --- */

int crypto_engine_encrypt_block(nasfs_cipher_algo_t algo,
                                const uint8_t* plaintext, size_t plaintext_len,
                                const uint8_t* key, uint64_t seq_num,
                                uint8_t* out_ciphertext,
                                size_t* out_ciphertext_len) {
  if (!plaintext || !key || !out_ciphertext || !out_ciphertext_len) return -1;

  uint8_t nonce[24] = {0};  // Largest needed nonce (for XSalsa20/XChaCha20)
  memcpy(nonce, &seq_num, sizeof(seq_num));

  switch (algo) {
    case NASFS_CIPHER_XSALSA20_POLY1305: {
      // 24-byte nonce XSalsa20-Poly1305
      if (crypto_secretbox_easy(out_ciphertext, plaintext, plaintext_len, nonce,
                                key) != 0) {
        return -1;
      }
      *out_ciphertext_len = plaintext_len + crypto_secretbox_MACBYTES;
      return 0;
    }

    case NASFS_CIPHER_XCHACHA20_POLY1305: {
      // Modern XChaCha20-Poly1305
      unsigned long long clen = 0;
      if (crypto_aead_xchacha20poly1305_ietf_encrypt(
              out_ciphertext, &clen, plaintext, plaintext_len, NULL, 0, NULL,
              nonce, key) != 0) {
        return -1;
      }
      *out_ciphertext_len = clen;
      return 0;
    }

    case NASFS_CIPHER_AES_256_GCM: {
      // Hardware accelerated AES-256-GCM using OpenSSL EVP
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (!ctx) return -1;

      int len = 0;
      int ciphertext_len = 0;

      // AES-GCM standard nonce size is 12 bytes
      if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
          EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
          EVP_EncryptUpdate(ctx, out_ciphertext, &len, plaintext,
                            plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
      }
      ciphertext_len = len;

      if (EVP_EncryptFinal_ex(ctx, out_ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
      }
      ciphertext_len += len;

      // Get tag (Poly1305 equivalent authentication tag)
      uint8_t tag[16];
      if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
      }

      // Standard AES-GCM output is ciphertext || 16-byte tag
      memcpy(out_ciphertext + ciphertext_len, tag, 16);
      *out_ciphertext_len = ciphertext_len + 16;

      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
  }
  return -1;
}

/* --- Block Decryption interface --- */

int crypto_engine_decrypt_block(nasfs_cipher_algo_t algo,
                                const uint8_t* ciphertext,
                                size_t ciphertext_len, const uint8_t* key,
                                uint64_t seq_num, uint8_t* out_plaintext,
                                size_t* out_plaintext_len) {
  if (!ciphertext || !key || !out_plaintext || !out_plaintext_len) return -1;

  uint8_t nonce[24] = {0};
  memcpy(nonce, &seq_num, sizeof(seq_num));

  switch (algo) {
    case NASFS_CIPHER_XSALSA20_POLY1305: {
      if (ciphertext_len < crypto_secretbox_MACBYTES) return -1;
      if (crypto_secretbox_open_easy(out_plaintext, ciphertext, ciphertext_len,
                                     nonce, key) != 0) {
        return -1;
      }
      *out_plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;
      return 0;
    }

    case NASFS_CIPHER_XCHACHA20_POLY1305: {
      unsigned long long plen = 0;
      if (crypto_aead_xchacha20poly1305_ietf_decrypt(
              out_plaintext, &plen, NULL, ciphertext, ciphertext_len, NULL, 0,
              nonce, key) != 0) {
        return -1;
      }
      *out_plaintext_len = plen;
      return 0;
    }

    case NASFS_CIPHER_AES_256_GCM: {
      if (ciphertext_len < 16) return -1;
      size_t actual_ciphertext_len = ciphertext_len - 16;

      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (!ctx) return -1;

      int len = 0;
      int plaintext_len = 0;

      if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
          EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
          EVP_DecryptUpdate(ctx, out_plaintext, &len, ciphertext,
                            actual_ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
      }
      plaintext_len = len;

      // Set expected tag
      uint8_t tag[16];
      memcpy(tag, ciphertext + actual_ciphertext_len, 16);
      if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
      }

      if (EVP_DecryptFinal_ex(ctx, out_plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;  // Authentication failed (tag mismatched or corrupted data)
      }
      plaintext_len += len;
      *out_plaintext_len = plaintext_len;

      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
  }
  return -1;
}

/* --- Integrity Check / Hash interface --- */

int crypto_engine_hash(nasfs_hash_algo_t algo, const uint8_t* data,
                       size_t data_len, uint8_t* out_hash,
                       size_t* out_hash_len) {
  if (!data || !out_hash || !out_hash_len) return -1;

  switch (algo) {
    case NASFS_HASH_BLAKE2B:
      if (crypto_generichash(out_hash, 32, data, data_len, NULL, 0) != 0) {
        return -1;
      }
      *out_hash_len = 32;
      return 0;

    case NASFS_HASH_SHA256: {
      unsigned int hlen = 0;
      if (EVP_Digest(data, data_len, out_hash, &hlen, EVP_sha256(), NULL) !=
          1) {
        return -1;
      }
      *out_hash_len = hlen;
      return 0;
    }

    case NASFS_HASH_ADLER32: {
      uint32_t val = calc_adler32(data, data_len);
      memcpy(out_hash, &val, sizeof(val));
      *out_hash_len = sizeof(val);
      return 0;
    }

    case NASFS_HASH_CRC32: {
      uint32_t val = calc_crc32(data, data_len);
      memcpy(out_hash, &val, sizeof(val));
      *out_hash_len = sizeof(val);
      return 0;
    }
  }
  return -1;
}
