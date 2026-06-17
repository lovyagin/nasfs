/**
 * @file crypto_engine.h
 * @brief Modular Crypto Engine for NASFS supporting multiple pluggable
 * algorithms.
 */

#ifndef NASFS_CRYPTO_ENGINE_H
#define NASFS_CRYPTO_ENGINE_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Supported Key Derivation Function (KDF) algorithms.
 */
typedef enum {
  NASFS_KDF_ARGON2ID, /**< High-security Memory-hard (interactive/GPU resistant)
                       */
  NASFS_KDF_HKDF_SHA256,  /**< Ultra-fast HKDF for stream keying */
  NASFS_KDF_PBKDF2_SHA256 /**< Traditional industry standard CPU-bound KDF */
} nasfs_kdf_algo_t;

/**
 * @brief Supported Symmetric encryption / AEAD algorithms.
 */
typedef enum {
  NASFS_CIPHER_XSALSA20_POLY1305,  /**< XSalsa20 + Poly1305 (default in MVP) */
  NASFS_CIPHER_XCHACHA20_POLY1305, /**< Extended Nonce ChaCha20 + Poly1305 */
  NASFS_CIPHER_AES_256_GCM /**< Hardware accelerated block cipher (AES-NI) */
} nasfs_cipher_algo_t;

/**
 * @brief Supported Hashing & Integrity algorithms.
 */
typedef enum {
  NASFS_HASH_BLAKE2B, /**< Modern high-speed cryptographic hash */
  NASFS_HASH_SHA256,  /**< Standard SHA-2 cryptographic hash */
  NASFS_HASH_ADLER32, /**< Extremely lightweight non-crypto checksum (error
                         detection only) */
  NASFS_HASH_CRC32    /**< High-speed CRC polynomial checksum for networks */
} nasfs_hash_algo_t;

/**
 * @struct nasfs_luks_header_t
 * @brief Conceptual LUKS-like Metadata block header for NASFS files.
 *
 * This structure sits at the beginning of the file and stores details of key
 * derivation, cipher suites, and key enveloping slots for multi-user sharing.
 */
#pragma pack(push, 1)
typedef struct {
  uint8_t magic[6];      /**< "NASLUX" magic signature */
  uint16_t version;      /**< Header version (e.g., 1) */
  uint8_t kdf_algo;      /**< nasfs_kdf_algo_t choice */
  uint8_t cipher_algo;   /**< nasfs_cipher_algo_t choice */
  uint8_t hash_algo;     /**< nasfs_hash_algo_t choice */
  uint32_t block_size;   /**< Block size (e.g., 65536) */
  uint64_t file_size;    /**< Original plaintext size (protects against GET
                            truncation) */
  uint8_t file_salt[16]; /**< Key derivation salt */
  uint8_t master_key_salt[16]; /**< Salt for OPAQUE PAKE or Master Key slot */

  /* Enveloped Key Slots (Concept: Multi-user sharing) */
  uint8_t slot_0_username[32]; /**< User name for Slot 0 */
  uint8_t slot_0_enc_key[32];  /**< File key encrypted (enveloped) with Slot 0's
                                  Public Key (X25519) */

  uint8_t slot_1_username[32]; /**< User name for Slot 1 */
  uint8_t slot_1_enc_key[32];  /**< File key encrypted (enveloped) with Slot 1's
                                  Public Key (X25519) */

  uint8_t
      header_mac[16]; /**< Poly1305 Authentication tag over the entire header */
} nasfs_luks_header_t;
#pragma pack(pop)

/**
 * @brief Derive a key using the specified KDF algorithm.
 */
int crypto_engine_derive_key(nasfs_kdf_algo_t algo, const char* password,
                             const uint8_t* salt, size_t salt_len,
                             uint8_t* out_key, size_t out_key_len);

/**
 * @brief Encrypt a block of data.
 * @return 0 on success, non-zero on failure.
 */
int crypto_engine_encrypt_block(nasfs_cipher_algo_t algo,
                                const uint8_t* plaintext, size_t plaintext_len,
                                const uint8_t* key, uint64_t seq_num,
                                uint8_t* out_ciphertext,
                                size_t* out_ciphertext_len);

/**
 * @brief Decrypt a block of data.
 * @return 0 on success, non-zero on failure.
 */
int crypto_engine_decrypt_block(nasfs_cipher_algo_t algo,
                                const uint8_t* ciphertext,
                                size_t ciphertext_len, const uint8_t* key,
                                uint64_t seq_num, uint8_t* out_plaintext,
                                size_t* out_plaintext_len);

/**
 * @brief Compute integrity checksum/hash over a buffer.
 */
int crypto_engine_hash(nasfs_hash_algo_t algo, const uint8_t* data,
                       size_t data_len, uint8_t* out_hash,
                       size_t* out_hash_len);

#endif /* NASFS_CRYPTO_ENGINE_H */
