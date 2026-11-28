#ifndef NASFS_VERSION_H
#define NASFS_VERSION_H

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto_engine.h"
#include "ecc.h"
#include "protocol.h"

#define NASFS_OBJECT_ID_SIZE 16u
#define NASFS_VERSION_DIGEST_SIZE 32u
#define NASFS_VERSION_HEADER_SIZE 160u
#define NASFS_VERSION_PROOF_SIZE (64u + crypto_sign_BYTES)
#define NASFS_VERSION_DATA_OFFSET \
  (NASFS_VERSION_HEADER_SIZE + NASFS_VERSION_PROOF_SIZE)
#define NASFS_VERSION_MIN_BLOCK 4096u
#define NASFS_VERSION_MAX_BLOCK 4194304u
#define NASFS_VERSION_BLOCK_TAG 16u
#define NASFS_VERSION_REQUEST 0x32u
#define NASFS_VERSION_EXCLUSIVE 0x33u
#define NASFS_VERSION_GET_SIZE \
  (1u + NASFS_OBJECT_ID_SIZE + NASFS_VERSION_DIGEST_SIZE + 16u)

typedef enum {
  NASFS_VERSION_BLAKE2B = 0,
  NASFS_VERSION_SHA256 = 1,
  NASFS_VERSION_BLAKE3 = 2
} nasfs_version_hash_t;

typedef struct {
  uint8_t id[NASFS_OBJECT_ID_SIZE];
  uint8_t parent[NASFS_VERSION_DIGEST_SIZE];
  uint64_t size;
  uint32_t block_size;
  uint8_t salt[crypto_pwhash_SALTBYTES];
  uint8_t cipher;
  uint8_t hash;
  uint8_t ecc;
  uint8_t slot[NASFS_OWNER_SLOT_V1_SIZE];
} nasfs_version_header_t;

/* Canonical encoding and checked record layout for the signed format. */
void nasfs_version_encode(uint8_t out[NASFS_VERSION_HEADER_SIZE],
                          const nasfs_version_header_t* header);
int nasfs_version_decode(nasfs_version_header_t* header, const uint8_t* wire,
                         size_t length);
uint64_t nasfs_version_block_count(const nasfs_version_header_t* header);
uint64_t nasfs_version_record_count(const nasfs_version_header_t* header);
uint64_t nasfs_version_data_sequence(const nasfs_version_header_t* header,
                                     uint64_t data_index);
int nasfs_version_group(const nasfs_version_header_t* header,
                        uint64_t data_index, uint64_t* start, unsigned* data,
                        unsigned* parity);
int nasfs_version_is_parity(const nasfs_version_header_t* header, uint64_t seq);
int nasfs_version_record(const nasfs_version_header_t* header, uint64_t seq,
                         int64_t* offset, uint32_t* length);
int64_t nasfs_version_file_size(const nasfs_version_header_t* header);
int nasfs_version_hash_block(uint8_t profile, const uint8_t* bytes,
                             size_t length, uint8_t digest[32]);

/* The index root hashes canonical sequence, ciphertext length and digest rows.
 */
void nasfs_version_index_init(crypto_generichash_state* index);
void nasfs_version_index_add(crypto_generichash_state* index,
                             const nasfs_block_meta_t* meta);
void nasfs_version_index_final(crypto_generichash_state* index,
                               uint8_t root[32]);
int nasfs_version_sign(const nasfs_version_header_t* header,
                       const uint8_t root[32], const uint8_t key[64],
                       uint8_t proof[NASFS_VERSION_PROOF_SIZE]);
int nasfs_version_verify(const nasfs_version_header_t* header,
                         const uint8_t proof[NASFS_VERSION_PROOF_SIZE],
                         const uint8_t key[32]);

#endif
