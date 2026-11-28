#include "version.h"

#include <arpa/inet.h>
#include <string.h>

#include "blake3.h"

static const uint8_t format_id[8] = {'N', 'A', 'S', 'F', 'S', 'V', '2', 0};
static const unsigned record_overhead =
    NASFS_BLOCK_META_SIZE + NASFS_VERSION_BLOCK_TAG;

void nasfs_version_encode(uint8_t out[NASFS_VERSION_HEADER_SIZE],
                          const nasfs_version_header_t* header) {
  memcpy(out, format_id, sizeof(format_id));
  memcpy(out + 8, header->id, sizeof(header->id));
  memcpy(out + 24, header->parent, sizeof(header->parent));
  protocol_store_u64(out + 56, header->size);
  uint32_t wire_block_size = htonl(header->block_size);
  memcpy(out + 64, &wire_block_size, sizeof(wire_block_size));
  memcpy(out + 68, header->salt, sizeof(header->salt));
  out[84] = header->cipher;
  out[85] = header->hash;
  out[86] = 0;
  out[87] = 0;
  memcpy(out + 88, header->slot, sizeof(header->slot));
}

int nasfs_version_decode(nasfs_version_header_t* header, const uint8_t* wire,
                         size_t length) {
  if (!header || !wire || length != NASFS_VERSION_HEADER_SIZE ||
      memcmp(wire, format_id, sizeof(format_id)) != 0 ||
      wire[84] > NASFS_CIPHER_AES_256_GCM || wire[85] > NASFS_VERSION_BLAKE3 ||
      wire[86] || wire[87] || sodium_is_zero(wire + 8, NASFS_OBJECT_ID_SIZE))
    return -1;

  memset(header, 0, sizeof(*header));
  memcpy(header->id, wire + 8, sizeof(header->id));
  memcpy(header->parent, wire + 24, sizeof(header->parent));
  header->size = protocol_load_u64(wire + 56);
  uint32_t wire_block_size;
  memcpy(&wire_block_size, wire + 64, sizeof(wire_block_size));
  header->block_size = ntohl(wire_block_size);
  memcpy(header->salt, wire + 68, sizeof(header->salt));
  header->cipher = wire[84];
  header->hash = wire[85];
  memcpy(header->slot, wire + 88, sizeof(header->slot));
  return nasfs_version_file_size(header) < 0 ? -1 : 0;
}

uint64_t nasfs_version_block_count(const nasfs_version_header_t* header) {
  if (!header->block_size) return 0;
  return header->size / header->block_size +
         (header->size % header->block_size != 0);
}

int64_t nasfs_version_file_size(const nasfs_version_header_t* header) {
  if (header->block_size < NASFS_VERSION_MIN_BLOCK ||
      header->block_size > NASFS_VERSION_MAX_BLOCK ||
      header->size > INT64_MAX - NASFS_VERSION_DATA_OFFSET)
    return -1;
  uint64_t room = INT64_MAX - NASFS_VERSION_DATA_OFFSET - header->size;
  uint64_t count = nasfs_version_block_count(header);
  if (count > room / record_overhead) return -1;
  return (int64_t)(NASFS_VERSION_DATA_OFFSET + header->size +
                   count * record_overhead);
}

int nasfs_version_record(const nasfs_version_header_t* header, uint64_t seq,
                         int64_t* offset, uint32_t* length) {
  if (nasfs_version_file_size(header) < 0 ||
      seq >= nasfs_version_block_count(header))
    return -1;
  uint64_t remaining = header->size - seq * header->block_size;
  uint32_t plaintext_length =
      remaining < header->block_size ? (uint32_t)remaining : header->block_size;
  *offset = (int64_t)(NASFS_VERSION_DATA_OFFSET +
                      seq * (header->block_size + record_overhead));
  *length = plaintext_length + NASFS_VERSION_BLOCK_TAG;
  return 0;
}

int nasfs_version_hash_block(uint8_t profile, const uint8_t* bytes,
                             size_t length, uint8_t digest[32]) {
  switch (profile) {
    case NASFS_VERSION_BLAKE2B:
      return crypto_generichash(digest, 32, bytes, length, NULL, 0);
    case NASFS_VERSION_SHA256:
      return crypto_hash_sha256(digest, bytes, length);
    case NASFS_VERSION_BLAKE3: {
      blake3_hasher hasher;
      blake3_hasher_init(&hasher);
      blake3_hasher_update(&hasher, bytes, length);
      blake3_hasher_finalize(&hasher, digest, 32);
      return 0;
    }
    default:
      return -1;
  }
}

void nasfs_version_index_init(crypto_generichash_state* index) {
  static const uint8_t domain[] = "NASFS-V2 index";
  crypto_generichash_init(index, NULL, 0, 32);
  crypto_generichash_update(index, domain, sizeof(domain));
}

void nasfs_version_index_add(crypto_generichash_state* index,
                             const nasfs_block_meta_t* meta) {
  uint8_t row[NASFS_BLOCK_META_SIZE];
  protocol_encode_block_meta(row, meta);
  crypto_generichash_update(index, row, sizeof(row));
}

void nasfs_version_index_final(crypto_generichash_state* index,
                               uint8_t root[32]) {
  crypto_generichash_final(index, root, 32);
}

static void manifest_digest(const nasfs_version_header_t* header,
                            const uint8_t root[32], uint8_t digest[32]) {
  static const uint8_t domain[] = "NASFS-V2 manifest";
  crypto_generichash_state state;
  uint8_t wire[NASFS_VERSION_HEADER_SIZE];
  nasfs_version_encode(wire, header);
  crypto_generichash_init(&state, NULL, 0, 32);
  crypto_generichash_update(&state, domain, sizeof(domain));
  crypto_generichash_update(&state, wire, sizeof(wire));
  crypto_generichash_update(&state, root, 32);
  crypto_generichash_final(&state, digest, 32);
}

int nasfs_version_sign(const nasfs_version_header_t* header,
                       const uint8_t root[32], const uint8_t key[64],
                       uint8_t proof[NASFS_VERSION_PROOF_SIZE]) {
  memcpy(proof, root, 32);
  manifest_digest(header, root, proof + 32);
  return crypto_sign_detached(proof + 64, NULL, proof + 32, 32, key);
}

int nasfs_version_verify(const nasfs_version_header_t* header,
                         const uint8_t proof[NASFS_VERSION_PROOF_SIZE],
                         const uint8_t key[32]) {
  uint8_t digest[32];
  manifest_digest(header, proof, digest);
  if (sodium_memcmp(digest, proof + 32, sizeof(digest)) != 0) return -1;
  return crypto_sign_verify_detached(proof + 64, digest, sizeof(digest), key);
}
