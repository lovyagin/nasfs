/**
 * @file protocol.c
 * @brief Implementation of the NASFS binary protocol framing.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS common library.
 * Provides the core serialization and deserialization functions for
 * network protocol frames used by both the client and server.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

int protocol_parse_frame(const uint8_t* buffer, size_t size,
                         nasfs_frame_t* frame) {
  if (!buffer || !frame) {
    return -1;
  }

  if (size < sizeof(uint32_t)) {
    return 0;
  }

  uint32_t network_len;
  memcpy(&network_len, buffer, sizeof(uint32_t));
  uint32_t frame_len = ntohl(network_len);

  // Validate frame_len to prevent integer overflow and denial of service /
  // memory corruption. 16 MB is a very generous maximum limit for a single
  // protocol frame (with 64KB blocks).
  if (frame_len == 0 || frame_len > NASFS_PROTO_MAX_FRAME) {
    return -1;
  }

  uint32_t total_required = sizeof(uint32_t) + frame_len;
  if (size < total_required) {
    return 0;
  }

  frame->length = frame_len;
  frame->type = (nasfs_cmd_type_t)buffer[4];

  if (frame_len > 1) {
    frame->payload_len = frame_len - 1;
    frame->payload = (uint8_t*)(buffer + NASFS_PROTO_HEADER_SIZE);
  } else {
    frame->payload_len = 0;
    frame->payload = NULL;
  }

  return (int)total_required;
}

uint8_t* protocol_pack_frame(nasfs_cmd_type_t type, const uint8_t* payload,
                             size_t payload_len, size_t* out_size) {
  if (!out_size || (!payload && payload_len != 0)) {
    return NULL;
  }

  if (payload_len >= NASFS_PROTO_MAX_FRAME) {
    return NULL;
  }

  uint32_t frame_len = 1 + (uint32_t)payload_len;
  size_t total_size = sizeof(uint32_t) + frame_len;

  uint8_t* buffer = (uint8_t*)malloc(total_size);
  if (!buffer) {
    return NULL;
  }

  uint32_t network_len = htonl(frame_len);
  memcpy(buffer, &network_len, sizeof(uint32_t));

  buffer[4] = (uint8_t)type;

  if (payload && payload_len > 0) {
    memcpy(buffer + NASFS_PROTO_HEADER_SIZE, payload, payload_len);
  }

  *out_size = total_size;
  return buffer;
}

void protocol_store_u64(uint8_t out[8], uint64_t value) {
  for (size_t i = 0; i < 8; i++) {
    out[i] = (uint8_t)(value >> (56 - 8 * i));
  }
}

uint64_t protocol_load_u64(const uint8_t in[8]) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++) {
    value = (value << 8u) | in[i];
  }
  return value;
}

void protocol_encode_block_meta(uint8_t out[NASFS_BLOCK_META_SIZE],
                                const nasfs_block_meta_t* meta) {
  protocol_store_u64(out, meta->seq_num);
  uint32_t size = htonl(meta->size);
  memcpy(out + 8, &size, sizeof(size));
  memcpy(out + 12, meta->hash, sizeof(meta->hash));
}

int protocol_decode_block_meta(const uint8_t* payload, size_t length,
                               nasfs_block_meta_t* meta) {
  if (!payload || !meta || length != NASFS_BLOCK_META_SIZE) return -1;
  meta->seq_num = protocol_load_u64(payload);
  uint32_t size;
  memcpy(&size, payload + 8, sizeof(size));
  meta->size = ntohl(size);
  memcpy(meta->hash, payload + 12, sizeof(meta->hash));
  return 0;
}

void protocol_manifest_init(crypto_generichash_state* state, const char* object,
                            uint64_t plaintext_size,
                            const uint8_t salt[crypto_pwhash_SALTBYTES],
                            uint8_t cipher, uint8_t hash) {
  const uint8_t domain[] = "NASFS ciphertext manifest/1";
  uint8_t header[10] = {cipher, hash};
  protocol_store_u64(header + 2, plaintext_size);
  crypto_generichash_init(state, NULL, 0, 32);
  crypto_generichash_update(state, domain, sizeof(domain));
  crypto_generichash_update(state, header, sizeof(header));
  crypto_generichash_update(state, salt, crypto_pwhash_SALTBYTES);
  crypto_generichash_update(state, (const uint8_t*)object, strlen(object) + 1);
}

void protocol_manifest_owner_slot(crypto_generichash_state* state,
                                  const uint8_t* slot, size_t length) {
  const uint8_t tag[] = {0, 0, 0, 0, 'N', 'A', 'S', 'L', 'U', 'K', 'S', 1};
  crypto_generichash_update(state, tag, sizeof(tag));
  crypto_generichash_update(state, slot, length);
}

void protocol_manifest_record(crypto_generichash_state* state,
                              const uint8_t* ciphertext, size_t length) {
  uint32_t prefix = htonl((uint32_t)length);
  crypto_generichash_update(state, (const uint8_t*)&prefix, sizeof(prefix));
  crypto_generichash_update(state, ciphertext, length);
}

int protocol_manifest_sign(crypto_generichash_state* state,
                           uint8_t manifest[NASFS_MANIFEST_SIZE],
                           const uint8_t key[crypto_sign_SECRETKEYBYTES]) {
  crypto_generichash_final(state, manifest, 32);
  return crypto_sign_detached(manifest + 32, NULL, manifest, 32, key);
}

int protocol_manifest_verify(crypto_generichash_state* state,
                             const uint8_t manifest[NASFS_MANIFEST_SIZE],
                             const uint8_t key[crypto_sign_PUBLICKEYBYTES]) {
  uint8_t digest[32];
  crypto_generichash_final(state, digest, sizeof(digest));
  if (sodium_memcmp(digest, manifest, sizeof(digest)) != 0) return -1;
  return crypto_sign_verify_detached(manifest + 32, digest, sizeof(digest),
                                     key);
}
