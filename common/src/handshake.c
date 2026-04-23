/**
 * @file handshake.c
 * @brief Helpers for NASFS secure-channel negotiation payloads.
 */

#include "handshake.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Duplicates a byte sequence as a NUL-terminated string.
 *
 * @param src Source bytes to duplicate.
 * @param len Number of bytes to copy from @p src.
 * @return Newly allocated string, or NULL on failure.
 */
static char* nasfs_dup_string_field(const uint8_t* src, size_t len) {
  char* out;

  out = malloc(len + 1);
  if (!out) {
    return NULL;
  }

  if (len > 0) {
    memcpy(out, src, len);
  }
  out[len] = '\0';
  return out;
}

uint8_t* nasfs_handshake_pack_client_hello(const char* kex_list,
                                           const char* cipher_list,
                                           size_t* out_size) {
  uint16_t kex_len;
  uint16_t cipher_len;
  uint16_t kex_len_net;
  uint16_t cipher_len_net;
  size_t total_size;
  uint8_t* buffer;
  size_t offset;

  if (!kex_list || !cipher_list || !out_size) {
    return NULL;
  }

  if (strlen(kex_list) > UINT16_MAX || strlen(cipher_list) > UINT16_MAX) {
    return NULL;
  }

  kex_len = (uint16_t)strlen(kex_list);
  cipher_len = (uint16_t)strlen(cipher_list);
  total_size = sizeof(uint16_t) * 2 + (size_t)kex_len + (size_t)cipher_len;

  buffer = malloc(total_size);
  if (!buffer) {
    return NULL;
  }

  kex_len_net = htons(kex_len);
  cipher_len_net = htons(cipher_len);
  memcpy(buffer, &kex_len_net, sizeof(kex_len_net));
  memcpy(buffer + sizeof(kex_len_net), &cipher_len_net, sizeof(cipher_len_net));

  offset = sizeof(uint16_t) * 2;
  memcpy(buffer + offset, kex_list, kex_len);
  offset += kex_len;
  memcpy(buffer + offset, cipher_list, cipher_len);

  *out_size = total_size;
  return buffer;
}

int nasfs_handshake_unpack_client_hello(const uint8_t* payload,
                                        size_t payload_len, char** kex_list_out,
                                        char** cipher_list_out) {
  uint16_t kex_len_net;
  uint16_t cipher_len_net;
  uint16_t kex_len;
  uint16_t cipher_len;
  size_t offset;
  char* kex_list;
  char* cipher_list;

  if (!payload || !kex_list_out || !cipher_list_out ||
      payload_len < sizeof(uint16_t) * 2) {
    return -1;
  }

  memcpy(&kex_len_net, payload, sizeof(kex_len_net));
  memcpy(&cipher_len_net, payload + sizeof(kex_len_net),
         sizeof(cipher_len_net));
  kex_len = ntohs(kex_len_net);
  cipher_len = ntohs(cipher_len_net);

  offset = sizeof(uint16_t) * 2;
  if (payload_len != offset + (size_t)kex_len + (size_t)cipher_len) {
    return -1;
  }

  kex_list = nasfs_dup_string_field(payload + offset, kex_len);
  if (!kex_list) {
    return -1;
  }

  offset += kex_len;
  cipher_list = nasfs_dup_string_field(payload + offset, cipher_len);
  if (!cipher_list) {
    free(kex_list);
    return -1;
  }

  *kex_list_out = kex_list;
  *cipher_list_out = cipher_list;
  return 0;
}

uint8_t* nasfs_handshake_pack_server_selection(const char* kex_name,
                                               const char* cipher_name,
                                               const uint8_t* public_key,
                                               size_t public_key_len,
                                               size_t* out_size) {
  uint16_t kex_len;
  uint16_t cipher_len;
  uint16_t kex_len_net;
  uint16_t cipher_len_net;
  size_t total_size;
  uint8_t* buffer;
  size_t offset;

  if (!kex_name || !cipher_name || !public_key || !out_size) {
    return NULL;
  }

  if (strlen(kex_name) > UINT16_MAX || strlen(cipher_name) > UINT16_MAX) {
    return NULL;
  }

  kex_len = (uint16_t)strlen(kex_name);
  cipher_len = (uint16_t)strlen(cipher_name);
  total_size = sizeof(uint16_t) * 2 + (size_t)kex_len + (size_t)cipher_len +
               public_key_len;

  buffer = malloc(total_size);
  if (!buffer) {
    return NULL;
  }

  kex_len_net = htons(kex_len);
  cipher_len_net = htons(cipher_len);
  memcpy(buffer, &kex_len_net, sizeof(kex_len_net));
  memcpy(buffer + sizeof(kex_len_net), &cipher_len_net, sizeof(cipher_len_net));

  offset = sizeof(uint16_t) * 2;
  memcpy(buffer + offset, kex_name, kex_len);
  offset += kex_len;
  memcpy(buffer + offset, cipher_name, cipher_len);
  offset += cipher_len;
  memcpy(buffer + offset, public_key, public_key_len);

  *out_size = total_size;
  return buffer;
}

int nasfs_handshake_unpack_server_selection(const uint8_t* payload,
                                            size_t payload_len,
                                            char** kex_name_out,
                                            char** cipher_name_out,
                                            uint8_t** public_key_out,
                                            size_t* public_key_len_out) {
  uint16_t kex_len_net;
  uint16_t cipher_len_net;
  uint16_t kex_len;
  uint16_t cipher_len;
  size_t offset;
  size_t public_key_len;
  char* kex_name;
  char* cipher_name;
  uint8_t* public_key;

  if (!payload || !kex_name_out || !cipher_name_out || !public_key_out ||
      !public_key_len_out || payload_len < sizeof(uint16_t) * 2) {
    return -1;
  }

  memcpy(&kex_len_net, payload, sizeof(kex_len_net));
  memcpy(&cipher_len_net, payload + sizeof(kex_len_net),
         sizeof(cipher_len_net));
  kex_len = ntohs(kex_len_net);
  cipher_len = ntohs(cipher_len_net);

  offset = sizeof(uint16_t) * 2;
  if (payload_len < offset + (size_t)kex_len + (size_t)cipher_len) {
    return -1;
  }

  kex_name = nasfs_dup_string_field(payload + offset, kex_len);
  if (!kex_name) {
    return -1;
  }

  offset += kex_len;
  cipher_name = nasfs_dup_string_field(payload + offset, cipher_len);
  if (!cipher_name) {
    free(kex_name);
    return -1;
  }

  offset += cipher_len;
  public_key_len = payload_len - offset;
  public_key = malloc(public_key_len);
  if (!public_key) {
    free(kex_name);
    free(cipher_name);
    return -1;
  }

  if (public_key_len > 0) {
    memcpy(public_key, payload + offset, public_key_len);
  }

  *kex_name_out = kex_name;
  *cipher_name_out = cipher_name;
  *public_key_out = public_key;
  *public_key_len_out = public_key_len;
  return 0;
}
