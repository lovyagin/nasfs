/**
 * @file handshake.c
 * @brief Helpers for NASFS secure-channel negotiation payloads.
 */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "handshake.h"

/**
 * @brief Duplicates a byte sequence as a NUL-terminated string.
 *
 * @param src Source bytes to duplicate.
 * @param len Number of bytes to copy from @p src.
 * @return Newly allocated string, or NULL on failure.
 */
static char* nasfs_dup_string_field(const uint8_t* src, size_t len) {
  char* out;

  if (len == 0 || memchr(src, 0, len)) return NULL;
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

void nasfs_handshake_hash(uint8_t out[32], const uint8_t* data, size_t size) {
  crypto_generichash(out, 32, data, size, NULL, 0);
}

void nasfs_handshake_transcript(uint8_t out[32], const uint8_t hello[32],
                                const uint8_t* selection, size_t size) {
  const uint8_t domain[] = "NASFS/1 server selection: client HELLO, server key";
  uint8_t fields[64];
  memcpy(fields, hello, 32);
  nasfs_handshake_hash(fields + 32, selection, size);
  crypto_generichash_state hash;
  crypto_generichash_init(&hash, NULL, 0, 32);
  crypto_generichash_update(&hash, domain, sizeof(domain));
  crypto_generichash_update(&hash, fields, sizeof(fields));
  crypto_generichash_final(&hash, out, 32);
}

int nasfs_handshake_key(uint8_t out[32], const uint8_t* secret,
                        size_t secret_len, const uint8_t transcript[32],
                        uint8_t purpose) {
  uint8_t context[33];
  memcpy(context, transcript, 32);
  context[32] = purpose;
  return crypto_generichash(out, 32, context, sizeof(context), secret,
                            secret_len);
}

int nasfs_handshake_finished(uint8_t out[32], const uint8_t key[32],
                             const uint8_t ciphertext_frame[32],
                             const uint8_t* ready_header, size_t size) {
  uint8_t fields[64];
  memcpy(fields, ciphertext_frame, 32);
  nasfs_handshake_hash(fields + 32, ready_header, size);
  return crypto_generichash(out, 32, fields, sizeof(fields), key, 32);
}

int nasfs_handshake_read_key(const char* path, uint8_t out[32], int secret) {
  if (!path || !*path) return -1;
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return -1;
  struct stat st;
  uint8_t bytes[33];
  size_t used = 0;
  int result = -1;
  if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
      (st.st_mode & 022u) == 0 && (!secret || (st.st_mode & 077u) == 0)) {
    while (used < sizeof(bytes)) {
      ssize_t count = read(fd, bytes + used, sizeof(bytes) - used);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) {
        if (count == 0 && used == 32) result = 0;
        break;
      }
      used += (size_t)count;
    }
  }
  if (close(fd) < 0) result = -1;
  if (result == 0) memcpy(out, bytes, 32);
  sodium_memzero(bytes, sizeof(bytes));
  return result;
}

/**
 * @brief Checks whether a comma-separated list contains a given token.
 *
 * @param csv_list Comma-separated list to search.
 * @param candidate Candidate token to match.
 * @return 1 if the token exists in the list, otherwise 0.
 */
int nasfs_handshake_offer_contains(const char* csv_list,
                                   const char* candidate) {
  const char* cursor;
  size_t candidate_len;

  if (!csv_list || !candidate) {
    return 0;
  }

  candidate_len = strlen(candidate);
  cursor = csv_list;

  while (*cursor != '\0') {
    const char* start = cursor;
    const char* end;

    while (*start != '\0' && isspace((unsigned char)*start)) {
      start++;
    }

    end = start;
    while (*end != '\0' && *end != ',') {
      end++;
    }

    while (end > start && isspace((unsigned char)end[-1])) {
      end--;
    }

    if ((size_t)(end - start) == candidate_len &&
        strncmp(start, candidate, candidate_len) == 0) {
      return 1;
    }

    cursor = (*end == ',') ? end + 1 : end;
  }

  return 0;
}

uint8_t nasfs_handshake_profile(const char* kex) {
  static const struct {
    const char* name;
    uint8_t id;
  } profiles[] = {
      {"ML-KEM-512", 1},
      {"ML-KEM-768", 2},
      {"Kyber512", 3},
      {"Kyber768", 4},
  };
  for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
    if (strcmp(kex, profiles[i].name) == 0) return profiles[i].id;
  }
  return 0;
}
