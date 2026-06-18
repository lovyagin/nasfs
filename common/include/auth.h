/**
 * @file auth.h
 * @brief Helpers for NASFS authentication payloads and hex keys.
 */

#ifndef NASFS_AUTH_H
#define NASFS_AUTH_H

#include <stddef.h>
#include <stdint.h>

#define NASFS_AUTH_METHOD_PASSWORD "password"
#define NASFS_AUTH_METHOD_PUBLICKEY "publickey"
#define NASFS_AUTH_METHOD_PASSWORD_PUBLICKEY "password+publickey"
#define NASFS_AUTH_METHOD_PAKE "pake"
#define NASFS_AUTH_DEFAULT_SIG_ALGORITHM "ML-DSA-65"

typedef struct {
  char* method;
  char* username;
  char* password;
  char* sig_algorithm;
  uint8_t* public_key;
  size_t public_key_len;
  uint8_t* signature;
  size_t signature_len;
} nasfs_auth_payload_t;

uint8_t* nasfs_auth_pack(const nasfs_auth_payload_t* auth, size_t* out_size);
int nasfs_auth_unpack(const uint8_t* payload, size_t payload_len,
                      nasfs_auth_payload_t* auth);
void nasfs_auth_payload_free(nasfs_auth_payload_t* auth);

char* nasfs_hex_encode(const uint8_t* data, size_t data_len);
uint8_t* nasfs_hex_decode(const char* hex, size_t* out_len);

uint8_t* nasfs_auth_build_message(const char* method, const char* username,
                                  const uint8_t* shared_secret,
                                  size_t shared_secret_len, size_t* out_len);

#endif /* NASFS_AUTH_H */
