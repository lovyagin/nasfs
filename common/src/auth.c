/**
 * @file auth.c
 * @brief Authentication payload and key encoding helpers.
 */

#include "auth.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int append_field(uint8_t* out, size_t out_size, size_t* offset,
                        const uint8_t* data, size_t data_len) {
  uint32_t field_len;
  uint32_t field_len_net;

  if (!out || !offset || *offset > out_size || data_len > UINT32_MAX ||
      out_size - *offset < sizeof(uint32_t) + data_len) {
    return -1;
  }

  field_len = (uint32_t)data_len;
  field_len_net = htonl(field_len);
  memcpy(out + *offset, &field_len_net, sizeof(field_len_net));
  *offset += sizeof(field_len_net);

  if (data_len > 0 && data) {
    memcpy(out + *offset, data, data_len);
  }
  *offset += data_len;
  return 0;
}

static int read_field(const uint8_t* payload, size_t payload_len,
                      size_t* offset, uint8_t** out, size_t* out_len) {
  uint32_t field_len_net;
  uint32_t field_len;
  uint8_t* field = NULL;

  if (!payload || !offset || !out || !out_len || *offset > payload_len ||
      payload_len - *offset < sizeof(uint32_t)) {
    return -1;
  }

  memcpy(&field_len_net, payload + *offset, sizeof(field_len_net));
  *offset += sizeof(field_len_net);
  field_len = ntohl(field_len_net);
  if (payload_len - *offset < field_len) {
    return -1;
  }

  if (field_len > 0) {
    field = malloc((size_t)field_len + 1);
    if (!field) {
      return -1;
    }
    memcpy(field, payload + *offset, field_len);
    field[field_len] = '\0';
  }

  *offset += field_len;
  *out = field;
  *out_len = field_len;
  return 0;
}

uint8_t* nasfs_auth_pack(const nasfs_auth_payload_t* auth, size_t* out_size) {
  const uint8_t* fields[6];
  size_t lengths[6];
  size_t total_size = 0;
  uint8_t* out;
  size_t offset = 0;
  size_t i;

  if (!auth || !out_size || !auth->method || !auth->username) {
    return NULL;
  }

  fields[0] = (const uint8_t*)auth->method;
  lengths[0] = strlen(auth->method);
  fields[1] = (const uint8_t*)auth->username;
  lengths[1] = strlen(auth->username);
  fields[2] = (const uint8_t*)auth->password;
  lengths[2] = auth->password ? strlen(auth->password) : 0;
  fields[3] = (const uint8_t*)auth->sig_algorithm;
  lengths[3] = auth->sig_algorithm ? strlen(auth->sig_algorithm) : 0;
  fields[4] = auth->public_key;
  lengths[4] = auth->public_key_len;
  fields[5] = auth->signature;
  lengths[5] = auth->signature_len;

  for (i = 0; i < 6; i++) {
    if (lengths[i] > UINT32_MAX ||
        total_size > SIZE_MAX - sizeof(uint32_t) - lengths[i]) {
      return NULL;
    }
    total_size += sizeof(uint32_t) + lengths[i];
  }

  out = malloc(total_size);
  if (!out) {
    return NULL;
  }

  for (i = 0; i < 6; i++) {
    if (append_field(out, total_size, &offset, fields[i], lengths[i]) != 0) {
      free(out);
      return NULL;
    }
  }

  *out_size = total_size;
  return out;
}

int nasfs_auth_unpack(const uint8_t* payload, size_t payload_len,
                      nasfs_auth_payload_t* auth) {
  uint8_t* field = NULL;
  size_t field_len = 0;
  size_t offset = 0;

  if (!payload || !auth) {
    return -1;
  }

  memset(auth, 0, sizeof(*auth));

  if (read_field(payload, payload_len, &offset, &field, &field_len) != 0)
    goto fail;
  auth->method = (char*)field;
  if (read_field(payload, payload_len, &offset, &field, &field_len) != 0)
    goto fail;
  auth->username = (char*)field;
  if (read_field(payload, payload_len, &offset, &field, &field_len) != 0)
    goto fail;
  auth->password = (char*)field;
  if (read_field(payload, payload_len, &offset, &field, &field_len) != 0)
    goto fail;
  auth->sig_algorithm = (char*)field;
  if (read_field(payload, payload_len, &offset, &field, &field_len) != 0)
    goto fail;
  auth->public_key = field;
  auth->public_key_len = field_len;
  if (read_field(payload, payload_len, &offset, &field, &field_len) != 0)
    goto fail;
  auth->signature = field;
  auth->signature_len = field_len;

  if (offset != payload_len || !auth->method || !auth->username) {
    goto fail;
  }

  return 0;

fail:
  nasfs_auth_payload_free(auth);
  return -1;
}

void nasfs_auth_payload_free(nasfs_auth_payload_t* auth) {
  if (!auth) {
    return;
  }
  free(auth->method);
  free(auth->username);
  free(auth->password);
  free(auth->sig_algorithm);
  free(auth->public_key);
  free(auth->signature);
  memset(auth, 0, sizeof(*auth));
}

char* nasfs_hex_encode(const uint8_t* data, size_t data_len) {
  static const char alphabet[] = "0123456789abcdef";
  char* out;
  size_t i;

  if (!data && data_len > 0) {
    return NULL;
  }

  out = malloc(data_len * 2 + 1);
  if (!out) {
    return NULL;
  }

  for (i = 0; i < data_len; i++) {
    out[i * 2] = alphabet[data[i] >> 4];
    out[i * 2 + 1] = alphabet[data[i] & 0x0f];
  }
  out[data_len * 2] = '\0';
  return out;
}

static int hex_value(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

uint8_t* nasfs_hex_decode(const char* hex, size_t* out_len) {
  size_t hex_len;
  uint8_t* out;
  size_t i;

  if (!hex || !out_len) {
    return NULL;
  }

  while (isspace((unsigned char)*hex)) {
    hex++;
  }

  hex_len = strlen(hex);
  while (hex_len > 0 && isspace((unsigned char)hex[hex_len - 1])) {
    hex_len--;
  }
  if (hex_len % 2 != 0) {
    return NULL;
  }

  if (hex_len == 0) {
    *out_len = 0;
    return NULL;
  }

  out = malloc(hex_len / 2);
  if (!out) {
    return NULL;
  }

  for (i = 0; i < hex_len / 2; i++) {
    int hi = hex_value(hex[i * 2]);
    int lo = hex_value(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      free(out);
      return NULL;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }

  *out_len = hex_len / 2;
  return out;
}

uint8_t* nasfs_auth_build_message(const char* method, const char* username,
                                  const uint8_t* shared_secret,
                                  size_t shared_secret_len, size_t* out_len) {
  static const char prefix[] = "NASFS-AUTH-v1";
  size_t method_len;
  size_t username_len;
  size_t total_len;
  uint8_t* out;
  size_t offset = 0;

  if (!method || !username || !shared_secret || !out_len) {
    return NULL;
  }

  method_len = strlen(method);
  username_len = strlen(username);
  total_len = sizeof(prefix) - 1 + 1 + method_len + 1 + username_len + 1 +
              shared_secret_len;
  out = malloc(total_len);
  if (!out) {
    return NULL;
  }

  memcpy(out + offset, prefix, sizeof(prefix) - 1);
  offset += sizeof(prefix) - 1;
  out[offset++] = '\0';
  memcpy(out + offset, method, method_len);
  offset += method_len;
  out[offset++] = '\0';
  memcpy(out + offset, username, username_len);
  offset += username_len;
  out[offset++] = '\0';
  memcpy(out + offset, shared_secret, shared_secret_len);

  *out_len = total_len;
  return out;
}
