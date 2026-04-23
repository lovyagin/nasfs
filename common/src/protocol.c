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

  if (size < NASFS_PROTO_HEADER_SIZE) {
    return 0;
  }

  uint32_t network_len;
  memcpy(&network_len, buffer, sizeof(uint32_t));
  uint32_t frame_len = ntohl(network_len);

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
  if (!out_size) {
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
