/**
 * @file protocol.h
 * @brief Definition of the NASFS binary protocol framing and command types.
 *
 * This file defines the core framing structure and command constants used for
 * communication between the NASFS client and server over libuv TCP streams.
 */

#ifndef NASFS_PROTOCOL_H
#define NASFS_PROTOCOL_H

#include <stdint.h>
#include <uv.h>

/**
 * @brief NASFS Minimum Protocol Framing.
 *
 * The protocol uses a simple binary framing structure:
 * - Length: 4 bytes (uint32_t), Network Byte Order. Includes the Command Type byte and Payload length.
 * - Command Type: 1 byte (uint8_t).
 * - Payload: Variable length, derived from (Length - 1).
 */

/**
 * @enum nasfs_cmd_type_t
 * @brief Command types used in the NASFS protocol.
 */
typedef enum {
    NASFS_CMD_AUTH       = 0x01, /**< Sent by client after connection to authenticate. */
    NASFS_CMD_PUT_REQ    = 0x02, /**< Client requests to upload a file. */
    NASFS_CMD_PUT_DATA   = 0x03, /**< Data chunk for file upload. */
    NASFS_CMD_GET_REQ    = 0x04, /**< Client requests to download a file. */
    NASFS_CMD_GET_DATA   = 0x05, /**< Data chunk for file download. */
    NASFS_CMD_ERROR      = 0xFF  /**< Error response from the server. */
} nasfs_cmd_type_t;

/**
 * @def NASFS_PROTO_HEADER_SIZE
 * @brief Standard size of the protocol header (4 bytes length + 1 byte command).
 */
#define NASFS_PROTO_HEADER_SIZE 5

#endif /* NASFS_PROTOCOL_H */