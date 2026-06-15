/**
 * @file protocol.h
 * @brief Definition of the NASFS binary protocol framing and command types.
 *
 * This file defines the core framing structure and command constants used for
 * communication between the NASFS client and server over libuv TCP streams.
 */

#ifndef NASFS_PROTOCOL_H
#define NASFS_PROTOCOL_H

#include <pthread.h>
#include <stdint.h>
#include <uv.h>

/**
 * @brief NASFS Minimum Protocol Framing.
 *
 * The protocol uses a simple binary framing structure:
 * - Length: 4 bytes (uint32_t), Network Byte Order. Includes the Command Type
 * byte and Payload length.
 * - Command Type: 1 byte (uint8_t).
 * - Payload: Variable length, derived from (Length - 1).
 */

/**
 * @enum nasfs_cmd_type_t
 * @brief Command types used in the NASFS protocol.
 */
typedef enum {
  /* PQC Key Exchange Commands (Unencrypted) */
  NASFS_CMD_PQC_HELLO =
      0x01, /**< C->S: Initiate a PQC handshake. Payload contains KEM name. */
  NASFS_CMD_PQC_PUBLIC_KEY =
      0x02, /**< S->C: Server responds with its public key. */
  NASFS_CMD_PQC_CIPHERTEXT =
      0x03, /**< C->S: Client sends the encapsulated shared secret. */
  NASFS_CMD_SECURE_READY = 0x04, /**< S->C: Server confirms secure channel and
                                    sends its stream header. */

  /* Control Commands (Payload will be encrypted) */
  NASFS_CMD_AUTH = 0x10,     /**< C->S: Authenticate with credentials. */
  NASFS_CMD_AUTH_ACK = 0x11, /**< S->C: Respond to authentication attempt. */
  NASFS_CMD_PUT_REQ = 0x12,  /**< C->S: Request to upload a file. */
  NASFS_CMD_PUT_ACK =
      0x13, /**< S->C: Confirm file is open and ready for PUT. */
  NASFS_CMD_PUT_DONE = 0x14, /**< C->S: Indicate end of file upload. */
  NASFS_CMD_GET_REQ = 0x15,  /**< C->S: Request to download a file. */
  NASFS_CMD_GET_ACK = 0x16,  /**< S->C: Acknowledge GET request. */
  NASFS_CMD_GET_DONE = 0x17, /**< S->C: Indicate end of file download. */
  NASFS_CMD_PUT_BLOCK_META = 0x18, /**< C->S: Metadata for the next put block (encrypted). */
  NASFS_CMD_GET_BLOCK_META = 0x19, /**< S->C: Metadata for the next get block (encrypted). */

  /* Data Transfer Commands (Unencrypted Payload) */
  NASFS_CMD_PUT_DATA = 0x20, /**< C->S: Data chunk for file upload. */
  NASFS_CMD_GET_DATA = 0x21, /**< S->C: Data chunk for file download. */

  /* General Commands */
  NASFS_CMD_ERROR = 0xFF /**< S->C: Error response from the server. */
} nasfs_cmd_type_t;

/**
 * @def NASFS_PROTO_HEADER_SIZE
 * @brief Standard size of the protocol header (4 bytes length + 1 byte
 * command).
 */
#define NASFS_PROTO_HEADER_SIZE 5

/**
 * @struct nasfs_frame_t
 * @brief Represents a parsed protocol frame.
 */
typedef struct {
  uint32_t
      length; /**< Total length excluding the 4-byte length field itself. */
  nasfs_cmd_type_t type; /**< Protocol command type. */
  uint8_t* payload;      /**< Pointer to payload data (if any). */
  size_t payload_len;    /**< Length of the payload data. */
} nasfs_frame_t;

/**
 * @brief Parses a protocol frame from a byte buffer.
 *
 * @param buffer Pointer to the start of the buffer.
 * @param size Available bytes in the buffer.
 * @param frame Pointer to the frame structure to populate.
 * @return The number of bytes consumed if a complete frame was parsed,
 *         0 if more data is needed, or a negative value on framing error.
 */
int protocol_parse_frame(const uint8_t* buffer, size_t size,
                         nasfs_frame_t* frame);

/**
 * @brief Packs a protocol frame into a dynamically allocated buffer.
 *
 * @param type The command type to send.
 * @param payload Pointer to payload data, or NULL.
 * @param payload_len Length of the payload.
 * @param out_size Pointer to store the total size of the allocated buffer.
 * @return A dynamically allocated buffer containing the packed frame, or NULL
 * on error. The caller is responsible for freeing the returned buffer.
 */
uint8_t* protocol_pack_frame(nasfs_cmd_type_t type, const uint8_t* payload,
                             size_t payload_len, size_t* out_size);

#pragma pack(push, 1)
typedef struct {
  uint64_t seq_num;
  uint32_t size;
  uint8_t hash[32];
} nasfs_block_meta_t;
#pragma pack(pop)

#endif /* NASFS_PROTOCOL_H */
