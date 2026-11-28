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
#include <sodium.h>
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
  NASFS_CMD_HELLO = 0x05, /**< C->S: Offer handshake algorithms. */
  NASFS_CMD_PQC_PUBLIC_KEY =
      0x02, /**< S->C: Server responds with its public key. */
  NASFS_CMD_PQC_CIPHERTEXT =
      0x03, /**< C->S: Client sends the encapsulated shared secret. */
  NASFS_CMD_READY = 0x06, /**< S->C: Send the server stream header. */

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
  NASFS_CMD_PUT_BLOCK_META =
      0x18, /**< C->S: Metadata for the next put block (encrypted). */
  NASFS_CMD_GET_BLOCK_META =
      0x19, /**< S->C: Metadata for the next get block (encrypted). */
  NASFS_CMD_PAKE_HELLO =
      0x1A, /**< C->S: SPAKE2 client share [u8 ulen][username][X(32)]. */
  NASFS_CMD_PAKE_RESPONSE = 0x1B, /**< S->C: SPAKE2 server share [Y(32)]. */

  NASFS_CMD_PUT_RESULT = 0x1C, /**< S->C: Final PUT status, one byte. */
  NASFS_CMD_RESOLVE = 0x1D,
  NASFS_CMD_RESOLVED = 0x1E,
  NASFS_CMD_GET_INDEX = 0x1F,
  NASFS_CMD_COLLECT = 0x22,
  NASFS_CMD_COLLECTED = 0x23,
  NASFS_CMD_GET_ADVANCE = 0x24,
  NASFS_CMD_GET_REPAIR = 0x25,
  NASFS_CMD_GET_REPAIR_DONE = 0x26,
  NASFS_CMD_PUT_PARITY = 0x27,
  NASFS_CMD_GET_REPAIR_DATA = 0x28,
  NASFS_CMD_PUT_RESUME = 0x29,

  /* Data Transfer Commands (Unencrypted Payload) */
  NASFS_CMD_PUT_DATA = 0x20, /**< C->S: Data chunk for file upload. */
  NASFS_CMD_GET_DATA = 0x21, /**< S->C: Data chunk for file download. */

  /* General Commands */
  NASFS_CMD_ERROR = 0xFF /**< S->C: Error response from the server. */
} nasfs_cmd_type_t;

typedef enum {
  NASFS_PUT_PUBLISHED = 0,
  NASFS_PUT_PUBLICATION_FAILED = 1,
  NASFS_PUT_CONFLICT = 2,
  NASFS_PUT_QUOTA = 3,
  NASFS_PUT_UNCERTAIN = 4
} nasfs_put_status_t;

static inline int nasfs_control_command(nasfs_cmd_type_t type) {
  return (type >= NASFS_CMD_AUTH && type <= NASFS_CMD_GET_INDEX) ||
         (type >= NASFS_CMD_COLLECT && type <= NASFS_CMD_GET_REPAIR_DONE) ||
         type == NASFS_CMD_PUT_RESUME || type == NASFS_CMD_ERROR;
}

/**
 * @def NASFS_PROTO_HEADER_SIZE
 * @brief Standard size of the protocol header (4 bytes length + 1 byte
 * command).
 */
#define NASFS_PROTO_HEADER_SIZE 5
#define NASFS_PROTO_MAX_FRAME (16u * 1024u * 1024u)

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

typedef struct {
  uint64_t seq_num;
  uint32_t size;
  uint8_t hash[32];
} nasfs_block_meta_t;
#define NASFS_BLOCK_META_SIZE 44

void protocol_encode_block_meta(uint8_t out[NASFS_BLOCK_META_SIZE],
                                const nasfs_block_meta_t* meta);
int protocol_decode_block_meta(const uint8_t* payload, size_t length,
                               nasfs_block_meta_t* meta);

void protocol_store_u64(uint8_t out[8], uint64_t value);
uint64_t protocol_load_u64(const uint8_t in[8]);

#endif /* NASFS_PROTOCOL_H */
