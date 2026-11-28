#ifndef NASFS_FILE_SERVICE_H
#define NASFS_FILE_SERVICE_H

#include <sodium.h>
#include <uv.h>

#include "protocol.h"
#include "storage.h"

typedef struct client_session client_session_t;

typedef struct {
  char* subject;
} nasfs_file_access_t;

typedef struct {
  nasfs_file_access_t access;
  const uint8_t* trusted_author;
  const nasfs_storage_t* storage;
  /* File Transfer State */
  uv_file active_fd; /**< File descriptor for active transfers (PUT/GET). */
  int has_record_lengths; /**< Container carries ciphertext record lengths. */
  uint64_t file_offset;   /**< Current offset in the active file. */

  crypto_generichash_state manifest;
  uint8_t upload_manifest[32 + crypto_sign_BYTES];
  int has_manifest;
  uint8_t owner_slot[NASFS_OWNER_SLOT_V1_SIZE];
  /* Block Integrity Verification / Encryption info */
  int file_encryption_enabled; /**< Flag indicating if the current file transfer
                                  has encryption/integrity enabled. */
  int has_pending_block_meta; /**< Flag indicating if we received block metadata
                                 but not yet the data. */
  uint64_t
      expected_block_seq; /**< Expected sequence number of the next block. */
  uint32_t
      expected_block_size; /**< Expected size of the next block's ciphertext. */
  uint8_t expected_block_hash[32]; /**< Expected hash of the next block's
                                      ciphertext. */
  uint64_t
      server_block_seq; /**< Current block sequence counter on the server. */
  uint8_t file_salt[crypto_pwhash_SALTBYTES]; /**< Per-file random salt used for
                                                 key derivation. */
  uint64_t expected_plaintext_size; /**< Plaintext file size announced by the
                                       client on PUT; returned on GET so the
                                       client can verify no truncation. */
  int upload_exclusive;     /**< Publish only if the name does not exist. */
  uint8_t file_cipher_algo; /**< nasfs_cipher_algo_t for this file's blocks. */
  uint8_t file_hash_algo;   /**< nasfs_hash_algo_t for block integrity. */

  size_t
      pending_fs; /**< File requests whose callbacks still own the session. */
  char upload_name[NASFS_STORAGE_NAME_MAX + 1];
  char upload_temp_name[NASFS_UPLOAD_TEMP_SIZE];
  uint64_t upload_plaintext_bytes;
  int put_draining; /**< PUT_DONE received while writes are outstanding. */
} nasfs_file_service_t;

/* File callbacks retain the owning session until all outstanding I/O drains. */
int nasfs_file_service_close(client_session_t* session);
void nasfs_file_service_dispatch(client_session_t* session,
                                 nasfs_frame_t frame);
void nasfs_file_service_get_next(client_session_t* session);
int nasfs_file_service_draining(const client_session_t* session);
int nasfs_file_service_at_capacity(const client_session_t* session);

#endif
