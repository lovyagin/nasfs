#ifndef NASFS_FILE_SERVICE_H
#define NASFS_FILE_SERVICE_H

#include "storage.h"
#include "version_store.h"

typedef struct client_session client_session_t;

typedef struct {
  char* subject;
} nasfs_file_access_t;

typedef struct {
  crypto_generichash_state index;
  nasfs_file_access_t access;
  nasfs_version_store_t* store;
  const uint8_t* trusted_author;
  nasfs_version_header_t header;
  nasfs_block_meta_t expected;
  uint8_t proof[NASFS_VERSION_PROOF_SIZE];
  uint8_t version[NASFS_VERSION_DIGEST_SIZE];
  uint64_t sequence;
  uint64_t first;
  uint64_t end;
  size_t pending_fs;
  int64_t reserved;
  uv_file active_fd;
  int put_draining;
  int busy;
  int has_expected;
  int send_index;
  char name[NASFS_STORAGE_NAME_MAX + 1];
  char staging[NASFS_VERSION_TEMP_NAME];
} nasfs_file_service_t;

/* File callbacks retain the owning session until all outstanding I/O drains. */
int nasfs_file_service_close(client_session_t* session);
void nasfs_file_service_dispatch(client_session_t* session,
                                 nasfs_frame_t frame);
void nasfs_file_service_get_next(client_session_t* session);
int nasfs_file_service_draining(const client_session_t* session);
int nasfs_file_service_at_capacity(const client_session_t* session);

#endif
