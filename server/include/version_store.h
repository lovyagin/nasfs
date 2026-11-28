#ifndef NASFS_VERSION_STORE_H
#define NASFS_VERSION_STORE_H

#include <sqlite3.h>
#include <stdint.h>
#include <uv.h>

#include "version.h"

#define NASFS_VERSION_TEMP_NAME 48
#define NASFS_ATTEMPT_ID_SIZE 32

typedef struct {
  uint8_t token[32];
  uint8_t scope[32];
  uint8_t digest[32];
} nasfs_attempt_t;

typedef struct {
  sqlite3* catalog;
  uv_mutex_t mutex;
  int directory;
  int lock;
  int64_t quota;
  int64_t reserved_bytes;
  int64_t retention;
  int64_t attempt_retention;
} nasfs_version_store_t;

int nasfs_version_store_open(nasfs_version_store_t* store, const char* root,
                             int64_t quota, int64_t retention,
                             int64_t attempt_retention);
void nasfs_version_store_close(nasfs_version_store_t* store);

int nasfs_version_resolve(nasfs_version_store_t* store, const char* name,
                          uint8_t id[NASFS_OBJECT_ID_SIZE],
                          uint8_t digest[NASFS_VERSION_DIGEST_SIZE]);
int nasfs_version_open(nasfs_version_store_t* store, const uint8_t id[16],
                       const uint8_t digest[32]);
int nasfs_version_reserve(nasfs_version_store_t* store, int64_t size);
void nasfs_version_release(nasfs_version_store_t* store, int64_t size);
int nasfs_version_stage(nasfs_version_store_t* store,
                        char name[NASFS_VERSION_TEMP_NAME]);
void nasfs_version_discard(nasfs_version_store_t* store, const char* staging);
int nasfs_version_publish(nasfs_version_store_t* store, const char* staging,
                          const char* name, const nasfs_version_header_t* meta,
                          const uint8_t digest[32], int64_t size,
                          const nasfs_attempt_t* attempt);
/* Returns a locked fd, UV_EALREADY with result set, or an error. */
int nasfs_version_attempt_open(nasfs_version_store_t* store,
                               const nasfs_attempt_t* attempt,
                               const nasfs_version_header_t* header,
                               const char* name,
                               char staging[NASFS_VERSION_TEMP_NAME],
                               uint64_t* seq, int* result,
                               crypto_generichash_state* index);
int nasfs_version_checkpoint(nasfs_version_store_t* store,
                             const nasfs_attempt_t* attempt, int fd,
                             uint64_t next);
int nasfs_version_collect(nasfs_version_store_t* store);

#endif
