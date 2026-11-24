#ifndef NASFS_STORAGE_H
#define NASFS_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#define NASFS_STORAGE_NAME_MAX 255
#define NASFS_UPLOAD_TEMP_SIZE 64
#define NASFS_STORAGE_SERVICE_DIR ".nasfs"

typedef struct {
  int root_fd;
  int service_fd;
  int uploads_locked;
} nasfs_storage_t;

/* Returns 0 on success or a negative libuv error on failure. */
int nasfs_storage_init(nasfs_storage_t* storage, const char* directory);
void nasfs_storage_close(nasfs_storage_t* storage);

/* The wire name may have a single trailing NUL. */
int nasfs_storage_parse_name(const uint8_t* wire_name, size_t length,
                             char name[NASFS_STORAGE_NAME_MAX + 1]);

/* Blocking. The caller owns the returned descriptor and runs this on a worker.
 */
int nasfs_storage_open_object(const nasfs_storage_t* storage, const char* name);
int nasfs_storage_begin_upload(const nasfs_storage_t* storage,
                               char temp_name[NASFS_UPLOAD_TEMP_SIZE]);
int nasfs_storage_publish_upload(const nasfs_storage_t* storage,
                                 const char* temp_name, const char* name);
int nasfs_storage_discard_upload(const nasfs_storage_t* storage,
                                 const char* temp_name);

#endif
