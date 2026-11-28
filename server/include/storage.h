#ifndef NASFS_STORAGE_H
#define NASFS_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#define NASFS_STORAGE_NAME_MAX 255
#define NASFS_STORAGE_SERVICE_DIR ".nasfs"

/* The wire name may have a single trailing NUL. */
int nasfs_storage_parse_name(const uint8_t* wire_name, size_t length,
                             char name[NASFS_STORAGE_NAME_MAX + 1]);

#endif
