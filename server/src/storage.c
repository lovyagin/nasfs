#include "storage.h"

#include <string.h>
#include <uv.h>

static const char publication_lock[] = ".nasfs-publish.lock";
static const char upload_prefix[] = ".nasfs-upload.";
static const char version_directory[] = ".nasfs-v2";

static int has_ascii_prefix(const uint8_t* name, size_t length,
                            const char* prefix) {
  for (size_t i = 0; prefix[i]; i++) {
    if (i == length) return 0;
    uint8_t ch = name[i];
    if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    if (ch != (uint8_t)prefix[i]) return 0;
  }
  return 1;
}

static int is_flat_name(const uint8_t* name, size_t length) {
  return length != 0 && length <= NASFS_STORAGE_NAME_MAX &&
         !(length == 1 && name[0] == '.') &&
         !(length == 2 && name[0] == '.' && name[1] == '.') &&
         !(length == sizeof(NASFS_STORAGE_SERVICE_DIR) - 1 &&
           has_ascii_prefix(name, length, NASFS_STORAGE_SERVICE_DIR)) &&
         !(length == sizeof(publication_lock) - 1 &&
           has_ascii_prefix(name, length, publication_lock)) &&
         !(length == sizeof(version_directory) - 1 &&
           has_ascii_prefix(name, length, version_directory)) &&
         !has_ascii_prefix(name, length, upload_prefix) &&
         !memchr(name, '/', length) && !memchr(name, '\\', length) &&
         !memchr(name, '\0', length);
}

int nasfs_storage_parse_name(const uint8_t* wire_name, size_t length,
                             char name[NASFS_STORAGE_NAME_MAX + 1]) {
  if (length > 0 && wire_name[length - 1] == '\0') length--;
  if (!is_flat_name(wire_name, length)) return UV_EINVAL;
  memcpy(name, wire_name, length);
  name[length] = '\0';
  return 0;
}
