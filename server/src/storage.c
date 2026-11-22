#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uv.h>

#include "storage.h"

int nasfs_storage_init(nasfs_storage_t* storage, const char* directory) {
  storage->root_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  return storage->root_fd < 0 ? uv_translate_sys_error(errno) : 0;
}

void nasfs_storage_close(nasfs_storage_t* storage) {
  if (storage->root_fd >= 0) close(storage->root_fd);
  storage->root_fd = -1;
}

static int is_flat_name(const uint8_t* name, size_t length) {
  return length != 0 && length <= NASFS_STORAGE_NAME_MAX &&
         !(length == 1 && name[0] == '.') &&
         !(length == 2 && name[0] == '.' && name[1] == '.') &&
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

int nasfs_storage_open_object(const nasfs_storage_t* storage, const char* name,
                              nasfs_storage_mode_t mode) {
  if (!is_flat_name((const uint8_t*)name, strlen(name))) return UV_EINVAL;

  int flags = mode == NASFS_STORAGE_REPLACE ? O_WRONLY | O_CREAT : O_RDONLY;
  int fd = openat(storage->root_fd, name,
                  flags | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0644);
  if (fd < 0) return uv_translate_sys_error(errno);

  struct stat st;
  int rc = 0;
  if (fstat(fd, &st) < 0) {
    rc = uv_translate_sys_error(errno);
  } else if (!S_ISREG(st.st_mode)) {
    rc = UV_EINVAL;
  } else if (mode == NASFS_STORAGE_REPLACE && ftruncate(fd, 0) < 0) {
    rc = uv_translate_sys_error(errno);
  }

  if (rc == 0) return fd;
  close(fd);
  return rc;
}
