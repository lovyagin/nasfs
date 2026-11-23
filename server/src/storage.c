#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
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

static const char upload_prefix[] = ".nasfs-upload.";

static int is_flat_name(const uint8_t* name, size_t length) {
  return length != 0 && length <= NASFS_STORAGE_NAME_MAX &&
         !(length == 1 && name[0] == '.') &&
         !(length == 2 && name[0] == '.' && name[1] == '.') &&
         !(length >= sizeof(upload_prefix) - 1 &&
           memcmp(name, upload_prefix, sizeof(upload_prefix) - 1) == 0) &&
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

int nasfs_storage_open_object(const nasfs_storage_t* storage,
                              const char* name) {
  if (!is_flat_name((const uint8_t*)name, strlen(name))) return UV_EINVAL;

  int fd = openat(storage->root_fd, name,
                  O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) return uv_translate_sys_error(errno);

  struct stat st;
  int rc = 0;
  if (fstat(fd, &st) < 0) {
    rc = uv_translate_sys_error(errno);
  } else if (!S_ISREG(st.st_mode)) {
    rc = UV_EINVAL;
  }

  if (rc == 0) return fd;
  close(fd);
  return rc;
}

int nasfs_storage_begin_upload(const nasfs_storage_t* storage,
                               char temp_name[NASFS_UPLOAD_TEMP_SIZE]) {
  char candidate[NASFS_UPLOAD_TEMP_SIZE];
  memcpy(candidate, upload_prefix, sizeof(upload_prefix) - 1);
  for (int attempt = 0; attempt < 8; attempt++) {
    unsigned char random_id[16];
    randombytes_buf(random_id, sizeof(random_id));
    sodium_bin2hex(candidate + sizeof(upload_prefix) - 1,
                   sizeof(candidate) - (sizeof(upload_prefix) - 1), random_id,
                   sizeof(random_id));
    int fd = openat(storage->root_fd, candidate,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0) {
      snprintf(temp_name, NASFS_UPLOAD_TEMP_SIZE, "%s", candidate);
      return fd;
    }
    if (errno != EEXIST) return uv_translate_sys_error(errno);
  }
  return UV_EEXIST;
}

int nasfs_storage_publish_upload(const nasfs_storage_t* storage,
                                 const char* temp_name, const char* name) {
  if (!is_flat_name((const uint8_t*)name, strlen(name))) return UV_EINVAL;

  struct stat st;
  if (fstatat(storage->root_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
    if (!S_ISREG(st.st_mode)) return UV_EINVAL;
    if (faccessat(storage->root_fd, name, W_OK,
                  AT_EACCESS | AT_SYMLINK_NOFOLLOW) < 0 &&
        errno != ENOENT)
      return uv_translate_sys_error(errno);
  } else if (errno != ENOENT) {
    return uv_translate_sys_error(errno);
  }

  if (renameat(storage->root_fd, temp_name, storage->root_fd, name) < 0)
    return uv_translate_sys_error(errno);
  return 0;
}

int nasfs_storage_discard_upload(const nasfs_storage_t* storage,
                                 const char* temp_name) {
  if (unlinkat(storage->root_fd, temp_name, 0) < 0 && errno != ENOENT)
    return uv_translate_sys_error(errno);
  return 0;
}
