#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uv.h>

#include "storage.h"

#if defined(__linux__)
#include <linux/magic.h>
#include <sys/vfs.h>
#elif defined(__APPLE__)
#include <sys/mount.h>
#endif

static const char upload_prefix[] = ".nasfs-upload.";
static const char unlocked_upload_prefix[] = ".nasfs-upload.unlocked.";

static int sweep_uploads(int root) {
  int scan = openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (scan < 0) return uv_translate_sys_error(errno);
  DIR* entries = fdopendir(scan);
  if (!entries) {
    int rc = uv_translate_sys_error(errno);
    close(scan);
    return rc;
  }

  int rc = 0;
  for (;;) {
    errno = 0;
    struct dirent* entry = readdir(entries);
    if (!entry) {
      if (errno) rc = uv_translate_sys_error(errno);
      break;
    }
    const char* name = entry->d_name;
    if (strncmp(name, upload_prefix, sizeof(upload_prefix) - 1) != 0) continue;
    const char* suffix = name + sizeof(upload_prefix) - 1;
    if (strlen(suffix) != 32 || strspn(suffix, "0123456789abcdef") != 32)
      continue;

    struct stat st;
    if (fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
      if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1)
        continue;
      if (unlinkat(root, name, 0) == 0) continue;
    }
    if (errno != ENOENT) {
      rc = uv_translate_sys_error(errno);
      break;
    }
  }
  closedir(entries);
  return rc;
}

static int can_coordinate_uploads(int root) {
#if defined(__linux__)
  struct statfs fs;
  return fstatfs(root, &fs) == 0 && fs.f_type != NFS_SUPER_MAGIC;
#elif defined(__APPLE__)
  struct statfs fs;
  return fstatfs(root, &fs) == 0 && strcmp(fs.f_fstypename, "nfs") != 0;
#else
  (void)root;
  return 1;
#endif
}

int nasfs_storage_init(nasfs_storage_t* storage, const char* directory) {
  storage->root_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (storage->root_fd < 0) return uv_translate_sys_error(errno);

  storage->uploads_locked = 0;
  // NFS can use client-local locks or share storage with local writers.
  if (!can_coordinate_uploads(storage->root_fd)) return 0;

  // A directory opened read-only may only support shared locks.
  // Only sweep under an exclusive lock, and only use sweepable names while
  // holding a shared lock for the lifetime of all uploads.
  int rc = 0;
  if (flock(storage->root_fd, LOCK_EX | LOCK_NB) == 0)
    rc = sweep_uploads(storage->root_fd);
  storage->uploads_locked = rc == 0 && flock(storage->root_fd, LOCK_SH) == 0;
  if (rc < 0) nasfs_storage_close(storage);
  return rc;
}

void nasfs_storage_close(nasfs_storage_t* storage) {
  if (storage->root_fd >= 0) close(storage->root_fd);
  storage->root_fd = -1;
}

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
  const char* prefix =
      storage->uploads_locked ? upload_prefix : unlocked_upload_prefix;
  size_t prefix_len = strlen(prefix);
  memcpy(candidate, prefix, prefix_len);
  for (int attempt = 0; attempt < 8; attempt++) {
    unsigned char random_id[16];
    randombytes_buf(random_id, sizeof(random_id));
    sodium_bin2hex(candidate + prefix_len, sizeof(candidate) - prefix_len,
                   random_id, sizeof(random_id));
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
