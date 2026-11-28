#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "version_store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/acl.h>
#endif

static const char version_directory[] = ".nasfs-v2";
static const char staging_prefix[] = ".attempt.";
static const char version_prefix[] = "v-";

static int private_directory(int fd, int strict) {
  struct stat st;
  unsigned mask = strict ? 077u : 022u;
  if (fstat(fd, &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & mask))
    return 0;
#ifdef __APPLE__
  acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
  if (!acl) return errno == ENOENT;
  acl_entry_t entry;
  int rc = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  int empty = rc < 0 && errno == EINVAL;
  acl_free(acl);
  return empty;
#else
  return 1;
#endif
}

static int db_run(sqlite3* db, const char* sql) {
  return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : UV_EIO;
}

static int db_prepare(sqlite3* db, const char* sql, sqlite3_stmt** stmt) {
  return sqlite3_prepare_v2(db, sql, -1, stmt, NULL) == SQLITE_OK ? 0 : UV_EIO;
}

static void version_name(char name[67], const uint8_t digest[32]) {
  memcpy(name, version_prefix, sizeof(version_prefix) - 1);
  sodium_bin2hex(name + sizeof(version_prefix) - 1, 65, digest, 32);
}

static int version_exists(sqlite3* db, const uint8_t digest[32]) {
  sqlite3_stmt* stmt = NULL;
  int rc = db_prepare(db, "SELECT 1 FROM versions WHERE digest=?1", &stmt);
  if (!rc &&
      sqlite3_bind_blob(stmt, 1, digest, 32, SQLITE_STATIC) == SQLITE_OK) {
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW)
      rc = 1;
    else if (step != SQLITE_DONE)
      rc = UV_EIO;
  } else {
    rc = UV_EIO;
  }
  sqlite3_finalize(stmt);
  return rc;
}

static int sweep_orphans(nasfs_version_store_t* store) {
  int scan_fd =
      openat(store->directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (scan_fd < 0) return uv_translate_sys_error(errno);
  DIR* scan = fdopendir(scan_fd);
  if (!scan) {
    int rc = uv_translate_sys_error(errno);
    close(scan_fd);
    return rc;
  }
  int rc = 0;
  for (;;) {
    errno = 0;
    const struct dirent* entry = readdir(scan);
    if (!entry) {
      if (errno) rc = uv_translate_sys_error(errno);
      break;
    }
    const char* name = entry->d_name;
    if (strncmp(name, staging_prefix, sizeof(staging_prefix) - 1) == 0 &&
        strlen(name) == sizeof(staging_prefix) - 1 + 32 &&
        strspn(name + sizeof(staging_prefix) - 1, "0123456789abcdef") == 32) {
      /* A crashed writer cannot hold the daemon lifetime lock at startup. */
    } else if (strncmp(name, version_prefix, sizeof(version_prefix) - 1) == 0 &&
               strlen(name) == sizeof(version_prefix) - 1 + 64) {
      uint8_t digest[32];
      if (sodium_hex2bin(digest, sizeof(digest), name + 2, 64, NULL, NULL,
                         NULL) != 0)
        continue;
      int exists = version_exists(store->catalog, digest);
      if (exists < 0) {
        rc = exists;
        break;
      }
      if (exists) continue;
    } else {
      continue;
    }
    struct stat st;
    if (fstatat(store->directory, name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 077u) == 0 && unlinkat(store->directory, name, 0) < 0 &&
        errno != ENOENT) {
      rc = uv_translate_sys_error(errno);
      break;
    }
  }
  closedir(scan);
  return rc;
}

int nasfs_version_store_open(nasfs_version_store_t* store, const char* root,
                             int64_t quota, int64_t retention) {
  *store = (nasfs_version_store_t){
      .directory = -1, .lock = -1, .quota = quota, .retention = retention};
  int rc = uv_mutex_init(&store->mutex);
  if (rc < 0) return rc;

  char* path = realpath(root, NULL);
  int root_fd =
      path ? open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
  rc = UV_EACCES;
  if (root_fd < 0 || !private_directory(root_fd, 0)) goto cleanup;
  if (mkdirat(root_fd, version_directory, 0700) < 0 && errno != EEXIST)
    goto cleanup;
  store->directory = openat(root_fd, version_directory,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (store->directory < 0 || !private_directory(store->directory, 1))
    goto cleanup;
  struct stat st_root, st_store;
  if (fstat(root_fd, &st_root) < 0 || fstat(store->directory, &st_store) < 0 ||
      st_root.st_dev != st_store.st_dev)
    goto cleanup;

  store->lock =
      openat(store->directory, ".daemon.lock",
             O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
  struct stat lock_stat;
  if (store->lock < 0 || fstat(store->lock, &lock_stat) < 0 ||
      !S_ISREG(lock_stat.st_mode) || lock_stat.st_uid != geteuid() ||
      lock_stat.st_nlink != 1 || (lock_stat.st_mode & 077u) != 0)
    goto cleanup;
  if (flock(store->lock, LOCK_EX | LOCK_NB) < 0) {
    rc = uv_translate_sys_error(errno);
    goto cleanup;
  }
  struct stat catalog;
  if (fstatat(store->directory, "catalog.db", &catalog, AT_SYMLINK_NOFOLLOW) ==
      0) {
    if (!S_ISREG(catalog.st_mode) || catalog.st_uid != geteuid() ||
        catalog.st_nlink != 1 || (catalog.st_mode & 077u) != 0)
      goto cleanup;
  } else if (errno == ENOENT) {
    int fd = openat(store->directory, "catalog.db",
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 || close(fd) < 0) goto cleanup;
  } else {
    goto cleanup;
  }
  char* db_path = sqlite3_mprintf("%s/%s/catalog.db", path, version_directory);
  if (!db_path) {
    rc = UV_ENOMEM;
    goto cleanup;
  }
  int status =
      sqlite3_open_v2(db_path, &store->catalog,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, NULL);
  sqlite3_free(db_path);
  if (status != SQLITE_OK) {
    rc = UV_EIO;
    goto cleanup;
  }
  rc = db_run(
      store->catalog,
      "PRAGMA synchronous=FULL;"
      "CREATE TABLE IF NOT EXISTS names ("
      "name TEXT PRIMARY KEY,id BLOB UNIQUE NOT NULL,current BLOB NOT NULL);"
      "CREATE TABLE IF NOT EXISTS versions ("
      "digest BLOB PRIMARY KEY,id BLOB NOT NULL,size INTEGER NOT NULL,"
      "replaced INTEGER);");
  if (!rc) rc = sweep_orphans(store);

cleanup:
  if (root_fd >= 0) close(root_fd);
  free(path);
  if (rc < 0) nasfs_version_store_close(store);
  return rc;
}

void nasfs_version_store_close(nasfs_version_store_t* store) {
  sqlite3_close(store->catalog);
  if (store->lock >= 0) close(store->lock);
  if (store->directory >= 0) close(store->directory);
  uv_mutex_destroy(&store->mutex);
}

static int resolve_locked(nasfs_version_store_t* store, const char* name,
                          uint8_t id[16], uint8_t digest[32]) {
  sqlite3_stmt* stmt = NULL;
  int rc = db_prepare(store->catalog,
                      "SELECT id,current FROM names WHERE name=?1", &stmt);
  if (!rc && sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC) == SQLITE_OK) {
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW && sqlite3_column_bytes(stmt, 0) == 16 &&
        sqlite3_column_bytes(stmt, 1) == 32) {
      memcpy(id, sqlite3_column_blob(stmt, 0), 16);
      memcpy(digest, sqlite3_column_blob(stmt, 1), 32);
    } else {
      rc = step == SQLITE_DONE ? UV_ENOENT : UV_EIO;
    }
  } else {
    rc = UV_EIO;
  }
  sqlite3_finalize(stmt);
  return rc;
}

int nasfs_version_resolve(nasfs_version_store_t* store, const char* name,
                          uint8_t id[16], uint8_t digest[32]) {
  uv_mutex_lock(&store->mutex);
  int rc = resolve_locked(store, name, id, digest);
  uv_mutex_unlock(&store->mutex);
  return rc;
}

int nasfs_version_open(nasfs_version_store_t* store, const uint8_t id[16],
                       const uint8_t digest[32]) {
  sqlite3_stmt* stmt = NULL;
  uv_mutex_lock(&store->mutex);
  int rc =
      db_prepare(store->catalog,
                 "SELECT size FROM versions WHERE id=?1 AND digest=?2", &stmt);
  if (!rc && sqlite3_bind_blob(stmt, 1, id, 16, SQLITE_STATIC) == SQLITE_OK &&
      sqlite3_bind_blob(stmt, 2, digest, 32, SQLITE_STATIC) == SQLITE_OK) {
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
      char name[67];
      version_name(name, digest);
      int fd = openat(store->directory, name,
                      O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
      if (fd < 0) {
        rc = uv_translate_sys_error(errno);
      } else {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_size == sqlite3_column_int64(stmt, 0)) {
          rc = fd;
        } else {
          close(fd);
          rc = UV_EIO;
        }
      }
    } else {
      rc = step == SQLITE_DONE ? UV_ENOENT : UV_EIO;
    }
  } else {
    rc = UV_EIO;
  }
  sqlite3_finalize(stmt);
  uv_mutex_unlock(&store->mutex);
  return rc;
}

int nasfs_version_stage(nasfs_version_store_t* store,
                        char name[NASFS_VERSION_TEMP_NAME]) {
  uint8_t random[16];
  char candidate[NASFS_VERSION_TEMP_NAME];
  memcpy(candidate, staging_prefix, sizeof(staging_prefix) - 1);
  for (int i = 0; i < 8; ++i) {
    randombytes_buf(random, sizeof(random));
    sodium_bin2hex(candidate + sizeof(staging_prefix) - 1, 33, random,
                   sizeof(random));
    int fd = openat(store->directory, candidate,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
      strcpy(name, candidate);
      return fd;
    }
    if (errno != EEXIST) return uv_translate_sys_error(errno);
  }
  return UV_EEXIST;
}

void nasfs_version_discard(nasfs_version_store_t* store, const char* staging) {
  if (*staging) unlinkat(store->directory, staging, 0);
}

static int check_quota(nasfs_version_store_t* store, int64_t size) {
  if (!store->quota) return 0;
  sqlite3_stmt* stmt = NULL;
  int rc = db_prepare(store->catalog,
                      "SELECT coalesce(sum(size),0) FROM versions", &stmt);
  if (!rc) {
    if (sqlite3_step(stmt) != SQLITE_ROW)
      rc = UV_EIO;
    else if (size > store->quota ||
             sqlite3_column_int64(stmt, 0) > store->quota - size)
      rc = UV_ENOSPC;
  }
  sqlite3_finalize(stmt);
  return rc;
}

int nasfs_version_reserve(nasfs_version_store_t* store, int64_t size) {
  if (size < 0) return UV_EINVAL;
  if (!store->quota) return 0;
  uv_mutex_lock(&store->mutex);
  int rc = size > store->quota - store->reserved_bytes
               ? UV_ENOSPC
               : check_quota(store, size + store->reserved_bytes);
  if (!rc) store->reserved_bytes += size;
  uv_mutex_unlock(&store->mutex);
  return rc;
}

void nasfs_version_release(nasfs_version_store_t* store, int64_t size) {
  if (!store->quota || !size) return;
  uv_mutex_lock(&store->mutex);
  store->reserved_bytes -= size;
  uv_mutex_unlock(&store->mutex);
}

static int record_version(nasfs_version_store_t* store, const char* name,
                          const nasfs_version_header_t* meta,
                          const uint8_t digest[32], int64_t size, int replace) {
  sqlite3_stmt* stmt = NULL;
  int rc = db_prepare(store->catalog,
                      "INSERT INTO versions(digest,id,size) VALUES(?1,?2,?3)",
                      &stmt);
  if (rc ||
      sqlite3_bind_blob(stmt, 1, digest, 32, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_blob(stmt, 2, meta->id, 16, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_int64(stmt, 3, size) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return UV_EIO;
  }
  sqlite3_finalize(stmt);
  stmt = NULL;
  rc = db_prepare(store->catalog,
                  replace
                      ? "UPDATE names SET current=?3 WHERE name=?1 AND id=?2"
                      : "INSERT INTO names(name,id,current) VALUES(?1,?2,?3)",
                  &stmt);
  if (rc || sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_blob(stmt, 2, meta->id, 16, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_blob(stmt, 3, digest, 32, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE ||
      sqlite3_changes(store->catalog) != 1) {
    sqlite3_finalize(stmt);
    return UV_EIO;
  }
  sqlite3_finalize(stmt);
  if (!replace) return 0;

  stmt = NULL;
  rc = db_prepare(store->catalog,
                  "UPDATE versions SET replaced=unixepoch() WHERE digest=?1",
                  &stmt);
  if (rc ||
      sqlite3_bind_blob(stmt, 1, meta->parent, 32, SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE || sqlite3_changes(store->catalog) != 1)
    rc = UV_EIO;
  sqlite3_finalize(stmt);
  return rc;
}

int nasfs_version_publish(nasfs_version_store_t* store, const char* staging,
                          const char* name, const nasfs_version_header_t* meta,
                          const uint8_t digest[32], int64_t size) {
  char committed[67];
  version_name(committed, digest);
  int linked = 0;
  uv_mutex_lock(&store->mutex);
  int rc = db_run(store->catalog, "BEGIN IMMEDIATE");
  if (rc < 0) goto unlock;
  uint8_t id[16], current[32];
  int replace = resolve_locked(store, name, id, current);
  if (replace == 0) {
    if (sodium_memcmp(id, meta->id, sizeof(id)) != 0 ||
        sodium_memcmp(current, meta->parent, sizeof(current)) != 0)
      rc = UV_EEXIST;
  } else if (replace == UV_ENOENT) {
    if (!sodium_is_zero(meta->parent, sizeof(meta->parent))) rc = UV_EEXIST;
  } else {
    rc = replace;
  }

  if (!rc) rc = check_quota(store, size);
  if (!rc) rc = record_version(store, name, meta, digest, size, replace == 0);
  if (!rc) {
    if (linkat(store->directory, staging, store->directory, committed, 0) < 0) {
      rc = uv_translate_sys_error(errno);
    } else {
      linked = 1;
      if (fsync(store->directory) < 0) rc = uv_translate_sys_error(errno);
    }
  }
  if (!rc) rc = db_run(store->catalog, "COMMIT");
  if (rc < 0) {
    db_run(store->catalog, "ROLLBACK");
    // On a commit I/O error leave the immutable file for startup
    // reconciliation.
    if (linked && version_exists(store->catalog, digest) == 0)
      unlinkat(store->directory, committed, 0);
  }

unlock:
  uv_mutex_unlock(&store->mutex);
  return rc;
}

int nasfs_version_collect(nasfs_version_store_t* store) {
  uv_mutex_lock(&store->mutex);
  sqlite3_stmt* stmt = NULL;
  int rc = db_prepare(store->catalog,
                      "DELETE FROM versions WHERE replaced IS NOT NULL "
                      "AND replaced<=unixepoch()-?1",
                      &stmt);
  if (!rc) {
    if (sqlite3_bind_int64(stmt, 1, store->retention) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE)
      rc = UV_EIO;
  }
  sqlite3_finalize(stmt);
  if (!rc) {
    // Do not touch staging during pruning. Existing GET readers hold their fd.
    int scan_fd =
        openat(store->directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR* scan = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (!scan) {
      rc = uv_translate_sys_error(errno);
      if (scan_fd >= 0) close(scan_fd);
    } else {
      const struct dirent* entry;
      while ((entry = readdir(scan)) != NULL) {
        if (strncmp(entry->d_name, version_prefix, 2) != 0 ||
            strlen(entry->d_name) != 66)
          continue;
        uint8_t digest[32];
        if (sodium_hex2bin(digest, sizeof(digest), entry->d_name + 2, 64, NULL,
                           NULL, NULL) != 0)
          continue;
        int exists = version_exists(store->catalog, digest);
        if (exists < 0 ||
            (exists == 0 && unlinkat(store->directory, entry->d_name, 0) < 0)) {
          rc = UV_EIO;
          break;
        }
      }
      closedir(scan);
    }
  }
  uv_mutex_unlock(&store->mutex);
  return rc;
}
