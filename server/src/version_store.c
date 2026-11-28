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

static int valid_staging_name(const char* name) {
  size_t prefix = sizeof(staging_prefix) - 1;
  return strncmp(name, staging_prefix, prefix) == 0 &&
         strlen(name) == prefix + 32 &&
         strspn(name + prefix, "0123456789abcdef") == 32;
}

static int staging_live(sqlite3* db, const char* name) {
  sqlite3_stmt* stmt = NULL;
  int rc = db_prepare(
      db, "SELECT 1 FROM attempts WHERE staging=?1 AND result=0", &stmt);
  if (rc || sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC) != SQLITE_OK) {
    rc = UV_EIO;
  } else {
    int step = sqlite3_step(stmt);
    rc = step == SQLITE_ROW ? 1 : step == SQLITE_DONE ? 0 : UV_EIO;
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
    if (valid_staging_name(name)) {
      int live = staging_live(store->catalog, name);
      if (live < 0) {
        rc = live;
        break;
      }
      if (live) continue;
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
                             int64_t quota, int64_t retention,
                             int64_t attempt_retention) {
  *store = (nasfs_version_store_t){.directory = -1,
                                   .lock = -1,
                                   .quota = quota,
                                   .retention = retention,
                                   .attempt_retention = attempt_retention};
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
      "replaced INTEGER);"
      "CREATE TABLE IF NOT EXISTS attempts ("
      "token BLOB PRIMARY KEY,scope BLOB NOT NULL,header BLOB NOT NULL,"
      "name TEXT NOT NULL,staging TEXT NOT NULL,size INTEGER NOT NULL,"
      "sequence INTEGER NOT NULL,result INTEGER NOT NULL,digest BLOB NOT NULL,"
      "expires INTEGER NOT NULL);"
      "UPDATE attempts SET result=4 WHERE result=0 AND expires<=unixepoch();");
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
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
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

static int check_quota(nasfs_version_store_t* store, int64_t size,
                       const nasfs_attempt_t* current) {
  if (!store->quota) return 0;
  sqlite3_stmt* stmt = NULL;
  const char* sql =
      "SELECT coalesce(sum(size),0) FROM ("
      "SELECT size FROM versions UNION ALL SELECT size FROM attempts "
      "WHERE result=0 AND (?1 IS NULL OR token<>?1))";
  int rc = db_prepare(store->catalog, sql, &stmt);
  if (!rc && current &&
      sqlite3_bind_blob(stmt, 1, current->token, 32, SQLITE_STATIC) !=
          SQLITE_OK)
    rc = UV_EIO;
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
               : check_quota(store, size + store->reserved_bytes, NULL);
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

static int attempt_owned(nasfs_version_store_t* store,
                         const nasfs_attempt_t* attempt,
                         const nasfs_version_header_t* header, const char* name,
                         char staging[NASFS_VERSION_TEMP_NAME], uint64_t* seq,
                         int* result) {
  sqlite3_stmt* stmt = NULL;
  const char* sql =
      "SELECT scope,header,name,staging,sequence,result,digest,"
      "expires>unixepoch() FROM attempts WHERE token=?1";
  int rc = db_prepare(store->catalog, sql, &stmt);
  if (rc || sqlite3_bind_blob(stmt, 1, attempt->token, 32, SQLITE_STATIC) !=
                SQLITE_OK) {
    sqlite3_finalize(stmt);
    return UV_EIO;
  }
  int step = sqlite3_step(stmt);
  if (step != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return step == SQLITE_DONE ? UV_ENOENT : UV_EIO;
  }
  uint8_t wire[NASFS_VERSION_HEADER_SIZE];
  nasfs_version_encode(wire, header);
  if (sqlite3_column_bytes(stmt, 0) != 32 ||
      sodium_memcmp(sqlite3_column_blob(stmt, 0), attempt->scope, 32) != 0 ||
      sqlite3_column_bytes(stmt, 1) != sizeof(wire) ||
      sodium_memcmp(sqlite3_column_blob(stmt, 1), wire, sizeof(wire)) != 0 ||
      !sqlite3_column_text(stmt, 2) ||
      strcmp((const char*)sqlite3_column_text(stmt, 2), name) != 0 ||
      sqlite3_column_bytes(stmt, 6) != 32 ||
      sodium_memcmp(sqlite3_column_blob(stmt, 6), attempt->digest, 32) != 0) {
    rc = UV_EACCES;
  } else if (!sqlite3_column_int(stmt, 7)) {
    rc = UV_ETIMEDOUT;
  } else {
    const char* filename = (const char*)sqlite3_column_text(stmt, 3);
    int64_t saved = sqlite3_column_int64(stmt, 4);
    int saved_result = sqlite3_column_int(stmt, 5);
    if (!filename || !valid_staging_name(filename) || saved < 0 ||
        saved_result < 0 || saved_result > 3 ||
        (uint64_t)saved > nasfs_version_record_count(header)) {
      rc = UV_EIO;
    } else {
      memcpy(staging, filename, strlen(filename) + 1);
      *seq = (uint64_t)saved;
      *result = saved_result;
    }
  }
  sqlite3_finalize(stmt);
  return rc;
}

static int record_attempt(nasfs_version_store_t* store,
                          const nasfs_attempt_t* attempt,
                          const nasfs_version_header_t* header,
                          const char* name, const char* staging) {
  sqlite3_stmt* stmt = NULL;
  uint8_t wire[NASFS_VERSION_HEADER_SIZE];
  nasfs_version_encode(wire, header);
  const char* sql =
      "INSERT INTO attempts(token,scope,header,name,staging,size,"
      "sequence,result,digest,expires) "
      "VALUES(?1,?2,?3,?4,?5,?6,0,0,?7,unixepoch()+?8)";
  int rc = db_prepare(store->catalog, sql, &stmt);
  if (rc ||
      sqlite3_bind_blob(stmt, 1, attempt->token, 32, SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_bind_blob(stmt, 2, attempt->scope, 32, SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_bind_blob(stmt, 3, wire, sizeof(wire), SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_bind_text(stmt, 4, name, -1, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_text(stmt, 5, staging, -1, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_int64(stmt, 6, nasfs_version_file_size(header)) !=
          SQLITE_OK ||
      sqlite3_bind_blob(stmt, 7, attempt->digest, 32, SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_bind_int64(stmt, 8, store->attempt_retention) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE)
    rc = UV_EIO;
  sqlite3_finalize(stmt);
  return rc;
}

static int checkpoint_position(const nasfs_version_header_t* header,
                               uint64_t seq, int64_t* offset) {
  uint32_t length;
  if (seq == 0) {
    *offset = 0;
    return 0;
  }
  if (seq == nasfs_version_record_count(header)) {
    *offset = nasfs_version_file_size(header);
    return *offset < 0 ? UV_EINVAL : 0;
  }
  return nasfs_version_record(header, seq, offset, &length) < 0 ? UV_EINVAL : 0;
}

static int restore_stage(nasfs_version_store_t* store, const char* staging,
                         const nasfs_version_header_t* header, uint64_t seq,
                         crypto_generichash_state* index) {
  int fd = openat(store->directory, staging,
                  O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return uv_translate_sys_error(errno);
  struct stat st;
  int rc = UV_EIO;
  int64_t end;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
      st.st_uid != geteuid() || (st.st_mode & 077u) ||
      checkpoint_position(header, seq, &end) < 0 || st.st_size < end)
    goto cleanup;
  if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
    rc = UV_EBUSY;
    goto cleanup;
  }
  if (ftruncate(fd, (off_t)end) < 0) goto cleanup;
  for (uint64_t i = 0; i < seq; i++) {
    int64_t offset;
    uint32_t length;
    uint8_t row[NASFS_BLOCK_META_SIZE];
    nasfs_block_meta_t meta;
    if (nasfs_version_record(header, i, &offset, &length) < 0 ||
        pread(fd, row, sizeof(row), (off_t)offset) != sizeof(row) ||
        protocol_decode_block_meta(row, sizeof(row), &meta) < 0 ||
        meta.seq_num != i || meta.size != length)
      goto cleanup;
    nasfs_version_index_add(index, &meta);
  }
  return fd;

cleanup:
  close(fd);
  return rc;
}

int nasfs_version_attempt_open(nasfs_version_store_t* store,
                               const nasfs_attempt_t* attempt,
                               const nasfs_version_header_t* header,
                               const char* name,
                               char staging[NASFS_VERSION_TEMP_NAME],
                               uint64_t* seq, int* result,
                               crypto_generichash_state* index) {
  nasfs_version_index_init(index);
  uv_mutex_lock(&store->mutex);
  int rc = attempt_owned(store, attempt, header, name, staging, seq, result);
  if (rc == UV_ENOENT) {
    int64_t size = nasfs_version_file_size(header);
    rc = store->quota && size > store->quota - store->reserved_bytes
             ? UV_ENOSPC
             : check_quota(store, size + store->reserved_bytes, NULL);
    if (rc == 0) {
      int fd = nasfs_version_stage(store, staging);
      if (fd < 0) {
        rc = fd;
      } else if (flock(fd, LOCK_EX | LOCK_NB) < 0 ||
                 fsync(store->directory) < 0 ||
                 record_attempt(store, attempt, header, name, staging) < 0) {
        close(fd);
        nasfs_version_discard(store, staging);
        staging[0] = '\0';
        rc = UV_EIO;
      } else {
        rc = fd;
      }
    }
  } else if (rc == 0 && !*result) {
    rc = restore_stage(store, staging, header, *seq, index);
  } else if (rc == 0) {
    // A completed journal entry pins the result even after version collection.
    rc = UV_EALREADY;
  }
  uv_mutex_unlock(&store->mutex);
  return rc;
}

int nasfs_version_checkpoint(nasfs_version_store_t* store,
                             const nasfs_attempt_t* attempt, int fd,
                             uint64_t next) {
  if (fsync(fd) < 0) return uv_translate_sys_error(errno);
  uv_mutex_lock(&store->mutex);
  sqlite3_stmt* stmt = NULL;
  const char* sql =
      "UPDATE attempts SET sequence=?2,expires=unixepoch()+?3 "
      "WHERE token=?1 AND result=0 AND sequence<=?2";
  int rc = db_prepare(store->catalog, sql, &stmt);
  if (rc ||
      sqlite3_bind_blob(stmt, 1, attempt->token, 32, SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_bind_int64(stmt, 2, (int64_t)next) != SQLITE_OK ||
      sqlite3_bind_int64(stmt, 3, store->attempt_retention) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE || sqlite3_changes(store->catalog) != 1)
    rc = UV_EIO;
  sqlite3_finalize(stmt);
  uv_mutex_unlock(&store->mutex);
  return rc;
}

static int attempt_result(nasfs_version_store_t* store,
                          const nasfs_attempt_t* attempt, int result) {
  sqlite3_stmt* stmt = NULL;
  const char* sql =
      "UPDATE attempts SET result=?2,expires=unixepoch()+?3 "
      "WHERE token=?1 AND result=0";
  int rc = db_prepare(store->catalog, sql, &stmt);
  if (rc ||
      sqlite3_bind_blob(stmt, 1, attempt->token, 32, SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_bind_int(stmt, 2, result) != SQLITE_OK ||
      sqlite3_bind_int64(stmt, 3, store->attempt_retention) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE || sqlite3_changes(store->catalog) != 1)
    rc = UV_EIO;
  sqlite3_finalize(stmt);
  return rc;
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
                          const uint8_t digest[32], int64_t size,
                          const nasfs_attempt_t* attempt) {
  char committed[67];
  version_name(committed, digest);
  int linked = 0;
  uv_mutex_lock(&store->mutex);
  if (store->quota && !attempt) store->reserved_bytes -= size;
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

  if (!rc) rc = check_quota(store, size, attempt);
  if (!rc) rc = record_version(store, name, meta, digest, size, replace == 0);
  if (!rc) {
    if (linkat(store->directory, staging, store->directory, committed, 0) < 0) {
      rc = uv_translate_sys_error(errno);
    } else {
      linked = 1;
      if (fsync(store->directory) < 0) rc = uv_translate_sys_error(errno);
    }
  }
  if (!rc && attempt) rc = attempt_result(store, attempt, 1);
  if (!rc) rc = db_run(store->catalog, "COMMIT");
  if (rc < 0) {
    db_run(store->catalog, "ROLLBACK");
    if (linked) {
      int exists = version_exists(store->catalog, digest);
      if (exists == 0) unlinkat(store->directory, committed, 0);
      if (exists > 0) rc = 0;
      if (exists < 0) rc = UV_EAGAIN;
    }
    if (attempt && (rc == UV_EEXIST || rc == UV_ENOSPC) &&
        attempt_result(store, attempt, rc == UV_EEXIST ? 2 : 3) < 0)
      rc = UV_EAGAIN;
  }

unlock:
  uv_mutex_unlock(&store->mutex);
  return rc;
}

static int next_expired_attempt(nasfs_version_store_t* store, uint8_t token[32],
                                int have_cursor,
                                char staging[NASFS_VERSION_TEMP_NAME]) {
  sqlite3_stmt* stmt = NULL;
  const char* sql =
      "SELECT token,staging FROM attempts WHERE result=0 AND "
      "expires<=unixepoch() "
      "AND (?1 IS NULL OR token>?1) ORDER BY token LIMIT 1";
  int rc = db_prepare(store->catalog, sql, &stmt);
  if (!rc && have_cursor &&
      sqlite3_bind_blob(stmt, 1, token, 32, SQLITE_TRANSIENT) != SQLITE_OK)
    rc = UV_EIO;
  if (!rc) {
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
      const char* name = (const char*)sqlite3_column_text(stmt, 1);
      if (sqlite3_column_bytes(stmt, 0) != 32 || !name ||
          !valid_staging_name(name)) {
        rc = UV_EIO;
      } else {
        memcpy(token, sqlite3_column_blob(stmt, 0), 32);
        memcpy(staging, name, strlen(name) + 1);
        rc = 1;
      }
    } else if (step != SQLITE_DONE) {
      rc = UV_EIO;
    }
  }
  sqlite3_finalize(stmt);
  return rc;
}

static int expire_attempt(nasfs_version_store_t* store,
                          const uint8_t token[32]) {
  sqlite3_stmt* stmt = NULL;
  int rc = db_prepare(
      store->catalog,
      "UPDATE attempts SET result=4 WHERE token=?1 AND result=0", &stmt);
  if (rc || sqlite3_bind_blob(stmt, 1, token, 32, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE)
    rc = UV_EIO;
  sqlite3_finalize(stmt);
  return rc;
}

static int collect_expired_attempts(nasfs_version_store_t* store) {
  uint8_t token[32];
  char staging[NASFS_VERSION_TEMP_NAME];
  int have_cursor = 0;
  for (;;) {
    int rc = next_expired_attempt(store, token, have_cursor, staging);
    if (rc <= 0) return rc;
    have_cursor = 1;
    int fd = openat(store->directory, staging,
                    O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 && errno != ENOENT) return uv_translate_sys_error(errno);
    if (fd >= 0) {
      struct stat st;
      if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
          st.st_uid != geteuid() || (st.st_mode & 077u) != 0) {
        close(fd);
        return UV_EACCES;
      }
      if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        rc = uv_translate_sys_error(errno);
        close(fd);
        if (rc == UV_EAGAIN) continue;
        return rc;
      }
    }
    rc = expire_attempt(store, token);
    if (rc == 0 && fd >= 0 && unlinkat(store->directory, staging, 0) < 0 &&
        errno != ENOENT)
      rc = uv_translate_sys_error(errno);
    if (fd >= 0) close(fd);
    if (rc < 0) return rc;
  }
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
  if (!rc) rc = collect_expired_attempts(store);
  if (!rc) {
    // Version collection leaves staging to the attempt journal. Existing GET
    // readers hold their fd.
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
  if (!rc)
    rc = db_run(
        store->catalog,
        "DELETE FROM attempts WHERE result<>0 AND expires<=unixepoch()-604800");
  uv_mutex_unlock(&store->mutex);
  return rc;
}
