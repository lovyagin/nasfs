/* Linux integration-test fixture for deterministic process and I/O failures. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <uv.h>

int linkat(int olddir, const char* oldpath, int newdir, const char* newpath,
           int flags) {
  const char* checkpoint = getenv("NASFS_TEST_SALT_CHECKPOINT");
  int publishing_salt = checkpoint && strcmp(newpath, "master.salt") == 0;
  if (publishing_salt && strcmp(checkpoint, "before") == 0) {
    kill(getpid(), SIGKILL);
  }
  int result =
      (int)syscall(SYS_linkat, olddir, oldpath, newdir, newpath, flags);
  if (result == 0 && publishing_salt && strcmp(checkpoint, "after") == 0) {
    kill(getpid(), SIGKILL);
  }
  return result;
}

static int matches_file(uv_file fd, const char* setting) {
  const char* expected = getenv(setting);
  if (!expected || !*expected) return 0;
  char descriptor[64];
  snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
  char path[4096];
  ssize_t length = readlink(descriptor, path, sizeof(path) - 1);
  if (length < 0) return 0;
  path[length] = '\0';
  const char* name = strrchr(path, '/');
  return name && strncmp(name + 1, expected, strlen(expected)) == 0;
}

int uv_fs_read(uv_loop_t* loop, uv_fs_t* request, uv_file fd,
               const uv_buf_t buffers[], unsigned count, int64_t offset,
               uv_fs_cb callback) {
  typedef int (*read_fn)(uv_loop_t*, uv_fs_t*, uv_file, const uv_buf_t*,
                         unsigned, int64_t, uv_fs_cb);
  read_fn actual = (read_fn)dlsym(RTLD_NEXT, "uv_fs_read");
  if (!actual) abort();
  if (matches_file(fd, "NASFS_TEST_READ_FAILURE")) fd = -1;
  return actual(loop, request, fd, buffers, count, offset, callback);
}

int uv_fs_close(uv_loop_t* loop, uv_fs_t* request, uv_file fd,
                uv_fs_cb callback) {
  typedef int (*close_fn)(uv_loop_t*, uv_fs_t*, uv_file, uv_fs_cb);
  close_fn actual = (close_fn)dlsym(RTLD_NEXT, "uv_fs_close");
  if (!actual) abort();
  int fail = !callback && matches_file(fd, "NASFS_TEST_CLOSE_FAILURE");
  int result = actual(loop, request, fd, callback);
  return fail && result == 0 ? UV_EIO : result;
}

typedef struct {
  uv_timer_t timer;
  uv_fs_t* request;
  void* request_data;
  uv_fs_cb callback;
} delayed_write_t;

static unsigned queued_writes;
static unsigned peak_writes;

static void free_delay(uv_handle_t* handle) { free(handle->data); }

static void complete_delay(uv_timer_t* timer) {
  const char* gate = getenv("NASFS_TEST_WRITE_GATE");
  if (gate && access(gate, F_OK) != 0) return;
  uv_timer_stop(timer);
  delayed_write_t* delayed = timer->data;
  delayed->request->data = delayed->request_data;
  queued_writes--;
  delayed->callback(delayed->request);
  uv_close((uv_handle_t*)timer, free_delay);
}

static void delay_write_completion(uv_fs_t* request) {
  delayed_write_t* delayed = request->data;
  if (uv_timer_init(request->loop, &delayed->timer) != 0) abort();
  delayed->timer.data = delayed;
  if (uv_timer_start(&delayed->timer, complete_delay, 150, 50) != 0) abort();
}

int uv_fs_write(uv_loop_t* loop, uv_fs_t* request, uv_file fd,
                const uv_buf_t buffers[], unsigned count, int64_t offset,
                uv_fs_cb callback) {
  typedef int (*write_fn)(uv_loop_t*, uv_fs_t*, uv_file, const uv_buf_t*,
                          unsigned, int64_t, uv_fs_cb);
  write_fn actual = (write_fn)dlsym(RTLD_NEXT, "uv_fs_write");
  if (!actual) abort();
  if (!callback || !matches_file(fd, "NASFS_TEST_DELAY_WRITES"))
    return actual(loop, request, fd, buffers, count, offset, callback);

  delayed_write_t* delayed = malloc(sizeof(*delayed));
  if (!delayed) abort();
  delayed->request = request;
  delayed->request_data = request->data;
  delayed->callback = callback;
  request->data = delayed;
  int result =
      actual(loop, request, fd, buffers, count, offset, delay_write_completion);
  if (result < 0) {
    request->data = delayed->request_data;
    free(delayed);
    return result;
  }
  queued_writes++;
  if (queued_writes > peak_writes) {
    peak_writes = queued_writes;
    fprintf(stderr, "Test fixture pending writes: %u\n", peak_writes);
  }
  return result;
}

int rename(const char* oldpath, const char* newpath) {
  typedef int (*rename_fn)(const char*, const char*);
  rename_fn actual = (rename_fn)dlsym(RTLD_NEXT, "rename");
  if (!actual) abort();
  int result = actual(oldpath, newpath);
  const char* name = strrchr(oldpath, '/');
  name = name ? name + 1 : oldpath;
  if (result == 0 && getenv("NASFS_TEST_CRASH_AFTER_DOWNLOAD") &&
      strncmp(name, ".nasfs-download.", sizeof(".nasfs-download.") - 1) == 0) {
    kill(getpid(), SIGKILL);
  }
  return result;
}

int fclose(FILE* stream) {
  typedef int (*fclose_fn)(FILE*);
  fclose_fn actual = (fclose_fn)dlsym(RTLD_NEXT, "fclose");
  if (!actual) abort();
  int fail = matches_file(fileno(stream), "NASFS_TEST_FCLOSE_FAILURE");
  int result = actual(stream);
  if (fail && result == 0) {
    errno = EIO;
    return EOF;
  }
  return result;
}

int link(const char* oldpath, const char* newpath) {
  typedef int (*link_fn)(const char*, const char*);
  link_fn actual = (link_fn)dlsym(RTLD_NEXT, "link");
  if (!actual) abort();
  int result = actual(oldpath, newpath);
  const char* checkpoint = getenv("NASFS_TEST_CRASH_AFTER_KEY_LINK");
  if (result == 0 && checkpoint && strcmp(checkpoint, newpath) == 0)
    kill(getpid(), SIGKILL);
  return result;
}

static void block_write_if_requested(int fd, off64_t offset) {
  const char* gate = getenv("NASFS_TEST_BLOCK_WRITE_GATE");
  if (offset > 0 && gate && matches_file(fd, "NASFS_TEST_BLOCK_WRITES") &&
      access(gate, F_OK) != 0) {
    static atomic_uint blocked_writes;
    unsigned blocked = atomic_fetch_add(&blocked_writes, 1) + 1;
    fprintf(stderr, "Test fixture blocked writes: %u\n", blocked);
    const struct timespec pause = {.tv_nsec = 10000000};
    while (access(gate, F_OK) != 0) nanosleep(&pause, NULL);
    atomic_fetch_sub(&blocked_writes, 1);
  }
}

ssize_t pwrite64(int fd, const void* buffer, size_t count, off64_t offset) {
  typedef ssize_t (*pwrite_fn)(int, const void*, size_t, off64_t);
  pwrite_fn actual = (pwrite_fn)dlsym(RTLD_NEXT, "pwrite64");
  if (!actual) abort();
  block_write_if_requested(fd, offset);
  return actual(fd, buffer, count, offset);
}

ssize_t pwritev64(int fd, const struct iovec* buffers, int count,
                  off64_t offset) {
  typedef ssize_t (*pwritev_fn)(int, const struct iovec*, int, off64_t);
  pwritev_fn actual = (pwritev_fn)dlsym(RTLD_NEXT, "pwritev64");
  if (!actual) abort();
  block_write_if_requested(fd, offset);
  return actual(fd, buffers, count, offset);
}

int openat(int directory, const char* path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
    va_list args;
    va_start(args, flags);
    mode = (mode_t)va_arg(args, int);
    va_end(args);
  }

  const char* gate = getenv("NASFS_TEST_OPEN_GATE");
  if (gate &&
      strncmp(path, ".nasfs-upload.", sizeof(".nasfs-upload.") - 1) == 0 &&
      access(gate, F_OK) != 0) {
    fprintf(stderr, "Test fixture blocked upload open\n");
    const struct timespec pause = {.tv_nsec = 10000000};
    while (access(gate, F_OK) != 0) nanosleep(&pause, NULL);
  }
  return (int)syscall(SYS_openat, directory, path, flags, mode);
}

static void block_record_read(int fd, size_t length) {
  const char* gate = getenv("NASFS_TEST_READ_GATE");
  if (length > 4096 && gate && matches_file(fd, "NASFS_TEST_BLOCK_READS") &&
      access(gate, F_OK) != 0) {
    fprintf(stderr, "Test fixture blocked record read\n");
    const struct timespec pause = {.tv_nsec = 10000000};
    while (access(gate, F_OK) != 0) nanosleep(&pause, NULL);
  }
}

ssize_t pread64(int fd, void* buffer, size_t length, off64_t offset) {
  typedef ssize_t (*pread_fn)(int, void*, size_t, off64_t);
  pread_fn actual = (pread_fn)dlsym(RTLD_NEXT, "pread64");
  if (!actual) abort();
  block_record_read(fd, length);
  return actual(fd, buffer, length, offset);
}

ssize_t preadv64(int fd, const struct iovec* buffers, int count,
                 off64_t offset) {
  typedef ssize_t (*preadv_fn)(int, const struct iovec*, int, off64_t);
  preadv_fn actual = (preadv_fn)dlsym(RTLD_NEXT, "preadv64");
  if (!actual) abort();
  if (count > 0) block_record_read(fd, buffers[0].iov_len);
  return actual(fd, buffers, count, offset);
}

int renameat(int olddir, const char* oldpath, int newdir, const char* newpath) {
  typedef int (*renameat_fn)(int, const char*, int, const char*);
  renameat_fn actual = (renameat_fn)dlsym(RTLD_NEXT, "renameat");
  if (!actual) abort();
  const char* gate = getenv("NASFS_TEST_RENAME_GATE");
  if (gate &&
      strncmp(oldpath, ".nasfs-upload.", sizeof(".nasfs-upload.") - 1) == 0 &&
      access(gate, F_OK) != 0) {
    fprintf(stderr, "Test fixture blocked upload rename\n");
    const struct timespec pause = {.tv_nsec = 10000000};
    while (access(gate, F_OK) != 0) nanosleep(&pause, NULL);
  }
  return actual(olddir, oldpath, newdir, newpath);
}
