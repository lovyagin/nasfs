/* Linux integration-test fixture for deterministic process and I/O failures. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/vfs.h>
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

int unlinkat(int directory, const char* path, int flags) {
  const char* denied = getenv("NASFS_TEST_READONLY_ORPHAN");
  if (denied && strcmp(path, denied) == 0) {
    errno = EROFS;
    return -1;
  }
  return (int)syscall(SYS_unlinkat, directory, path, flags);
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

int fstatfs(int fd, struct statfs* fs) {
  typedef int (*statfs_fn)(int, struct statfs*);
  statfs_fn actual = (statfs_fn)dlsym(RTLD_NEXT, "fstatfs");
  if (!actual) abort();
  int result = actual(fd, fs);
  struct stat st;
  const char* nfs = getenv("NASFS_TEST_DIRECTORY_NFS");
  if (result == 0 && nfs && *nfs && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode))
    fs->f_type = NFS_SUPER_MAGIC;
  return result;
}

int flock(int fd, int operation) {
  typedef int (*flock_fn)(int, int);
  flock_fn actual = (flock_fn)dlsym(RTLD_NEXT, "flock");
  if (!actual) abort();
  const char* mode = getenv("NASFS_TEST_DIRECTORY_LOCK_ERROR");
  struct stat st;
  if (mode && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
    if (strcmp(mode, "all") == 0) {
      errno = ENOTSUP;
      return -1;
    }
    if (strcmp(mode, "exclusive") == 0 && (operation & LOCK_EX) != 0) {
      errno = EBADF;
      return -1;
    }
  }
  return actual(fd, operation);
}

int uv_queue_work(uv_loop_t* loop, uv_work_t* request, uv_work_cb work,
                  uv_after_work_cb done) {
  typedef int (*queue_fn)(uv_loop_t*, uv_work_t*, uv_work_cb, uv_after_work_cb);
  queue_fn actual = (queue_fn)dlsym(RTLD_NEXT, "uv_queue_work");
  if (!actual) abort();
  if (getenv("NASFS_TEST_OPEN_SUBMISSION_ERROR")) return UV_EBUSY;
  return actual(loop, request, work, done);
}

static uv_buf_t opening_io(uv_buf_t buffer, const char* phase) {
  const char* selected = getenv("NASFS_TEST_OPEN_IO");
  if (!selected || strcmp(selected, phase) != 0) return buffer;
  const char* gate = getenv("NASFS_TEST_OPEN_IO_GATE");
  if (gate) {
    fprintf(stderr, "Test fixture blocked %s\n", phase);
    const struct timespec pause = {.tv_nsec = 10000000};
    while (access(gate, F_OK) != 0) nanosleep(&pause, NULL);
  } else {
    buffer.len--;
  }
  return buffer;
}

int uv_fs_read(uv_loop_t* loop, uv_fs_t* request, uv_file fd,
               const uv_buf_t buffers[], unsigned count, int64_t offset,
               uv_fs_cb callback) {
  typedef int (*read_fn)(uv_loop_t*, uv_fs_t*, uv_file, const uv_buf_t*,
                         unsigned, int64_t, uv_fs_cb);
  read_fn actual = (read_fn)dlsym(RTLD_NEXT, "uv_fs_read");
  if (!actual) abort();
  if (!callback && count == 1 &&
      matches_file(fd, "NASFS_TEST_OPEN_IO_OBJECT")) {
    const char* phase = offset == 0 ? "get-header" : "get-slot";
    uv_buf_t buffer = opening_io(buffers[0], phase);
    return actual(loop, request, fd, &buffer, count, offset, callback);
  }
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
  if (!callback && offset == 0 && count == 1 &&
      matches_file(fd, "NASFS_TEST_OPEN_IO_OBJECT")) {
    uv_buf_t buffer = opening_io(buffers[0], "put-header");
    return actual(loop, request, fd, &buffer, count, offset, callback);
  }
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
  const char* prefix = getenv("NASFS_TEST_BLOCK_PREFIX");
  if ((prefix ? length == sizeof(uint32_t) : length > 4096) && gate &&
      matches_file(fd, "NASFS_TEST_BLOCK_READS") && access(gate, F_OK) != 0) {
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

static void wait_startup_checkpoint(const char* phase) {
  const char* expected = getenv("NASFS_TEST_STARTUP_PHASE");
  const char* gate = getenv("NASFS_TEST_STARTUP_GATE");
  if (!expected || !gate || strcmp(phase, expected) != 0) return;
  fprintf(stderr, "Test fixture startup phase: %s\n", phase);
  const struct timespec pause = {.tv_nsec = 10000000};
  while (access(gate, F_OK) != 0) nanosleep(&pause, NULL);
}

ssize_t write(int fd, const void* data, size_t length) {
  if (getenv("NASFS_TEST_STARTUP_PHASE") && data && length == 1 &&
      *(const char*)data == '1') {
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode))
      wait_startup_checkpoint("before-daemon-status");
  }
  return syscall(SYS_write, fd, data, length);
}

int uv_signal_start(uv_signal_t* handle, uv_signal_cb callback, int signum) {
  typedef int (*start_fn)(uv_signal_t*, uv_signal_cb, int);
  start_fn actual = (start_fn)dlsym(RTLD_NEXT, "uv_signal_start");
  if (!actual) abort();
  if (signum == SIGINT) wait_startup_checkpoint("before-sigint");
  if (signum == SIGTERM) wait_startup_checkpoint("before-sigterm");
  return actual(handle, callback, signum);
}

int uv_tcp_bind(uv_tcp_t* handle, const struct sockaddr* address,
                unsigned flags) {
  typedef int (*bind_fn)(uv_tcp_t*, const struct sockaddr*, unsigned);
  bind_fn actual = (bind_fn)dlsym(RTLD_NEXT, "uv_tcp_bind");
  if (!actual) abort();
  wait_startup_checkpoint("before-bind");
  return actual(handle, address, flags);
}

int uv_listen(uv_stream_t* stream, int backlog, uv_connection_cb callback) {
  typedef int (*listen_fn)(uv_stream_t*, int, uv_connection_cb);
  listen_fn actual = (listen_fn)dlsym(RTLD_NEXT, "uv_listen");
  if (!actual) abort();
  wait_startup_checkpoint("before-listen");
  return actual(stream, backlog, callback);
}
