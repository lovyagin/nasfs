/* server/src/utils/pid_file.c -- PID file management for the NASFS server
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles creating, removing, and cleaning up PID files for daemon processes.
 */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logging/log.h"
#include "utils/pid_file.h"

static char* pid_file_path;
static int pid_fd = -1;

static int owns_pid_path(int fd, const char* path) {
  struct stat opened;
  struct stat named;
  return fstat(fd, &opened) == 0 && lstat(path, &named) == 0 &&
         opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}

int create_pid_file(const char* path) {
  char* saved_path = strdup(path);
  if (!saved_path) return -1;
  int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0644);
  if (fd < 0) {
    free(saved_path);
    return -1;
  }

  struct stat info;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      flock(fd, LOCK_EX | LOCK_NB) != 0 || !owns_pid_path(fd, path)) {
    close(fd);
    free(saved_path);
    return -1;
  }

  if (ftruncate(fd, 0) != 0 || dprintf(fd, "%d\n", getpid()) < 0) {
    if (owns_pid_path(fd, path)) unlink(path);
    close(fd);
    free(saved_path);
    return -1;
  }

  pid_fd = fd;
  pid_file_path = saved_path;
  log_all(LOG_INFO, "Created PID file: %s with PID %d", path, getpid());
  return 0;
}

void cleanup_pid_file(void) {
  if (pid_fd < 0) return;
  if (!owns_pid_path(pid_fd, pid_file_path) || unlink(pid_file_path) != 0) {
    log_all(LOG_WARNING, "Could not remove PID file: %s", pid_file_path);
  } else {
    log_all(LOG_INFO, "Removed PID file: %s", pid_file_path);
  }
  close(pid_fd);
  pid_fd = -1;
  free(pid_file_path);
  pid_file_path = NULL;
}
