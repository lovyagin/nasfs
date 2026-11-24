/* server/src/utils/daemon.c -- Server daemonization utilities
   Copyright (C) 2025  Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Provides functionality to run the server as a daemon process.  */

#include "utils/daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "logging/log.h"
#include "utils/pid_file.h"

static int wait_for_child(pid_t pid) {
  int status;
  pid_t result;
  do {
    result = waitpid(pid, &status, 0);
  } while (result < 0 && errno == EINTR);
  return result == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void wait_for_daemon(pid_t pid, int read_fd, const char* pid_path) {
  char ready;
  ssize_t count;
  do {
    count = read(read_fd, &ready, sizeof(ready));
  } while (count < 0 && errno == EINTR);
  close(read_fd);
  if (count == sizeof(ready) && ready == '1') _exit(EXIT_SUCCESS);

  // EOF also covers a daemon that exited before reporting readiness.
  wait_for_child(pid);
  cleanup_failed_startup_pid(pid_path, pid);
  _exit(EXIT_FAILURE);
}

int daemonize(const char* pid_path) {
  int status_pipe[2];
  if (pipe(status_pipe) < 0) {
    log_all(LOG_ERROR, "Cannot open daemon startup pipe");
    return -1;
  }

  fflush(NULL);
  pid_t pid = fork();
  if (pid != 0) {
    close(status_pipe[0]);
    close(status_pipe[1]);
    if (pid < 0) {
      log_all(LOG_ERROR, "Failed to fork daemon process");
      return -1;
    }
    if (wait_for_child(pid)) exit(EXIT_SUCCESS);
    fprintf(stderr, "NASFS daemon failed to start. See the configured log.\n");
    exit(EXIT_FAILURE);
  }

  if (setsid() < 0 || signal(SIGHUP, SIG_IGN) == SIG_ERR) {
    log_all(LOG_ERROR, "Cannot detach daemon session");
    _exit(EXIT_FAILURE);
  }

  pid = fork();
  if (pid < 0) {
    log_all(LOG_ERROR, "Failed to fork detached daemon process");
    _exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    close(status_pipe[1]);
    wait_for_daemon(pid, status_pipe[0], pid_path);
  }
  close(status_pipe[0]);

  umask(0);
  if (chdir("/") < 0) {
    log_all(LOG_ERROR, "Failed to change directory");
    _exit(EXIT_FAILURE);
  }

  int null_fd = open("/dev/null", O_RDWR);
  if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
      dup2(null_fd, STDOUT_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0) {
    log_all(LOG_ERROR, "Cannot redirect daemon standard descriptors");
    _exit(EXIT_FAILURE);
  }
  close(null_fd);
  return status_pipe[1];
}

int daemon_notify_ready(int status_fd) {
  const char ready = '1';
  ssize_t count;
  do {
    count = write(status_fd, &ready, sizeof(ready));
  } while (count < 0 && errno == EINTR);
  close(status_fd);
  return count == sizeof(ready) ? 0 : -1;
}
