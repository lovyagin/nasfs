/* server/src/utils/daemon.c -- Server daemonization utilities
   Copyright (C) 2025  Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Provides functionality to run the server as a daemon process.  */

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "logging/log.h"

/* Daemonize the server process.
   Follows the standard Unix double-fork method to properly daemonize:
   1. First fork and exit parent
   2. Create new session with setsid()
   3. Ignore SIGHUP
   4. Second fork and exit parent
   5. Change working directory to root
   6. Close all standard file descriptors
   7. Reopen stdin, stdout, stderr to /dev/null

   Returns 0 on success, or exits with failure on error.  */
int daemonize(void) {
  pid_t pid;

  pid = fork();
  if (pid < 0) {
    log_all(LOG_ERROR, "Failed to fork daemon process");
    exit(EXIT_FAILURE);
  }
  if (pid > 0) exit(EXIT_SUCCESS);
  log_all(LOG_DEBUG, "Fork 1 daemon process with PID %d", pid);

  if (setsid() < 0) {
    log_all(LOG_ERROR, "Setsid failure");
    exit(EXIT_FAILURE);
  }

  signal(SIGHUP, SIG_IGN);

  pid = fork();
  if (pid < 0) {
    log_all(LOG_ERROR, "Fork 2 failure");
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    log_all(LOG_DEBUG, "Fork 2 daemon process with PID %d", pid);
    exit(EXIT_SUCCESS);
  }

  umask(0);

  if (chdir("/") < 0) {
    log_all(LOG_ERROR, "Failed to change directory");
    exit(EXIT_FAILURE);
  }
  log_all(LOG_DEBUG, "Changed directory to /");

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  open("/dev/null", O_RDONLY); /* stdin */
  open("/dev/null", O_WRONLY); /* stdout */
  open("/dev/null", O_RDWR);   /* stderr */

  dup(STDIN_FILENO);
  dup(STDIN_FILENO);

  return 0;
}
