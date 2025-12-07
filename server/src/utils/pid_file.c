/* server/src/utils/pid_file.c -- PID file management for the NASFS server
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles creating, removing, and cleaning up PID files for daemon processes.
 */

#include "utils/pid_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging/log.h"

/* Path to the PID file used for cleanup at program exit.  */
static char *pid_file_path = NULL;

/* Create a PID file with the current process ID.
   Writes the current process ID to the file at PATH.

   Returns 0 on success, or -1 on failure.  */
int create_pid_file(const char *path) {
  FILE *pid_file = fopen(path, "w");
  if (pid_file == NULL) {
    log_all(LOG_ERROR, "Cannot create PID file: %s", path);
    return -1;
  }

  fprintf(pid_file, "%d\n", getpid());
  fclose(pid_file);

  log_all(LOG_INFO, "Created PID file: %s with PID %d", path, getpid());
  return 0;
}

/* Remove the PID file at the specified path.
   Attempts to delete the file at PATH and logs the result.  */
void remove_pid_file(const char *path) {
  if (unlink(path) != 0) {
    log_all(LOG_WARNING, "Could not remove PID file: %s", path);
  } else {
    log_all(LOG_INFO, "Removed PID file: %s", path);
  }
}

/* Store the PID file path for later cleanup.
   Saves the PATH in a static variable for use by cleanup_pid_file.
   Frees any previously stored path.  */
void set_pid_file_path(const char *path) {
  if (pid_file_path) {
    free(pid_file_path);
  }
  pid_file_path = strdup(path);
}

/* Cleanup function for removing the PID file at exit.
   Should be registered with atexit() to ensure the PID file
   is removed when the program terminates.  */
void cleanup_pid_file(void) {
  if (pid_file_path) {
    remove_pid_file(pid_file_path);
    free(pid_file_path);
    pid_file_path = NULL;
  }
}
