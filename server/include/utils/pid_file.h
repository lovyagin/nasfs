/* server/include/utils/pid_file.h -- PID file management
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Provides functions for handling process ID files for daemon processes.  */

#ifndef PID_FILE_H
#define PID_FILE_H

/* Create a PID file with the current process ID.
   Writes the current process ID to the file at PID_FILE_PATH.

   Returns 0 on success, or -1 on failure.  */
int create_pid_file(const char *pid_file_path);

/* Remove the PID file.
   Deletes the file at PID_FILE_PATH and logs the result.  */
void remove_pid_file(const char *pid_file_path);

/* Store the path of the PID file for later cleanup.
   Makes a copy of PATH to be used by cleanup_pid_file later.  */
void set_pid_file_path(const char *path);

/* Clean up the PID file when the program exits.
   Removes the PID file whose path was stored with set_pid_file_path.
   This function is intended to be registered with atexit().  */
void cleanup_pid_file(void);

#endif /* PID_FILE_H */
