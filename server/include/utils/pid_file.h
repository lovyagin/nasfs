/**
 * @file pid_file.h
 * @brief PID file management interface for the NASFS server daemon.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS server.
 * Provides functions for handling process ID files for daemon processes,
 * allowing the system to track the running instance of the server.
 */

#ifndef PID_FILE_H
#define PID_FILE_H

/**
 * @brief Create a PID file with the current process ID.
 *
 * Writes the current process ID to the specified file path. This is typically
 * used when the server starts up, especially in daemon mode.
 *
 * @param pid_file_path The path where the PID file should be created.
 * @return 0 on success, or -1 on failure.
 */
int create_pid_file(const char* pid_file_path);

/** Release the process's locked PID file. */
void cleanup_pid_file(void);

#endif /* PID_FILE_H */