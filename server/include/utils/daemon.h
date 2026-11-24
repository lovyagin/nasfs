/**
 * @file daemon.h
 * @brief Daemonization utilities for the NASFS server.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS server.
 * Provides functionality for running the server as a background daemon process.
 */

#ifndef DAEMON_H
#define DAEMON_H

/**
 * Detach via double fork. The original process exits with the startup result.
 * Returns the readiness pipe descriptor in the daemon, or -1 on setup error
 * before detaching. Close the descriptor on startup failure without writing.
 */
int daemonize(const char* pid_path);

/* Report startup success and consume the readiness pipe descriptor. */
int daemon_notify_ready(int status_fd);

#endif /* DAEMON_H */
