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
 * @brief Turn the current process into a daemon.
 *
 * Performs the standard Unix double-fork method to properly daemonize
 * the process. This detaches the process from the controlling terminal
 * and allows it to run in the background independently.
 *
 * @return 0 on success. If an error occurs, the function will exit
 *         the process with a failure status.
 */
int daemonize(void);

#endif /* DAEMON_H */