/* server/include/utils/daemon.h -- Daemonization utilities
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Provides functionality for running the server as a daemon process.  */

#ifndef DAEMON_H
#define DAEMON_H

/* Turn the process into a daemon.
   Performs the standard Unix double-fork method to properly daemonize
   the process, detaching it from the controlling terminal and running
   it in the background.

   Returns 0 on success, or exits with failure on error.  */
int daemonize(void);

#endif /* DAEMON_H */
