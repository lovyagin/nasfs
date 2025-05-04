/* server/include/utils/signal_handler.h -- Signal handling utilities
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Defines signal handling functions and global state for clean shutdown.  */

#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

#include <signal.h>

/* Flag indicating whether the server should continue running.
   Set to 0 when SIGTERM or SIGINT is received.  */
extern volatile sig_atomic_t server_running;

/* Signal handler for SIGTERM and SIGINT.
   Logs the signal and sets server_running to 0 for clean shutdown.
   SIGNO is the signal number that was received.  */
void signal_handler (int signo);

#endif /* SIGNAL_HANDLER_H */
