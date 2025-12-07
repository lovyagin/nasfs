/* server/src/utils/signal_handler.c -- Signal handling utilities
   Copyright (C) 2025  Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles server signal processing for clean shutdown.  */

#include "utils/signal_handler.h"

#include "logging/log.h"

/* Flag indicating whether the server should continue running.
   Set to 0 when SIGTERM or SIGINT is received.  */
volatile sig_atomic_t server_running = 1;

/* Signal handler for SIGTERM and SIGINT.
   Logs the signal and sets server_running to 0 for clean shutdown.
   SIGNO is the signal number that was received.  */
void signal_handler(int signo) {
  log_all(LOG_WARNING, "Signal received: %u", signo);
  if (signo == SIGTERM || signo == SIGINT) server_running = 0;
}
