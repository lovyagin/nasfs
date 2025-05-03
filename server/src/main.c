/* server/src/main.c -- Main server application file
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Entry point for the NASFS server application.  */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "config/config.h"
#include "logging/log.h"
#include "network/connections.h"
#include "network/server.h"

#define CONFIG_FILE "/etc/nasfs/nasfs.conf"

int
main (int argc, char *argv[])
{
  /* Parse command line arguments (if any)  */
  const char *config_file = CONFIG_FILE;
  /* if (argc > 1)
     {
       config_file = argv[1];
     }  */

  server_config_t config;
  if (load_config (config_file, &config) != 0)
    {
      fprintf (stderr, "Failed to load configuration\n");
      return EXIT_FAILURE;
    }

  /* Initialize logging  */
  log_init (config.log_file, config.log_level);
  log_all (LOG_INFO, "Starting NASFS server...");

  /* Setup network  */
  int server_socket = server_socket_setup (&config);
  if (server_socket < 0)
    {
      log_all (LOG_ERROR, "Failed to setup server socket");
      return EXIT_FAILURE;
    }

  /* Run server main loop  */
  log_all (LOG_INFO, "Server ready to accept connections");
  server_run (server_socket, &config);

  /* Cleanup  */
  log_all (LOG_INFO, "Server shutting down...");

  if (config.daemon_mode)
    remove_pid_file (config.pid_file);

  /* Free allocated config memory  */
  free (config.bind_address);
  free (config.log_file);
  free (config.pid_file);

  return EXIT_SUCCESS;
}
