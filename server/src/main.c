/* server/src/main.c -- Main server application file
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Entry point for the NASFS server application.  */

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "config/config.h"
#include "logging/log.h"
#include "network/server.h"
#include "utils/daemon.h"
#include "utils/pid_file.h"
#include "utils/signal_handler.h"

#define CONFIG_FILE "/usr/local/etc/nasfs/nasfs.conf"

void
print_usage (const char *program_name)
{
  printf ("Usage: %s [OPTIONS]\n\n", program_name);
  printf ("Options:\n");
  printf ("  -c, --config FILE    Specify configuration file (default: %s)\n",
          CONFIG_FILE);
  printf ("  -n, --no-daemon      Run in foreground, do not daemonize\n");
  printf ("  -h, --help           Display this help and exit\n");
}

int
main (int argc, char *argv[])
{
  /* Parse command line arguments */
  const char *config_file = CONFIG_FILE;
  int no_daemon = 0;

  struct option long_options[] = { { "config", required_argument, 0, 'c' },
                                   { "no-daemon", no_argument, 0, 'n' },
                                   { "help", no_argument, 0, 'h' },
                                   { 0, 0, 0, 0 } };

  int opt;
  int option_index = 0;

  while ((opt = getopt_long (argc, argv, "c:nh", long_options, &option_index))
         != -1)
    {
      switch (opt)
        {
        case 'c':
          config_file = optarg;
          break;
        case 'n':
          no_daemon = 1;
          break;
        case 'h':
          print_usage (argv[0]);
          return EXIT_SUCCESS;
        default:
          print_usage (argv[0]);
          return EXIT_FAILURE;
        }
    }

  server_config_t config;
  if (load_config (config_file, &config) != 0)
    {
      fprintf (stderr, "Failed to load configuration\n");
      return EXIT_FAILURE;
    }

  /* Override daemon mode if --no-daemon option was specified */
  if (no_daemon)
    {
      config.daemon_mode = 0;
    }

  /* Initialize logging  */
  log_init (config.log_file, config.log_level);
  log_all (LOG_INFO, "Starting NASFS server...");

  /* Register signal handlers  */
  if (signal (SIGTERM, signal_handler) == SIG_ERR
      || signal (SIGINT, signal_handler) == SIG_ERR)
    {
      log_all (LOG_ERROR, "Failed to register signal handlers");
      return EXIT_FAILURE;
    }

  if (config.daemon_mode)
    {
      log_all (LOG_INFO, "Starting in daemon mode");
      if (daemonize () != 0)
        {
          log_all (LOG_ERROR, "Failed to daemonize");
          return EXIT_FAILURE;
        }
      log_all (LOG_INFO, "Successfully daemonized, PID: %d", getpid ());

      /* Create PID file  */
      if (create_pid_file (config.pid_file) != 0)
        {
          log_all (LOG_ERROR, "Failed to create PID file");
          return EXIT_FAILURE;
        }

      /* Register cleanup handler for PID file  */
      atexit (cleanup_pid_file);
      set_pid_file_path (config.pid_file);
    }

  /* Check current working dir */
  char cwd[PATH_MAX];
  if (getcwd (cwd, sizeof (cwd)) != NULL)
    {
      log_all (LOG_DEBUG, "Current working dir: %s\n", cwd);
    }
  else
    {
      log_all (LOG_ERROR, "getcwd() error");
    }

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
  free (config.file_dir);

  return EXIT_SUCCESS;
}
