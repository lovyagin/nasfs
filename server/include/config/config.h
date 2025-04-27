/* server/include/config/config.h -- Configuration handling interface
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Defines structures and functions for server configuration.  */

#ifndef CONFIG_H
#define CONFIG_H

/* Server configuration structure.
   Contains all configurable parameters for the server.  */
typedef struct
{
  char *bind_address;   /* IP address to bind the server to */
  int port;             /* Port number to listen on */
  int max_connections;  /* Maximum number of simultaneous connections */
  int client_timeout;   /* Client connection timeout in seconds */
  char *log_file;       /* Path to the log file */
  int log_level;        /* Minimum log level to record */
  int daemon_mode;      /* Whether to run as a daemon (1) or not (0) */
  char *pid_file;       /* Path to the PID file for daemon mode */
} server_config_t;

/* Load configuration from a file.
   Reads settings from FILENAME into CONFIG structure.

   Returns 0 on success, or -1 on failure.  */
int load_config (const char *filename, server_config_t *config);

/* Set default configuration values.
   Initializes CONFIG with sensible default values for all settings.  */
void set_defaults (server_config_t *config);

/* Trim whitespace from a string.
   Modifies STR in place to remove leading and trailing whitespace,
   and cuts off any part of the string that follows a '#' character.  */
void trim_string (char *str);

#endif /* CONFIG_H */
