/* server/src/config/config.c -- Configuration file parser
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles loading and parsing of server configuration files.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config/config.h"

server_config_t global_config;

/* Load configuration from a file.
   Reads configuration settings from FILENAME and stores them in CONFIG.
   Default values are set first, then overridden by values in the file.

   Returns 0 on success, or -1 on failure.  */
int load_config(const char* filename, server_config_t* config) {
  FILE* file = fopen(filename, "r");
  if (!file) {
    fprintf(stderr, "Error opening configuration file: %s\n", filename);
    return -1;
  }

  set_defaults(config);

  char line[512];
  while (fgets(line, sizeof(line), file)) {
    if (line[0] == '#' || line[0] == '\n') continue;

    line[strcspn(line, "\n")] = 0;

    trim_string(line);

    char* key = strtok(line, " \t");
    if (!key) continue;

    char* value = strtok(NULL, " \t#");
    if (!value) continue;

    if (strcmp(key, "ListenAddr") == 0) {
      free(config->bind_address);
      config->bind_address = strdup(value);
      if (!config->bind_address) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "Port") == 0) {
      config->port = atoi(value);
    } else if (strcmp(key, "MaxConn") == 0) {
      config->max_connections = atoi(value);
    } else if (strcmp(key, "ClientTimeout") == 0) {
      config->client_timeout = atoi(value);
    } else if (strcmp(key, "LogFile") == 0) {
      free(config->log_file);
      config->log_file = strdup(value);
      if (!config->log_file) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "LogLevel") == 0) {
      if (strcmp(value, "Debug") == 0) {
        config->log_level = 0;
      } else if (strcmp(value, "Info") == 0) {
        config->log_level = 1;
      } else if (strcmp(value, "Warning") == 0) {
        config->log_level = 2;
      } else if (strcmp(value, "Error") == 0) {
        config->log_level = 3;
      }
    } else if (strcmp(key, "DaemonMode") == 0) {
      if (strcmp(value, "Yes") == 0 || strcmp(value, "yes") == 0 ||
          strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
          strcmp(value, "True") == 0) {
        config->daemon_mode = 1;
      } else {
        config->daemon_mode = 0;
      }
    } else if (strcmp(key, "PidFile") == 0) {
      free(config->pid_file);
      config->pid_file = strdup(value);
      if (!config->pid_file) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "StorageDir") == 0) {
      free(config->storage_dir);
      config->storage_dir = strdup(value);
      if (!config->storage_dir) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "KexAlgorithms") == 0) {
      free(config->kex_algorithms);
      config->kex_algorithms = strdup(value);
      if (!config->kex_algorithms) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "CipherAlgorithms") == 0) {
      free(config->cipher_algorithms);
      config->cipher_algorithms = strdup(value);
      if (!config->cipher_algorithms) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    }
  }

  fclose(file);
  return 0;
}

/* Set default configuration values.
   Initializes CONFIG with sensible default values to be used when
   no configuration file is available or when options are not specified.  */
void set_defaults(server_config_t* config) {
  config->bind_address = strdup("127.0.0.1");
  config->port = 8080;
  config->max_connections = 10;
  config->client_timeout = 30;
  config->log_file = strdup("/var/log/nasfs-server.log");
  config->log_level = 0;   /* Info */
  config->daemon_mode = 0; /* Not in daemon mode by default */
  config->pid_file = strdup("/var/run/nasfs-server.pid");
  config->storage_dir = strdup(".");
  config->kex_algorithms = strdup("ML-KEM-512,Kyber512,ML-KEM-768,Kyber768");
  config->cipher_algorithms = strdup("xchacha20poly1305");
}

/* Release configuration resources.
   Frees dynamically allocated strings stored in CONFIG and resets all fields
   to zero so the structure can be reused safely.  */
void free_config(server_config_t* config) {
  if (!config) {
    return;
  }

  free(config->bind_address);
  free(config->log_file);
  free(config->pid_file);
  free(config->storage_dir);
  free(config->kex_algorithms);
  free(config->cipher_algorithms);

  memset(config, 0, sizeof(*config));
}

/* Trim whitespace from a string and remove comments.
   Modifies STR in place to remove leading and trailing whitespace,
   and cuts off any part of the string that follows a '#' character.  */
void trim_string(char* str) {
  if (!str) return;

  char* end = str + strlen(str) - 1;

  while (isspace(*str)) str++;
  while (isspace(*end)) end--;

  *(end + 1) = '\0';

  char* comment_start = strchr(str, '#');
  if (comment_start) *comment_start = '\0';
}
