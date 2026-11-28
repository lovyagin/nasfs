/* server/src/config/config.c -- Configuration file parser
   Copyright (C) 2025 Nikita Morozov (@NikitosKey)

   This file is part of NASFS server.
   Handles loading and parsing of server configuration files.  */

#ifdef HAVE_CONFIG_H
#include "config.h"

#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config/config.h"
#include "defaults.h"

server_config_t global_config;

#define NASFS_CONFIG_MAX_LINE 4096

/* Parse a positive integer option from the configuration file.
   Returns 0 on success and stores the parsed value in OUT_VALUE.  */
static int parse_config_int(const char* value, int* out_value) {
  char* endptr;
  long parsed;

  if (!value || !out_value) {
    return -1;
  }

  parsed = strtol(value, &endptr, 10);
  if (*value == '\0' || *endptr != '\0' || parsed < 0 || parsed > INT_MAX) {
    return -1;
  }

  *out_value = (int)parsed;
  return 0;
}

/* Double-quoted values can contain whitespace and #. Backslash can
   escape a quote or a backslash inside a quoted value. */
static int parse_config_line(char* line, size_t length, char** key,
                             char** value) {
  size_t leading = strspn(line, " \t\r\v\f");
  *value = NULL;
  if (leading >= length || line[leading] == '#') {
    *key = NULL;
    return 0;
  }

  *key = line + leading;
  char* cursor = *key + strcspn(*key, " \t\r\v\f#");
  if (!*cursor) return 0;
  char separator = *cursor;
  *cursor++ = '\0';
  if (separator == '#') return 0;
  cursor += strspn(cursor, " \t\r\v\f");
  if (!*cursor || *cursor == '#') return 0;

  if (*cursor != '"') {
    trim_string(cursor);
    *value = cursor;
    cursor[strcspn(cursor, " \t\r\v\f#")] = '\0';
    return 0;
  }

  *value = ++cursor;
  char* out = cursor;
  while (*cursor && *cursor != '"') {
    if (*cursor == '\\') {
      cursor++;
      if (*cursor != '\\' && *cursor != '"') return -1;
    }
    *out++ = *cursor++;
  }
  if (*cursor != '"') return -1;
  *out = '\0';
  cursor++;
  cursor += strspn(cursor, " \t\r\v\f");
  return !*cursor || *cursor == '#' ? 0 : -1;
}

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

  char line[NASFS_CONFIG_MAX_LINE + 1] = {0};
  size_t line_number = 0;
  int byte;
  while (!feof(file) && (byte = fgetc(file)) != EOF) {
    line_number++;
    size_t length = 0;
    for (; byte != EOF && byte != '\n'; byte = fgetc(file)) {
      if (length == NASFS_CONFIG_MAX_LINE || byte == '\0') {
        fprintf(stderr, "Invalid configuration line %zu: %s\n", line_number,
                byte == '\0' ? "embedded NUL byte" : "line exceeds 4096 bytes");
        fclose(file);
        return -1;
      }
      line[length++] = (char)byte;
    }
    if (ferror(file)) {
      fclose(file);
      return -1;
    }
    line[length] = '\0';

    char* key;
    char* value;
    if (parse_config_line(line, length, &key, &value) < 0) {
      fprintf(stderr, "Invalid quoted value on configuration line %zu\n",
              line_number);
      fclose(file);
      return -1;
    }
    if (!key) continue;

    if (!value) {
      if (strcmp(key, "AuthPassword") == 0) {
        free(config->auth_password);
        config->auth_password = NULL;
      }
      continue;
    }

    if (strcmp(key, "ListenAddr") == 0) {
      free(config->bind_address);
      config->bind_address = strdup(value);
      if (!config->bind_address) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "Port") == 0) {
      if (parse_config_int(value, &config->port) != 0 || config->port < 0 ||
          config->port > 65535) {
        fprintf(stderr, "Invalid Port value: %s\n", value);
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "MaxConn") == 0) {
      if (parse_config_int(value, &config->max_connections) != 0 ||
          config->max_connections <= 0) {
        fprintf(stderr, "Invalid MaxConn value: %s\n", value);
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "ClientTimeout") == 0) {
      if (parse_config_int(value, &config->client_timeout) != 0 ||
          config->client_timeout <= 0) {
        fprintf(stderr, "Invalid ClientTimeout value: %s\n", value);
        fclose(file);
        return -1;
      }
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
    } else if (strcmp(key, "AuthMethods") == 0) {
      free(config->auth_methods);
      config->auth_methods = strdup(value);
      if (!config->auth_methods) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "AuthPassword") == 0) {
      free(config->auth_password);
      config->auth_password = strdup(value);
      if (!config->auth_password) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "AuthorizedKeysFile") == 0) {
      free(config->authorized_keys_file);
      config->authorized_keys_file = strdup(value);
      if (!config->authorized_keys_file) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "PubKeyAuthAlgorithms") == 0) {
      free(config->pubkey_auth_algorithms);
      config->pubkey_auth_algorithms = strdup(value);
      if (!config->pubkey_auth_algorithms) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "ServerSigningSeed") == 0 ||
               strcmp(key, "AuthorPublicKey") == 0) {
      if (value[0] != '/') {
        fprintf(stderr, "%s requires an absolute path\n", key);
        fclose(file);
        return -1;
      }
      char** path = strcmp(key, "ServerSigningSeed") == 0
                        ? &config->server_signing_seed
                        : &config->author_public_key;
      free(*path);
      *path = strdup(value);
      if (!*path) {
        fclose(file);
        return -1;
      }
    } else if (strcmp(key, "VersionQuotaBytes") == 0 ||
               strcmp(key, "VersionRetentionSeconds") == 0 ||
               strcmp(key, "AttemptRetentionSeconds") == 0) {
      char* end;
      errno = 0;
      long long parsed = strtoll(value, &end, 10);
      if (errno || !*value || *end || parsed < 0 ||
          (strcmp(key, "VersionQuotaBytes") != 0 && parsed > INT_MAX)) {
        fprintf(stderr, "Invalid %s value: %s\n", key, value);
        fclose(file);
        return -1;
      }
      if (strcmp(key, "VersionQuotaBytes") == 0)
        config->version_quota = parsed;
      else if (strcmp(key, "VersionRetentionSeconds") == 0)
        config->version_retention = parsed;
      else
        config->attempt_retention = parsed;
    } else if (strcmp(key, "BlockSize") == 0) {
      int bs = 0;
      if (parse_config_int(value, &bs) != 0 || bs < 4096 || bs > 4194304) {
        fprintf(stderr, "Invalid BlockSize value: %s (must be 4096–4194304)\n",
                value);
        fclose(file);
        return -1;
      }
      config->block_size = bs;
    }
  }

  int failed = ferror(file);
  if (fclose(file) != 0 || failed) return -1;
  return 0;
}

/* Set default configuration values.
   Initializes CONFIG with sensible default values to be used when
   no configuration file is available or when options are not specified.  */
void set_defaults(server_config_t* config) {
  config->bind_address = strdup("127.0.0.1");
  config->port = NASFS_DEFAULT_PORT;
  config->max_connections = 10;
  config->client_timeout = 30;
  config->log_file = strdup("/var/log/nasfs-server.log");
  config->log_level = 0;   /* Info */
  config->daemon_mode = 0; /* Not in daemon mode by default */
  config->pid_file = strdup("/var/run/nasfs-server.pid");
  config->storage_dir = strdup(".");
  config->kex_algorithms = strdup("ML-KEM-512,Kyber512,ML-KEM-768,Kyber768");
  config->cipher_algorithms = strdup("xchacha20poly1305");
  config->auth_methods = strdup("password,publickey,password+publickey");
  config->auth_password = NULL;
  config->authorized_keys_file = strdup("/usr/local/etc/nasfs/authorized_keys");
  config->pubkey_auth_algorithms = strdup("ML-DSA-65,ML-DSA-44");
  config->block_size = 65536;
  config->version_retention = 86400;
  config->attempt_retention = 86400;
  config->version_quota = 0;
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
  free(config->auth_methods);
  free(config->auth_password);
  free(config->authorized_keys_file);
  free(config->pubkey_auth_algorithms);
  free(config->server_signing_seed);
  free(config->author_public_key);

  memset(config, 0, sizeof(*config));
}

/* Trim whitespace from a string and remove comments.
   Modifies STR in place to remove leading and trailing whitespace,
   and cuts off any part of the string that follows a '#' character.  */
void trim_string(char* str) {
  if (!str) return;

  char* end = strchr(str, '#');
  if (!end) end = str + strlen(str);
  while (end > str && isspace((unsigned char)end[-1])) end--;

  char* start = str;
  while (start < end && isspace((unsigned char)*start)) start++;
  size_t length = (size_t)(end - start);
  memmove(str, start, length);
  str[length] = '\0';
}
