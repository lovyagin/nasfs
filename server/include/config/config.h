/**
 * @file config.h
 * @brief Configuration handling interface
 * @copyright Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * This file is part of NASFS server.
 * Defines structures and functions for server configuration.
 */

#ifndef CONFIG_H
#define CONFIG_H

/**
 * @struct server_config_t
 * @brief Server configuration structure.
 *
 * Contains all configurable parameters for the server.
 */
typedef struct {
  char* bind_address;  /**< IP address to bind the server to */
  int port;            /**< Port number to listen on */
  int max_connections; /**< Maximum number of simultaneous connections */
  int client_timeout;  /**< Client connection timeout in seconds */
  char* log_file;      /**< Path to the log file */
  int log_level;       /**< Minimum log level to record */
  int daemon_mode;     /**< Whether to run as a daemon (1) or not (0) */
  char* pid_file;      /**< Path to the PID file for daemon mode */
  char* storage_dir; /**< Directory for serving files; future can become a mount
                        point */
  char* kex_algorithms; /**< Allowed PQC KEX algorithms in preference order */
  char* cipher_algorithms; /**< Allowed control-channel ciphers in preference
                              order */
  char* auth_methods;      /**< Allowed authentication methods */
  char* auth_password;     /**< Shared password for password authentication */
  char* authorized_keys_file;   /**< Path to PQ public keys allowed for login */
  char* pubkey_auth_algorithms; /**< Allowed PQ signature algorithms */
} server_config_t;

/**
 * @brief Global server configuration instance.
 */
extern server_config_t global_config;

/**
 * @brief Load configuration from a file.
 *
 * Reads settings from the specified filename into the configuration structure.
 *
 * @param filename The path to the configuration file.
 * @param config Pointer to the configuration structure to populate.
 * @return 0 on success, or -1 on failure.
 */
int load_config(const char* filename, server_config_t* config);

/**
 * @brief Set default configuration values.
 *
 * Initializes the configuration structure with sensible default values
 * for all settings.
 *
 * @param config Pointer to the configuration structure to initialize.
 */
void set_defaults(server_config_t* config);

/**
 * @brief Release memory owned by a configuration structure.
 *
 * Frees all dynamically allocated string fields and resets the structure
 * to zeroed state.
 *
 * @param config Pointer to the configuration structure to release.
 */
void free_config(server_config_t* config);

/**
 * @brief Trim whitespace from a string.
 *
 * Modifies the string in place to remove leading and trailing whitespace,
 * and cuts off any part of the string that follows a '#' character.
 *
 * @param str The string to trim.
 */
void trim_string(char* str);

#endif /* CONFIG_H */
