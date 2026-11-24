/**
 * @file test_config.c
 * @brief Unit tests for NASFS server configuration parsing.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config/config.h"

#define FULL_PASSWORD_LENGTH (4096 - (sizeof("AuthPassword ") - 1))

static int write_test_config(char* path, size_t path_len) {
  FILE* file;
  int fd;

  snprintf(path, path_len, "/tmp/nasfs-config-test-XXXXXX");
  fd = mkstemp(path);
  if (fd < 0) {
    return -1;
  }

  file = fdopen(fd, "w");
  if (!file) {
    close(fd);
    unlink(path);
    return -1;
  }

  fprintf(file, "ListenAddr 10.0.0.1\n");
  fprintf(file, " \t  \t\n");
  fprintf(file, "\t Port 4242 \t # comment\n");
  fprintf(file, "StorageDir \"/srv/NAS # Files\" # comment\n");
  fprintf(file, "KexAlgorithms Kyber512,ML-KEM-512\n");
  fprintf(file, "CipherAlgorithms xchacha20poly1305\n");
  fprintf(file, "AuthMethods password+publickey\n");
  fprintf(file, "AuthorizedKeysFile /srv/nasfs/authorized_keys\n");
  fprintf(file, "PubKeyAuthAlgorithms ML-DSA-65\n");
  fputs("AuthPassword ", file);
  for (size_t i = 0; i < FULL_PASSWORD_LENGTH; i++) fputc('x', file);
  // The final line is exactly at the limit and has no newline.
  return fclose(file);
}

int main(void) {
  server_config_t config = {0};
  char path[] = "/tmp/nasfs-config-test-XXXXXX";

  if (write_test_config(path, sizeof(path)) != 0) {
    fprintf(stderr, "failed to create config fixture\n");
    return 1;
  }

  if (load_config(path, &config) != 0) {
    fprintf(stderr, "load_config failed\n");
    unlink(path);
    return 1;
  }

  if (strcmp(config.bind_address, "10.0.0.1") != 0 || config.port != 4242 ||
      strcmp(config.storage_dir, "/srv/NAS # Files") != 0 ||
      strcmp(config.kex_algorithms, "Kyber512,ML-KEM-512") != 0 ||
      strcmp(config.cipher_algorithms, "xchacha20poly1305") != 0 ||
      strcmp(config.auth_methods, "password+publickey") != 0 ||
      !config.auth_password ||
      strspn(config.auth_password, "x") != FULL_PASSWORD_LENGTH ||
      strlen(config.auth_password) != FULL_PASSWORD_LENGTH ||
      strcmp(config.authorized_keys_file, "/srv/nasfs/authorized_keys") != 0 ||
      strcmp(config.pubkey_auth_algorithms, "ML-DSA-65") != 0) {
    fprintf(stderr, "parsed values do not match expected configuration\n");
    free_config(&config);
    unlink(path);
    return 1;
  }

  free_config(&config);
  unlink(path);
  return 0;
}
