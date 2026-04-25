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
  fprintf(file, "Port 4242\n");
  fprintf(file, "StorageDir /srv/nasfs\n");
  fprintf(file, "KexAlgorithms Kyber512,ML-KEM-512\n");
  fprintf(file, "CipherAlgorithms xchacha20poly1305\n");
  fprintf(file, "AuthMethods password+publickey\n");
  fprintf(file, "AuthPassword test-secret\n");
  fprintf(file, "AuthorizedKeysFile /srv/nasfs/authorized_keys\n");
  fprintf(file, "PubKeyAuthAlgorithms ML-DSA-65\n");
  fclose(file);
  return 0;
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
      strcmp(config.storage_dir, "/srv/nasfs") != 0 ||
      strcmp(config.kex_algorithms, "Kyber512,ML-KEM-512") != 0 ||
      strcmp(config.cipher_algorithms, "xchacha20poly1305") != 0 ||
      strcmp(config.auth_methods, "password+publickey") != 0 ||
      strcmp(config.auth_password, "test-secret") != 0 ||
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
