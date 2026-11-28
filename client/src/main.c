/**
 * @file main.c
 * @brief Main entry point for the NASFS client CLI with PQC handshake.
 *
 * Copyright (C) 2025 Nikita Morozov (@NikitosKey)
 *
 * Implements an asynchronous libuv-based client that supports
 * PQC key exchange, and subsequent PUT/GET file operations over an
 * encrypted control channel.
 */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <oqs/oqs.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "auth.h"
#include "defaults.h"
#include "handshake.h"
#include "nasfs_client.h"
#include "protocol.h"

#define DEFAULT_KEX_ALGORITHMS "ML-KEM-512,Kyber512,ML-KEM-768,Kyber768"

static int parse_cipher_algo(const char* s) {
  if (!s || !*s || strcmp(s, "xsalsa20poly1305") == 0)
    return NASFS_CIPHER_XSALSA20_POLY1305;
  if (strcmp(s, "xchacha20poly1305") == 0)
    return NASFS_CIPHER_XCHACHA20_POLY1305;
  if (strcmp(s, "aes256gcm") == 0) return NASFS_CIPHER_AES_256_GCM;
  return -1;
}

static int parse_hash_algo(const char* s) {
  if (!s || !*s || strcmp(s, "blake2b") == 0) return NASFS_VERSION_BLAKE2B;
  if (strcmp(s, "sha256") == 0) return NASFS_VERSION_SHA256;
  if (strcmp(s, "blake3") == 0) return NASFS_VERSION_BLAKE3;
  return -1;
}

static int parse_ecc(const char* value) {
  if (!value || !*value || strcmp(value, "off") == 0) return NASFS_ECC_OFF;
  if (strcmp(value, "xor-4+1") == 0) return NASFS_ECC_XOR_4;
  if (strcmp(value, "xor-8+1") == 0) return NASFS_ECC_XOR_8;
  if (strcmp(value, "xor-16+1") == 0) return NASFS_ECC_XOR_16;
  if (strcmp(value, "rs-8+2") == 0) return NASFS_ECC_RS_8;
  return -1;
}

static int parse_u64(const char* value, uint64_t* out) {
  if (!*value || strspn(value, "0123456789") != strlen(value)) return -1;
  char* end;
  errno = 0;
  unsigned long long number = strtoull(value, &end, 10);
  if (errno || *end) return -1;
  *out = number;
  return 0;
}

static int parse_hex(const char* value, uint8_t* out, size_t size) {
  size_t length = strlen(value);
  return length != size * 2
             ? -1
             : sodium_hex2bin(out, size, value, length, NULL, NULL, NULL);
}

static const char* get_basename(const char* path) {
  const char* base = strrchr(path, '/');
  if (!base) base = strrchr(path, '\\');
  return base ? base + 1 : path;
}

static FILE* stage_key_file(const char* destination, char** temporary) {
  const char suffix[] = ".nasfs-key.XXXXXX";
  size_t length = strlen(destination);
  *temporary = malloc(length + sizeof(suffix));
  if (!*temporary) return NULL;
  memcpy(*temporary, destination, length);
  memcpy(*temporary + length, suffix, sizeof(suffix));
  int fd = mkstemp(*temporary);
  if (fd < 0) {
    free(*temporary);
    *temporary = NULL;
    return NULL;
  }
  FILE* stream = fdopen(fd, "w");
  if (!stream) close(fd);
  return stream;
}

static int finish_key_file(FILE** stream) {
  FILE* file = *stream;
  *stream = NULL;
  int result = fflush(file);
  if (result == 0) result = fsync(fileno(file));
  if (fclose(file) != 0) result = -1;
  return result;
}

static int write_keypair_files(const char* private_path,
                               const char* public_path, const char* algorithm) {
  OQS_SIG* sig;
  uint8_t* public_key = NULL;
  uint8_t* secret_key = NULL;
  char* public_hex = NULL;
  char* secret_hex = NULL;
  FILE* private_file = NULL;
  FILE* public_file = NULL;
  char* private_temp = NULL;
  char* public_temp = NULL;
  int rc = 1;

  if (strcmp(private_path, public_path) == 0) {
    fprintf(stderr, "Key destinations must be distinct\n");
    return 1;
  }
  sig = OQS_SIG_new(algorithm);
  if (!sig) {
    fprintf(stderr, "Unsupported signature algorithm: %s\n", algorithm);
    return 1;
  }
  if (!nasfs_auth_keys_fit(algorithm, sig->length_public_key,
                           sig->length_secret_key)) {
    fprintf(stderr, "Signature algorithm exceeds NASFS key size limits: %s\n",
            algorithm);
    goto out;
  }

  public_key = malloc(sig->length_public_key);
  secret_key = malloc(sig->length_secret_key);
  if (!public_key || !secret_key ||
      OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
    fprintf(stderr, "Failed to generate signature keypair\n");
    goto out;
  }

  public_hex = nasfs_hex_encode(public_key, sig->length_public_key);
  secret_hex = nasfs_hex_encode(secret_key, sig->length_secret_key);
  if (!public_hex || !secret_hex) {
    fprintf(stderr, "Failed to encode signature keypair\n");
    goto out;
  }

  private_file = stage_key_file(private_path, &private_temp);
  if (!private_file) {
    fprintf(stderr, "Failed to open private key file: %s\n", private_path);
    goto out;
  }
  if (fprintf(private_file, "NASFS-MLDSA-PRIVATE-v1\n%s\n%s\n%s\n", algorithm,
              public_hex, secret_hex) < 0) {
    fprintf(stderr, "Failed to write private key file: %s\n", private_path);
    goto out;
  }
  if (finish_key_file(&private_file) != 0) {
    fprintf(stderr, "Failed to save private key file: %s\n", private_path);
    goto out;
  }

  public_file = stage_key_file(public_path, &public_temp);
  if (!public_file) {
    fprintf(stderr, "Failed to open public key file: %s\n", public_path);
    goto out;
  }
  if (fprintf(public_file, "%s %s\n", algorithm, public_hex) < 0) {
    fprintf(stderr, "Failed to write public key file: %s\n", public_path);
    goto out;
  }

  if (finish_key_file(&public_file) != 0) {
    fprintf(stderr, "Failed to save public key file: %s\n", public_path);
    goto out;
  }
  if (link(private_temp, private_path) != 0) {
    fprintf(stderr, "Failed to publish private key file: %s\n", private_path);
    goto out;
  }
  if (link(public_temp, public_path) != 0) {
    fprintf(stderr, "Failed to publish public key file: %s\n", public_path);
    if (unlink(private_path) != 0) {
      fprintf(stderr,
              "Failed to remove unpublished keypair's private key: %s\n",
              private_path);
    }
    goto out;
  }
  rc = 0;

out:
  if (private_file) fclose(private_file);
  if (public_file) fclose(public_file);
  if (private_temp) unlink(private_temp);
  if (public_temp) unlink(public_temp);
  free(private_temp);
  free(public_temp);
  free(public_hex);
  if (secret_hex) sodium_memzero(secret_hex, strlen(secret_hex));
  free(secret_hex);
  if (secret_key) sodium_memzero(secret_key, sig->length_secret_key);
  free(public_key);
  free(secret_key);
  OQS_SIG_free(sig);
  return rc;
}

typedef struct {
  const nasfs_client_request_t* requests;
  const nasfs_client_result_t* results;
  size_t count;
} cli_output_t;

static const char* env_or(const char* name, const char* fallback) {
  const char* value = getenv(name);
  return value && *value ? value : fallback;
}

static void show_client_event(void* data, nasfs_client_event_t event,
                              size_t index, uint64_t bytes,
                              const char* message) {
  const cli_output_t* output = data;
  if (event == NASFS_CLIENT_ERROR || event == NASFS_CLIENT_INFO) {
    fputs(message, event == NASFS_CLIENT_ERROR ? stderr : stdout);
    return;
  }
  const nasfs_client_request_t* request = &output->requests[index];
  int uploading = request->operation == NASFS_CLIENT_PUT;
  if (event == NASFS_CLIENT_STARTED) {
    printf("\n[%zu/%zu] %s %s\n", index + 1, output->count,
           uploading                                    ? "PUT"
           : request->operation == NASFS_CLIENT_GET     ? "GET"
           : request->operation == NASFS_CLIENT_RESOLVE ? "RESOLVE"
                                                        : "COLLECT",
           uploading              ? request->local_path
           : request->remote_name ? request->remote_name
                                  : "");
  } else if (event == NASFS_CLIENT_PROGRESS) {
    printf("\r%s %llu bytes...", uploading ? "Uploaded" : "Downloaded",
           (unsigned long long)bytes);
    fflush(stdout);
  } else if (event == NASFS_CLIENT_COMPLETED) {
    const nasfs_client_result_t* result = &output->results[index];
    char id[33], digest[65];
    sodium_bin2hex(id, sizeof(id), result->version.id,
                   sizeof(result->version.id));
    sodium_bin2hex(digest, sizeof(digest), result->version.digest,
                   sizeof(result->version.digest));
    if (uploading) {
      printf("Upload published. Manifest digest: %s\n", digest);
    } else if (request->operation == NASFS_CLIENT_GET) {
      printf("\nDownload complete.\n");
    } else if (request->operation == NASFS_CLIENT_RESOLVE) {
      printf("%s %s\n", id, digest);
    } else {
      printf("Expired versions collected.\n");
    }
  }
}

int main(int argc, char** argv) {
  if (argc >= 2 && strcmp(argv[1], "keygen") == 0) {
    const char* algorithm =
        (argc >= 5) ? argv[4] : NASFS_AUTH_DEFAULT_SIG_ALGORITHM;
    if (argc < 4) {
      fprintf(stderr,
              "Usage:\n  %s keygen <private_key> <authorized_keys> "
              "[signature_algorithm]\n",
              argv[0]);
      return 1;
    }
    return write_keypair_files(argv[2], argv[3], algorithm);
  }

  int collecting = argc == 2 && strcmp(argv[1], "collect") == 0;
  if (argc < 3 && !collecting) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s put  <local_file> [remote_name]   -- single upload\n"
        "  %s get  <remote_file> [local_file]   -- single download\n"
        "  %s mput <file1> <file2> ...           -- batch upload, create only\n"
        "  %s mget <remote1> <remote2> ...       -- batch download (one "
        "session)\n"
        "  %s resolve <name>\n"
        "  %s get-version <id> <digest> <offset> <length|all> <local_file>\n"
        "  %s collect\n"
        "  %s keygen <private_key> <authorized_keys> [sig_algo]\n",
        argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
    return 1;
  }

  signal(SIGPIPE, SIG_IGN);

  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to initialize libsodium\n");
    return 1;
  }

  nasfs_client_options_t options = {
      .ip = "127.0.0.1",
      .port = NASFS_DEFAULT_PORT,
      .home = getenv("HOME"),
      .kex_algorithms = env_or("NASFS_KEX_ALGORITHMS", DEFAULT_KEX_ALGORITHMS),
      .cipher_algorithms = env_or("NASFS_CIPHER_ALGORITHMS",
                                  NASFS_CONTROL_CIPHER_XCHACHA20POLY1305),
      .auth_method = env_or("NASFS_AUTH_METHOD", NASFS_AUTH_METHOD_PASSWORD),
      .auth_user = env_or("NASFS_AUTH_USER", "user"),
      .auth_password = env_or("NASFS_AUTH_PASSWORD", NULL),
      .identity_file = env_or("NASFS_IDENTITY_FILE", NULL),
      .auth_sig_algorithm =
          env_or("NASFS_AUTH_SIG_ALGORITHM", NASFS_AUTH_DEFAULT_SIG_ALGORITHM),
      .block_size = 64 * 1024,
      .watch_signals = 1,
      .notify = show_client_event,
  };

  const char* env_server_ip = getenv("NASFS_SERVER_IP");
  const char* env_server_port = getenv("NASFS_SERVER_PORT");

  if (env_server_ip && env_server_ip[0] != '\0') {
    options.ip = env_server_ip;
  }
  if (env_server_port) {
    char* end;
    errno = 0;
    long port = strtol(env_server_port, &end, 10);
    if (errno || *end || port < 1 || port > 65535 ||
        strspn(env_server_port, "0123456789") != strlen(env_server_port)) {
      fprintf(stderr, "Invalid NASFS_SERVER_PORT (expected 1–65535)\n");
      return 1;
    }
    options.port = (int)port;
  }

  const char* env_file_cipher = getenv("NASFS_FILE_CIPHER");
  const char* env_file_hash = getenv("NASFS_FILE_HASH");
  const char* env_kdf = getenv("NASFS_KDF");
  const char* env_block_size = getenv("NASFS_BLOCK_SIZE");
  int selected_cipher = parse_cipher_algo(env_file_cipher);
  int selected_hash = parse_hash_algo(env_file_hash);
  if (selected_cipher < 0 || selected_hash < 0 ||
      (env_kdf && *env_kdf && strcmp(env_kdf, "argon2id") != 0)) {
    fprintf(stderr, "Invalid %s selection\n",
            selected_cipher < 0 ? "NASFS_FILE_CIPHER"
            : selected_hash < 0 ? "NASFS_FILE_HASH"
                                : "NASFS_KDF");
    return 1;
  }
  int ecc = parse_ecc(getenv("NASFS_ECC"));
  if (ecc < 0) {
    fprintf(stderr, "Invalid NASFS_ECC profile\n");
    return 1;
  }
  options.ecc = (nasfs_ecc_profile_t)ecc;
  options.file_cipher = (nasfs_cipher_algo_t)selected_cipher;
  options.file_hash = (nasfs_version_hash_t)selected_hash;
  int is_upload = strcmp(argv[1], "put") == 0 || strcmp(argv[1], "mput") == 0;
  int is_get = strcmp(argv[1], "get") == 0 || strcmp(argv[1], "mget") == 0 ||
               strcmp(argv[1], "get-version") == 0;
  if (env_block_size && env_block_size[0] != '\0') {
    char* end;
    long bs = strtol(env_block_size, &end, 10);
    if (*end != '\0' || bs < 4096 || bs > 4194304) {
      fprintf(stderr, "Invalid NASFS_BLOCK_SIZE (expected 4096–4194304)\n");
      return 1;
    }
    options.block_size = (size_t)bs;
  }

  const char* env_encryption_key = getenv("NASFS_ENCRYPTION_KEY");
  if ((is_upload || is_get) && (!env_encryption_key || !*env_encryption_key)) {
    fprintf(stderr, "\n[SECURITY AUDIT ENFORCEMENT]\n");
    fprintf(stderr, "NASFS is now Secure-by-Default.\n");
    fprintf(stderr, "Plaintext file transmission is strictly forbidden.\n");
    fprintf(stderr,
            "You MUST provide NASFS_ENCRYPTION_KEY environment variable.\n\n");
    return 1;
  }

  nasfs_client_request_t batch_queue[NASFS_MAX_BATCH];
  int batch_count = 0;
  nasfs_client_version_t version;
  if (collecting) {
    batch_queue[batch_count++] =
        (nasfs_client_request_t){.operation = NASFS_CLIENT_COLLECT};
  } else if (strcmp(argv[1], "resolve") == 0 && argc == 3) {
    batch_queue[batch_count++] = (nasfs_client_request_t){
        .operation = NASFS_CLIENT_RESOLVE, .remote_name = argv[2]};
  } else if (strcmp(argv[1], "get-version") == 0 && argc == 7) {
    uint64_t offset, length = UINT64_MAX;
    if (parse_hex(argv[2], version.id, sizeof(version.id)) < 0 ||
        parse_hex(argv[3], version.digest, sizeof(version.digest)) < 0 ||
        parse_u64(argv[4], &offset) < 0 ||
        (strcmp(argv[5], "all") != 0 && parse_u64(argv[5], &length) < 0)) {
      fprintf(stderr, "Invalid version identifier or range\n");
      return 1;
    }
    batch_queue[batch_count++] =
        (nasfs_client_request_t){.operation = NASFS_CLIENT_GET,
                                 .local_path = argv[6],
                                 .version = &version,
                                 .offset = offset,
                                 .length = length};
  } else if (strcmp(argv[1], "put") == 0) {
    /* Single PUT: put <local> [remote] */
    const char* loc = argv[2];
    const char* rem = (argc >= 4) ? argv[3] : get_basename(loc);
    batch_queue[batch_count++] = (nasfs_client_request_t){
        .operation = NASFS_CLIENT_PUT, .local_path = loc, .remote_name = rem};
  } else if (strcmp(argv[1], "get") == 0) {
    const char* rem = argv[2];
    const char* loc = (argc >= 4) ? argv[3] : get_basename(rem);
    batch_queue[batch_count++] = (nasfs_client_request_t){
        .operation = NASFS_CLIENT_GET, .local_path = loc, .remote_name = rem};
  } else if (strcmp(argv[1], "mput") == 0 || strcmp(argv[1], "mget") == 0) {
    if (argc - 2 > NASFS_MAX_BATCH) {
      fprintf(stderr, "Batch limit is %d files\n", NASFS_MAX_BATCH);
      return 1;
    }
    int uploading = strcmp(argv[1], "mput") == 0;
    for (int i = 2; i < argc; i++) {
      const char* name = get_basename(argv[i]);
      const char* requested_dest = uploading ? name : argv[i];
      for (int j = 0; j < batch_count; j++) {
        const char* dest =
            uploading ? batch_queue[j].remote_name : batch_queue[j].local_path;
        if (strcmp(requested_dest, dest) == 0) {
          fprintf(stderr, "Duplicate batch destination: %s\n", requested_dest);
          return 1;
        }
      }
      batch_queue[batch_count++] =
          uploading ? (nasfs_client_request_t){.operation = NASFS_CLIENT_PUT,
                                               .local_path = argv[i],
                                               .remote_name = name,
                                               .create_only = 1}
                    : (nasfs_client_request_t){.operation = NASFS_CLIENT_GET,
                                               .local_path = argv[i],
                                               .remote_name = name};
    }
  } else {
    fprintf(stderr, "Invalid operation. Use put, get, mput, or mget.\n");
    return 1;
  }

  options.encryption_password = env_encryption_key;
  options.author_key = getenv(is_upload ? "NASFS_AUTHOR_SIGNING_SEED"
                                        : "NASFS_AUTHOR_PUBLIC_KEY");
  uint8_t digest[32];
  const char* expected = getenv("NASFS_EXPECTED_MANIFEST");
  if (is_get && expected) {
    if (batch_count != 1 || strlen(expected) != 2 * sizeof(digest) ||
        sodium_hex2bin(digest, sizeof(digest), expected, strlen(expected), NULL,
                       NULL, NULL) != 0) {
      fprintf(stderr,
              "NASFS_EXPECTED_MANIFEST requires one GET and a 64-digit hex "
              "digest\n");
      return 1;
    }
    options.expected_digest = digest;
  }
  nasfs_client_result_t results[NASFS_MAX_BATCH];
  cli_output_t output = {batch_queue, results, (size_t)batch_count};
  options.callback_data = &output;
  return nasfs_client_run(&options, batch_queue, results, (size_t)batch_count);
}
