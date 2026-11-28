#ifndef NASFS_CLIENT_H
#define NASFS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_engine.h"

#define NASFS_MAX_BATCH 512

typedef enum {
  NASFS_CLIENT_PUT = 1,
  NASFS_CLIENT_GET
} nasfs_client_operation_t;

typedef struct {
  nasfs_client_operation_t operation;
  const char* local_path;
  const char* remote_name;
  int create_only;
} nasfs_client_request_t;

typedef enum {
  NASFS_CLIENT_NOT_STARTED,
  NASFS_CLIENT_FAILED,
  NASFS_CLIENT_REJECTED,
  NASFS_CLIENT_CANCELLED,
  NASFS_CLIENT_PUT_UNKNOWN,
  NASFS_CLIENT_PUT_PUBLISHED,
  NASFS_CLIENT_GET_PUBLISHED
} nasfs_client_outcome_t;

typedef struct {
  nasfs_client_outcome_t outcome;
  int has_digest;
  uint8_t digest[32];
} nasfs_client_result_t;

typedef enum {
  NASFS_CLIENT_INFO,
  NASFS_CLIENT_ERROR,
  NASFS_CLIENT_STARTED,
  NASFS_CLIENT_PROGRESS,
  NASFS_CLIENT_COMPLETED
} nasfs_client_event_t;

typedef void (*nasfs_client_notify_fn)(void* data, nasfs_client_event_t event,
                                       size_t index, uint64_t bytes,
                                       const char* message);

typedef struct {
  const char* ip;
  int port;
  const char* home;
  const char* server_pin;
  const char* kex_algorithms;
  const char* cipher_algorithms;
  const char* auth_method;
  const char* auth_user;
  const char* auth_password;
  const char* identity_file;
  const char* auth_sig_algorithm;
  const char* encryption_password;
  const char* author_key;
  nasfs_cipher_algo_t file_cipher;
  nasfs_hash_algo_t file_hash;
  nasfs_kdf_algo_t kdf;
  size_t block_size;
  const uint8_t* expected_digest;
  int allow_unsigned_reads;
  int watch_signals;
  nasfs_client_notify_fn notify;
  int (*should_cancel)(void* data);
  void* callback_data;
} nasfs_client_options_t;

/*
 * Execute a homogeneous batch in one authenticated connection. The function
 * owns its event loop, drains pending requests before returning, and stops at
 * the first failure. Options, requests, and callback data are borrowed for
 * the call. Callbacks run on the calling thread. Message pointers are only
 * valid for the callback. COMPLETED is sent after the result has been stored.
 * Return 0 for full success, 1 for failure, or 128 + signal with watch_signals.
 */
int nasfs_client_run(const nasfs_client_options_t* options,
                     const nasfs_client_request_t* requests,
                     nasfs_client_result_t* results, size_t count);

#endif
