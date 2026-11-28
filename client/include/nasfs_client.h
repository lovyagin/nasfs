#ifndef NASFS_CLIENT_H
#define NASFS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "version.h"

#define NASFS_MAX_BATCH 512

typedef enum {
  NASFS_CLIENT_PUT = 1,
  NASFS_CLIENT_GET,
  NASFS_CLIENT_RESOLVE,
  NASFS_CLIENT_COLLECT
} nasfs_client_operation_t;

typedef struct {
  uint8_t id[NASFS_OBJECT_ID_SIZE];
  uint8_t digest[NASFS_VERSION_DIGEST_SIZE];
} nasfs_client_version_t;

typedef struct {
  nasfs_client_operation_t operation;
  const char* local_path;
  const char* remote_name;
  int create_only;
  /* An exact GET may select a byte range. UINT64_MAX reads through EOF. */
  const nasfs_client_version_t* version;
  uint64_t offset;
  uint64_t length;
} nasfs_client_request_t;

typedef enum {
  NASFS_CLIENT_NOT_STARTED,
  NASFS_CLIENT_FAILED,
  NASFS_CLIENT_REJECTED,
  NASFS_CLIENT_CANCELLED,
  NASFS_CLIENT_PUT_UNKNOWN,
  NASFS_CLIENT_PUT_PUBLISHED,
  NASFS_CLIENT_GET_PUBLISHED,
  NASFS_CLIENT_RESOLVED,
  NASFS_CLIENT_COLLECTED,
  NASFS_CLIENT_NOT_FOUND,
  NASFS_CLIENT_CONFLICT,
  NASFS_CLIENT_QUOTA
} nasfs_client_outcome_t;

typedef struct {
  nasfs_client_outcome_t outcome;
  nasfs_client_version_t version;
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
  nasfs_version_hash_t file_hash;
  size_t block_size;
  const uint8_t* expected_digest;
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
