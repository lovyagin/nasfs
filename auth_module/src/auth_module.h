#ifndef AUTH_MODULE_H
#define AUTH_MODULE_H

#include <stddef.h>

#define AUTH_OK 0
#define AUTH_ERROR -1
#define AUTH_VERIFICATION_FAILED -2

typedef struct auth_ctx auth_ctx_t;

int auth_generate_keypair(const char *private_key_path,
                          const char *public_key_path, const char *password);

auth_ctx_t *auth_client_new(const char *private_key_path, const char *password);
auth_ctx_t *auth_server_new(const char *public_key_path);

void auth_free(auth_ctx_t *ctx);

int auth_create_challenge(auth_ctx_t *ctx, unsigned char **challenge,
                          size_t *challenge_len);

int auth_sign_challenge(auth_ctx_t *ctx, const unsigned char *challenge,
                        size_t challenge_len, unsigned char **signature,
                        size_t *signature_len);

int auth_verify_response(auth_ctx_t *ctx, const unsigned char *challenge,
                         size_t challenge_len, const unsigned char *signature,
                         size_t signature_len);
#endif
