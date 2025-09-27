#include "auth_module_impl.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>

auth_ctx_t *auth_client_new(const char *private_key_path,
                            const char *password) {
    auth_ctx_t *ctx = malloc(sizeof(auth_ctx_t));
    if (!ctx) {
        return NULL;
    }

    EVP_PKEY *private_key = NULL;

    FILE *private_key_file = fopen(private_key_path, "rb");
    if (private_key_file == NULL) {
        return NULL;
    }

    private_key =
        PEM_read_PrivateKey(private_key_file, NULL, NULL, (void *)password);
    fclose(private_key_file);

    if (!private_key) {
        free(ctx);
        return NULL;
    }

    ctx->pkey = private_key;
    return ctx;
}

auth_ctx_t *auth_server_new(const char *public_key_path) {
    auth_ctx_t *ctx = malloc(sizeof(auth_ctx_t));
    if (!ctx) {
        return NULL;
    }

    EVP_PKEY *public_key = NULL;

    FILE *public_key_file = fopen(public_key_path, "rb");
    if (public_key_file == NULL) {
        return NULL;
    }

    public_key = PEM_read_PUBKEY(public_key_file, &public_key, NULL, NULL);
    fclose(public_key_file);

    if (!public_key) {
        free(ctx);
        return NULL;
    }

    ctx->pkey = public_key;
    return ctx;
}

int auth_create_challenge(auth_ctx_t *ctx, unsigned char **challenge,
                          size_t *challenge_len) {
    (void)ctx;
    *challenge_len = NONCE_SIZE;
    *challenge = malloc(*challenge_len);

    if (RAND_poll() != 1) {
        return AUTH_ERROR;
    }

    if (RAND_bytes(*challenge, *challenge_len) != 1) {
        return AUTH_ERROR;
    }

    return AUTH_OK;
}

int auth_sign_challenge(auth_ctx_t *ctx, const unsigned char *challenge,
                        size_t challenge_len, unsigned char **signature,
                        size_t *signature_len) {
    EVP_MD_CTX *c_ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        return AUTH_ERROR;
    }
    if (EVP_DigestSignInit(c_ctx, NULL, NULL, NULL, ctx->pkey) != 1) {
        return AUTH_ERROR;
    }
    if (EVP_DigestSign(c_ctx, NULL, signature_len, challenge, challenge_len) !=
        1) {
        return AUTH_ERROR;
    }
    if ((*signature = OPENSSL_zalloc(*signature_len)) == NULL) {
        return AUTH_ERROR;
    }
    int result = EVP_DigestSign(c_ctx, *signature, signature_len, challenge,
                                challenge_len);

    EVP_MD_CTX_free(c_ctx);

    if (!result) {
        return AUTH_ERROR;
    }

    return AUTH_OK;
}

int auth_verify_response(auth_ctx_t *ctx, const unsigned char *challenge,
                         size_t challenge_len, const unsigned char *signature,
                         size_t signature_len) {
    EVP_MD_CTX *v_ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return AUTH_ERROR;
    }

    if (EVP_DigestVerifyInit(v_ctx, NULL, NULL, NULL, ctx->pkey) != 1) {
        return AUTH_ERROR;
    }

    int result = EVP_DigestVerify(v_ctx, signature, signature_len, challenge,
                                  challenge_len);
    EVP_MD_CTX_free(v_ctx);

    if (!result) {
        return AUTH_VERIFICATION_FAILED;
    }

    return AUTH_OK;
}

void auth_free(auth_ctx_t *ctx) {
    if (ctx) {
        EVP_PKEY_free(ctx->pkey);
        free(ctx);
    }
}
