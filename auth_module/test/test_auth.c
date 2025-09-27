#include "../src/auth_module_impl.h"
#include <openssl/pem.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static EVP_PKEY *generate_test_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int test_generate_challenge(void) {
    unsigned char *nonce1;
    size_t len1 = 0;
    unsigned char *nonce2;
    size_t len2 = 0;

    void *ctx = NULL;
    if (auth_create_challenge(ctx, &nonce1, &len1) != AUTH_OK)
        return 1;
    if (auth_create_challenge(ctx, &nonce2, &len2) != AUTH_OK)
        return 2;

    if (memcmp(nonce1, nonce2, len1) == 0) {
        return 3;
    }

    return 0;
}

int test_sign_verify(void) {
    EVP_PKEY *pkey = generate_test_key();
    if (!pkey) {
        return 1;
    }

    auth_ctx_t *ctx = malloc(sizeof(auth_ctx_t));
    ctx->pkey = pkey;

    unsigned char message[] = "Test message to sign";
    unsigned char *signature = NULL;
    size_t sig_len;

    if (auth_sign_challenge(ctx, message, strlen((char *)message), &signature,
                            &sig_len) != AUTH_OK) {
        EVP_PKEY_free(pkey);
        free(ctx);
        return 2;
    }

    int result = auth_verify_response(ctx, message, strlen((char *)message),
                                      signature, sig_len);

    EVP_PKEY_free(pkey);
    OPENSSL_free(signature);
    free(ctx);

    if (result != AUTH_OK) {
        return 3;
    }
    return 0;
}

int test_verify_fails_corrupt_data(void) {
    EVP_PKEY *pkey = generate_test_key();
    if (!pkey) {
        return 1;
    }

    auth_ctx_t *ctx = malloc(sizeof(auth_ctx_t));
    ctx->pkey = pkey;

    unsigned char message[] = "Correct message";
    unsigned char *signature = NULL;
    size_t sig_len;

    if (auth_sign_challenge(ctx, message, strlen((char *)message), &signature,
                            &sig_len) != AUTH_OK) {
        EVP_PKEY_free(pkey);
        free(ctx);
        return 2;
    }

    unsigned char corrupt_message[] = "Corrupt message";

    int result = auth_verify_response(ctx, corrupt_message,
                                      strlen((char *)corrupt_message),
                                      signature, sig_len);

    EVP_PKEY_free(pkey);
    OPENSSL_free(signature);
    free(ctx);

    if (result != AUTH_VERIFICATION_FAILED) {
        return 3;
    }
    return 0;
}
