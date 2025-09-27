#include "auth_module.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *password = "my_very_secure_password";

    printf("1. Generating keypair...\n");
    if (auth_generate_keypair("client_private.pem", "client_public.pem",
                              password) != AUTH_OK) {
        fprintf(stderr, "Key generation failed!\n");
        return 1;
    }

    printf("2. Testing sign/verify...\n");
    auth_ctx_t *client_ctx = auth_client_new("client_private.pem", password);
    auth_ctx_t *server_ctx = auth_server_new("client_public.pem");

    if (!client_ctx || !server_ctx) {
        fprintf(stderr, "Failed to create client or server context!\n");
        return 1;
    }

    unsigned char *nonce;
    size_t nonce_size;
    if (auth_create_challenge(server_ctx, &nonce, &nonce_size) != AUTH_OK) {
        fprintf(stderr, "Failed to create challenge!\n");
        return 1;
    }

    unsigned char *signature;
    size_t sig_len;
    if (auth_sign_challenge(client_ctx, nonce, sizeof(nonce), &signature,
                            &sig_len) != AUTH_OK) {
        fprintf(stderr, "Failed to sign challenge!\n");
        return 1;
    }

    int verify_result = auth_verify_response(server_ctx, nonce, sizeof(nonce),
                                             signature, sig_len);

    if (verify_result == AUTH_OK) {
        printf("SUCCESS: Signature verification passed!\n");
    } else {
        printf("FAILURE: Signature verification failed!\n");
    }

    auth_free(server_ctx);
    auth_free(client_ctx);
    free(nonce);

    return 0;
}
