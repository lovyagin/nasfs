#include "auth_module.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

int auth_generate_keypair(const char *private_key_path,
                          const char *public_key_path, const char *password) {
    EVP_PKEY *pkey = NULL;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (pctx == NULL) {
        return AUTH_ERROR;
    }
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        return AUTH_ERROR;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        return AUTH_ERROR;
    }
    EVP_PKEY_CTX_free(pctx);

    FILE *public_key_file = fopen(public_key_path, "wb");
    if (public_key_file == NULL) {
        return AUTH_ERROR;
    }
    if (PEM_write_PUBKEY(public_key_file, pkey) != 1) {
        return AUTH_ERROR;
    }
    if (fclose(public_key_file) == EOF) {
        return AUTH_ERROR;
    }

    FILE *private_key_file = fopen(private_key_path, "wb");
    if (private_key_file == NULL) {
        return AUTH_ERROR;
    }
    if (PEM_write_PKCS8PrivateKey(private_key_file, pkey, EVP_aes_256_cbc(),
                                  NULL, 0, NULL, (void *)password) <= 0) {
        return AUTH_ERROR;
    }
    if (fclose(private_key_file) == EOF) {
        return AUTH_ERROR;
    }

    EVP_PKEY_free(pkey);

    return AUTH_OK;
}
