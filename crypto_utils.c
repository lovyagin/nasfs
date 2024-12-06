#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include "crypto_utils.h"
#include "ds.h"


int generate_salt(unsigned char *salt, size_t length) {
    if (RAND_bytes(salt, length) != 1) {
        fprintf(stderr, "Error generating random salt\n");
        return -1;
    }
    return 0;
}

int hash_password(const char *password, const unsigned char *salt, unsigned char *hash) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 10000, EVP_sha256(), HASH_LEN, hash)) {
        fprintf(stderr, "Error hashing password\n");
        return -1;
    }
    return 0;
}
