#ifndef AUTH_MODULE_IMPL_H
#define AUTH_MODULE_IMPL_H

#include "auth_module.h"
#include <openssl/evp.h>

#define NONCE_SIZE 128

struct auth_ctx {
    EVP_PKEY *pkey;
};

#endif
