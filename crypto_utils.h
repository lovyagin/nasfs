#pragma once

#include <stddef.h>

int generate_salt(unsigned char *salt, size_t length);
int hash_password(const char *password, const unsigned char *salt, unsigned char *hash);