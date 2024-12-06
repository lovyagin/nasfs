#pragma once

#define SALT_LEN 16
#define HASH_LEN 32
#define MAX_INPUT_LEN 100

typedef struct {
    char username[MAX_INPUT_LEN];
    int user_id;
    unsigned char salt[SALT_LEN];
    unsigned char password_hash[HASH_LEN];
    char hash_function[20];
} User;
