#include <stdio.h>
#include <string.h>
#include "crypto_utils.h"
#include "ds.h"
#include "user_create.h"


int next_user_id = 1;

void load_next_user_id() {
    FILE *file = fopen("users.txt", "r");
    if (file == NULL) {
        next_user_id = 1;
        return;
    }

    User user;
    char salt_hex[SALT_LEN * 2 + 1];
    char hash_hex[HASH_LEN * 2 + 1];
    int max_user_id = 0;

    while (fscanf(file, "%49s %d %32s %64s %19s",
                  user.username, &user.user_id, salt_hex, hash_hex, user.hash_function) == 5) {
        if (user.user_id > max_user_id) {
            max_user_id = user.user_id;
        }
    }

    fclose(file);
    next_user_id = max_user_id + 1;
}

int is_username_taken(const char *username) {
    FILE *file = fopen("users.txt", "r");
    if (file == NULL) {
        return 0;
    }

    User user;
    while (fscanf(file, "%49s %d %32s %64s %19s",
                  user.username, &user.user_id, user.salt, user.password_hash, user.hash_function) == 5) {
        if (strcmp(user.username, username) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

void create_user(const char *username, const char *password) {
    User user;
    strncpy(user.username, username, sizeof(user.username) - 1); // Защита от переполнения
    user.username[sizeof(user.username) - 1] = '\0';

    load_next_user_id();

    user.user_id = next_user_id++;

    if (generate_salt(user.salt, SALT_LEN) != 0) {
        fprintf(stderr, "Error generating salt. User creation failed.\n");
        return;
    }
    if (hash_password(password, user.salt, user.password_hash) != 0) {
        fprintf(stderr, "Error hashing password. User creation failed.\n");
        return;
    }

    char salt_hex[SALT_LEN * 2 + 1];
    char hash_hex[HASH_LEN * 2 + 1];
    for (int i = 0; i < SALT_LEN; ++i) {
        sprintf(&salt_hex[i * 2], "%02x", user.salt[i]);
    }
    for (int i = 0; i < HASH_LEN; ++i) {
        sprintf(&hash_hex[i * 2], "%02x", user.password_hash[i]);
    }

    FILE *file = fopen("users.txt", "a");
    if (file == NULL) {
        fprintf(stderr, "Error opening users file for writing.\n");
        return;
    }

    fprintf(file, "%s %d %s %s %s\n", user.username, user.user_id, salt_hex, hash_hex, "SHA256");
    fclose(file);
}

int register_user() {
    char username[MAX_INPUT_LEN];
    char password[MAX_INPUT_LEN];
    int username_taken;

    do {
        printf("Enter username (at most %d characters, at least 4 characters): ", MAX_INPUT_LEN - 1);
        if (fgets(username, sizeof(username), stdin) == NULL) {
            printf("Error reading username. Please try again.\n");
            continue;
        }

        username[strcspn(username, "\n")] = '\0';

        if (strlen(username) >= MAX_INPUT_LEN - 1) {
            printf("Username is too long. Maximum length is %d characters.\n", MAX_INPUT_LEN - 1);
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
            continue;
        }

        if (strlen(username) < 4) {
            printf("Username must be at least 4 characters long.\n");
            continue;
        }

        username_taken = is_username_taken(username);
        if (username_taken) {
            printf("Username is already taken. Please choose a different username.\n");
        }
    } while (strlen(username) < 4 || username_taken);

    do {
        printf("Enter password (at most %d characters, at least 8 characters): ", MAX_INPUT_LEN - 1);
        if (fgets(password, sizeof(password), stdin) == NULL) {
            printf("Error reading password. Please try again.\n");
            continue;
        }

        password[strcspn(password, "\n")] = '\0';

        if (strlen(password) >= MAX_INPUT_LEN - 1) {
            printf("Password is too long. Maximum length is %d characters.\n", MAX_INPUT_LEN - 1);
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
            continue;
        }

        if (strlen(password) < 8) {
            printf("Password must be at least 8 characters long.\n");
        } else {
            break;
        }
    } while (1);

    create_user(username, password);
    printf("User successfully registered.\n");
    return 0;
}
