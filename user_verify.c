#include <stdio.h>
#include <string.h>
#include "crypto_utils.h"
#include "ds.h"
#include "user_verify.h"


int verify_password(const char *username, const char *password) {
    FILE *file = fopen("users.txt", "r");
    if (file == NULL) {
        return 0;
    }

    User user;
    char salt_hex[SALT_LEN * 2 + 1];
    char hash_hex[HASH_LEN * 2 + 1];

    while (fscanf(file, "%49s %d %32s %64s %19s", user.username, &user.user_id, salt_hex, hash_hex, user.hash_function) == 5) {
        if (strcmp(user.username, username) == 0) {
            for (int i = 0; i < SALT_LEN; i++) {
                sscanf(&salt_hex[i * 2], "%02hhx", &user.salt[i]);
            }

            unsigned char computed_hash[HASH_LEN];
            if (hash_password(password, user.salt, computed_hash) != 0) {
                fclose(file);
                return 0;
            }

            unsigned char stored_hash[HASH_LEN];
            for (int i = 0; i < HASH_LEN; i++) {
                sscanf(&hash_hex[i * 2], "%02hhx", &stored_hash[i]);
            }

            fclose(file);
            return (memcmp(computed_hash, stored_hash, HASH_LEN) == 0) ? 1 : 0;
        }
    }

    fclose(file);
    return 0;
}

int login_user(char *logged_in_user) {
    char username[MAX_INPUT_LEN];
    char password[MAX_INPUT_LEN];

    printf("Enter username (at most %d characters): ", MAX_INPUT_LEN - 1);
    if (fgets(username, sizeof(username), stdin) == NULL) {
        printf("Error reading username.\n");
        return 0;
    }

    username[strcspn(username, "\n")] = '\0';

    if (strlen(username) >= MAX_INPUT_LEN - 1) {
        printf("Username is too long. Maximum length is %d characters.\n", MAX_INPUT_LEN - 1);
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
        return 0;
    }

    printf("Enter password (at most %d characters): ", MAX_INPUT_LEN - 1);
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("Error reading password.\n");
        return 0;
    }

    password[strcspn(password, "\n")] = '\0';

    if (strlen(password) >= MAX_INPUT_LEN - 1) {
        printf("Password is too long. Maximum length is %d characters.\n", MAX_INPUT_LEN - 1);
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
        return 0;
    }

    if (verify_password(username, password)) {
        printf("Login successful.\n");
        strncpy(logged_in_user, username, MAX_INPUT_LEN - 1);
        logged_in_user[MAX_INPUT_LEN - 1] = '\0'; // Защита от переполнения
        return 1;
    } else {
        printf("Invalid username or password.\n");
        return 0;
    }
}

