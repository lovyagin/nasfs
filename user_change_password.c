#include <stdio.h>
#include <string.h>
#include "crypto_utils.h"
#include "ds.h"
#include "user_change_password.h"
#include "user_verify.h"


int process_users_in_file(const char *username, const char *new_password, const char *current_password) {
    FILE *file = fopen("users.txt", "r");
    FILE *temp_file = fopen("users_temp.txt", "w");
    if (!file || !temp_file) {
        if (file) fclose(file);
        if (temp_file) fclose(temp_file);
        fprintf(stderr, "Error opening files.\n");
        return -1;
    }

    User user;
    char salt_hex[SALT_LEN * 2 + 1];
    char hash_hex[HASH_LEN * 2 + 1];
    int updated = 0;

    while (fscanf(file, "%s %d %32s %64s %s", user.username, &user.user_id, salt_hex, hash_hex, user.hash_function) == 5) {
        for (int i = 0; i < SALT_LEN; i++) sscanf(&salt_hex[i * 2], "%02hhx", &user.salt[i]);
        for (int i = 0; i < HASH_LEN; i++) sscanf(&hash_hex[i * 2], "%02hhx", &user.password_hash[i]);

        if (strcmp(user.username, username) == 0) {
            if (!verify_password(username, current_password)) {
                printf("Incorrect current password. Password change denied.\n");
                fclose(file);
                fclose(temp_file);
                remove("users_temp.txt");
                return -1;
            }

            if (strcmp(current_password, new_password) == 0) {
                printf("New password cannot be the same as the current password.\n");
                fclose(file);
                fclose(temp_file);
                remove("users_temp.txt");
                return -1;
            }

            generate_salt(user.salt, SALT_LEN);
            hash_password(new_password, user.salt, user.password_hash);
            strcpy(user.hash_function, "SHA256");
            updated = 1;
        }

        for (int i = 0; i < SALT_LEN; i++) sprintf(&salt_hex[i * 2], "%02x", user.salt[i]);
        for (int i = 0; i < HASH_LEN; i++) sprintf(&hash_hex[i * 2], "%02x", user.password_hash[i]);

        fprintf(temp_file, "%s %d %s %s %s\n", user.username, user.user_id, salt_hex, hash_hex, user.hash_function);
    }

    fclose(file);
    fclose(temp_file);

    if (updated) {
        remove("users.txt");
        rename("users_temp.txt", "users.txt");
        printf("Password successfully changed.\n");
        return 0;
    } else {
        remove("users_temp.txt");
        printf("User not found or error updating password.\n");
        return -1;
    }
}

// Функция смены пароля с взаимодействием с пользователем
void change_user_password(const char *logged_in_user) {
    char current_password[MAX_INPUT_LEN];
    char new_password[MAX_INPUT_LEN];

    printf("Enter current password: ");
    if (fgets(current_password, sizeof(current_password), stdin) == NULL) {
        printf("Error reading current password.\n");
        return;
    }
    current_password[strcspn(current_password, "\n")] = '\0';

    if (strlen(current_password) >= MAX_INPUT_LEN - 1) {
        printf("Input too long. Please try again.\n");
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
        return;
    }

    printf("Enter new password (at least 8 characters): ");
    if (fgets(new_password, sizeof(new_password), stdin) == NULL) {
        printf("Error reading new password.\n");
        return;
    }
    new_password[strcspn(new_password, "\n")] = '\0';

    if (strlen(new_password) >= MAX_INPUT_LEN - 1) {
        printf("Input too long. Please try again.\n");
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
        return;
    }

    if (strlen(new_password) < 8) {
        printf("Password must be at least 8 characters long.\n");
        return;
    }

    process_users_in_file(logged_in_user, new_password, current_password);
}

