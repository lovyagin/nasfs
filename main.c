#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "ds.h"
#include "user_create.h"
#include "user_verify.h"
#include "user_change_password.h"


int main() {
    int is_logged_in = 0;
    char logged_in_user[MAX_INPUT_LEN] = "";

    char choice[MAX_INPUT_LEN];
    do {
        printf("\nChoose an action:\n");
        if (!is_logged_in) {
            printf("1. Register\n");
            printf("2. Login\n");
            printf("3. Exit\n");
        } else {
            printf("1. Change password\n");
            printf("2. Logout\n");
            printf("3. Exit\n");
        }
        printf("Your choice: ");

        if (fgets(choice, sizeof(choice), stdin) == NULL) {
            printf("Error reading input. Please try again.\n");
            continue;
        }

        choice[strcspn(choice, "\n")] = '\0';

        if (strlen(choice) >= MAX_INPUT_LEN - 1) {
            printf("Input too long. Please try again.\n");
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
            continue;
        }

        if (!is_logged_in) {
            if (strcmp(choice, "1") == 0) {
                register_user();
            } else if (strcmp(choice, "2") == 0) {
                is_logged_in = login_user(logged_in_user);
            } else if (strcmp(choice, "3") == 0) {
                printf("Exiting program.\n");
                break;
            } else {
                printf("Invalid choice. Please choose again.\n");
            }
        } else {
            if (strcmp(choice, "1") == 0) {
                change_user_password(logged_in_user);
            } else if (strcmp(choice, "2") == 0) {
                printf("Logging out...\n");
                is_logged_in = 0;
            } else if (strcmp(choice, "3") == 0) {
                printf("Exiting program.\n");
                break;
            } else {
                printf("Invalid choice. Please choose again.\n");
            }
        }
    } while (1);

    return 0;
}