#include <stdio.h>
#include <string.h>

extern int test_generate_challenge(void);
extern int test_sign_verify(void);
extern int test_verify_fails_corrupt_data(void);

struct test_case {
    const char *name;
    int (*function)(void);
};

struct test_case test_suite[] = {
    {"generate_challenge", test_generate_challenge},
    {"sign_verify", test_sign_verify},
    {"verify_fails_corrupt_data", test_verify_fails_corrupt_data},
    {NULL, NULL}};

int main() {
    printf("=== Starting Auth Module Test Suite ===\n\n");

    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;

    for (int i = 0; test_suite[i].name != NULL; i++) {
        total_tests++;
        printf("Running test: %-40s", test_suite[i].name);

        int result = test_suite[i].function();

        if (result == 0) {
            passed_tests++;
            printf("[PASS]\n");
        } else {
            failed_tests++;
            printf("[FAIL] -> Error Code: %d\n", result);
        }
    }

    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", failed_tests);

    return failed_tests;
}
