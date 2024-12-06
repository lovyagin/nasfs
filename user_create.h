#pragma once

int is_username_taken(const char *username);
void load_next_user_id();
void create_user(const char *username, const char *password);
int register_user(void);
