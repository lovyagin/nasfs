CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LIBS = -lcrypto

SRC = main.c \
      crypto_utils.c \
      user_create.c \
      user_verify.c \
      user_change_password.c

OBJ = $(SRC:.c=.o)

TARGET = password_authentication

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
