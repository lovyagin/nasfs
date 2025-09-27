CC=gcc
CFLAGS=-Wall -Wextra
LDFLAGS=-lssl -lcrypto
SRC_DIR=src
SOURCES=$(SRC_DIR)/keygen.c $(SRC_DIR)/auth.c
OBJECTS=$(SOURCES:.c=.o)

DEMO_SOURCE = $(SRC_DIR)/auth_demo.c
DEMO_OBJECTS = $(DEMO_SOURCE:.c=.o)
DEMO_TARGET = auth_demo

TEST_SOURCES = $(wildcard test/*.c)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_RUNNER = test_runner

all: $(DEMO_TARGET) test

$(DEMO_TARGET): $(OBJECTS) $(DEMO_OBJECTS)
	$(CC) $(OBJECTS) $(DEMO_OBJECTS) -o $(DEMO_TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_RUNNER)
	./$(TEST_RUNNER)

$(TEST_RUNNER): $(OBJECTS) $(TEST_OBJECTS)
	$(CC) $(OBJECTS) $(TEST_OBJECTS) -o $(TEST_RUNNER) $(LDFLAGS)

test/%.o: test/%.c
	$(CC) $(CFLAGS) -I./src -c $< -o $@

clean:
	rm -f $(OBJECTS) $(DEMO_OBJECTS) $(DEMO_TARGET) $(TEST_OBJECTS) $(TEST_RUNNER) *.pem

.PHONY: all clean test
