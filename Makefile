# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
# owsync Makefile

PROGRAM = owsync
VERSION = 1.1.0

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
override CFLAGS += -std=gnu99 -I$(INC_DIR) -D_GNU_SOURCE
LDFLAGS ?= -lpthread

# Package dependencies
PKGCONFIG ?= pkg-config
JSON_CFLAGS = $(shell $(PKGCONFIG) --cflags json-c)
JSON_LIBS = $(shell $(PKGCONFIG) --libs json-c)

# Feature flags
ENABLE_ENCRYPTION ?= 1

ifeq ($(ENABLE_ENCRYPTION),1)
    override CFLAGS += -DENABLE_ENCRYPTION
    SSL_CFLAGS = $(shell $(PKGCONFIG) --cflags openssl)
    SSL_LIBS = $(shell $(PKGCONFIG) --libs openssl libcrypto)
    override LDFLAGS += $(SSL_LIBS)
    CRYPTO_OBJ = $(BUILD_DIR)/crypto.o
else
    SSL_CFLAGS =
    SSL_LIBS =
    CRYPTO_OBJ =
endif

override CFLAGS += $(JSON_CFLAGS) $(SSL_CFLAGS)
override LDFLAGS += $(JSON_LIBS)

# Build mode
DEBUG ?= 0
ifeq ($(DEBUG),1)
    override CFLAGS += -g -O0 -DDEBUG
else
    override CFLAGS += -DNDEBUG
endif

# Optional: Custom message size limit (default 32MB)
# Usage: make MAX_MESSAGE_SIZE=$((64*1024*1024))
ifdef MAX_MESSAGE_SIZE
    override CFLAGS += -DOWSYNC_MAX_MESSAGE_SIZE=$(MAX_MESSAGE_SIZE)
endif

# Source files
SOURCES = $(SRC_DIR)/common.c \
          $(SRC_DIR)/config.c \
          $(SRC_DIR)/log.c \
          $(SRC_DIR)/state.c \
          $(SRC_DIR)/sync.c \
          $(SRC_DIR)/net.c \
          $(SRC_DIR)/daemon.c \
          $(SRC_DIR)/main.c

ifeq ($(ENABLE_ENCRYPTION),1)
    SOURCES += $(SRC_DIR)/crypto.c
endif

# Object files
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

# Default target
all: $(BIN_DIR)/$(PROGRAM)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable
$(BIN_DIR)/$(PROGRAM): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Install
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

install: $(BIN_DIR)/$(PROGRAM)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BIN_DIR)/$(PROGRAM) $(DESTDIR)$(BINDIR)/

# Test
test: $(BIN_DIR)/$(PROGRAM)
	@echo "Running test suite..."
	@cd tests && ./test_runner.sh

# Code formatting (requires astyle)
format:
	@command -v astyle >/dev/null 2>&1 || { echo "astyle not found. Install with: apt install astyle"; exit 1; }
	astyle --options=.astylerc $(SRC_DIR)/*.c $(INC_DIR)/*.h

# Static analysis (optional - skips gracefully if cppcheck not installed)
analyze:
	@./scripts/static-analysis.sh

# Combined check target
check: test analyze

# Clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Phony targets
.PHONY: all clean install test format analyze check

# Dependencies
$(BUILD_DIR)/common.o: $(INC_DIR)/common.h
$(BUILD_DIR)/config.o: $(INC_DIR)/config.h $(INC_DIR)/common.h
$(BUILD_DIR)/log.o: $(INC_DIR)/log.h
$(BUILD_DIR)/crypto.o: $(INC_DIR)/crypto.h $(INC_DIR)/common.h
$(BUILD_DIR)/state.o: $(INC_DIR)/state.h $(INC_DIR)/common.h
$(BUILD_DIR)/sync.o: $(INC_DIR)/sync.h $(INC_DIR)/state.h $(INC_DIR)/common.h
$(BUILD_DIR)/net.o: $(INC_DIR)/net.h $(INC_DIR)/state.h $(INC_DIR)/crypto.h $(INC_DIR)/common.h
$(BUILD_DIR)/daemon.o: $(INC_DIR)/daemon.h $(INC_DIR)/net.h $(INC_DIR)/state.h $(INC_DIR)/common.h
$(BUILD_DIR)/main.o: $(INC_DIR)/common.h $(INC_DIR)/config.h $(INC_DIR)/crypto.h $(INC_DIR)/state.h $(INC_DIR)/net.h $(INC_DIR)/daemon.h
