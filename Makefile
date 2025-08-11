# Makefile for Ravencrypt Project

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
DEBUG_FLAGS = -g -O0
RELEASE_FLAGS = -O3
LDFLAGS = -lcrypto -lsodium -lrt

SRC = src/aes_gcm.c \
      src/chacha20_poly1305.c \
      src/hkdf.c \
      src/key_management.c \
      src/hybrid_encrypt.c \
      src/argon2_kdf.c \
      src/ravencrypt.c \
      src/utils.c

OBJ = $(SRC:.c=.o)
LIBNAME = libravencrypt.a

all: release

release: CFLAGS += $(RELEASE_FLAGS)
release: $(LIBNAME)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean $(LIBNAME)

$(LIBNAME): $(OBJ)
	ar rcs $@ $^

%.o: %.c include/ravencrypt.h
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

clean:
	rm -f $(OBJ) $(LIBNAME) test_ravencrypt bench_raven test_hybrid

test: $(LIBNAME)
	$(CC) -Iinclude -o test_ravencrypt tests/test_ravencrypt.c $(LIBNAME) $(LDFLAGS)
	./test_ravencrypt

bench: $(LIBNAME)
	$(CC) -Iinclude -o bench_raven benchmark/bench_raven.c $(LIBNAME) $(LDFLAGS)
	./bench_raven

test_hybrid: $(LIBNAME)
	$(CC) -Iinclude -o test_hybrid tests/test_hybrid.c $(LIBNAME) $(LDFLAGS)
	./test_hybrid

.PHONY: all clean test bench debug release test_hybrid
