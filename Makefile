CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Iinclude -I.
SRC = src/ravencrypt.c src/chacha20.c src/poly1305.c src/sha256.c src/hkdf.c src/utils.c
SRC += src/blake2s.c
# AES-GCM via OpenSSL - only if compiled with -DUSE_OPENSSL and linked with -lcrypto
# To enable: make OPENSSL=1
ifneq ($(OPENSSL),)
CFLAGS += -DUSE_OPENSSL
LIBS = -lcrypto
SRC += src/aes_gcm.c
endif
TEST = tests/test_ravencrypt.c
BENCH = benchmark/bench_raven.c
OBJ = $(SRC:.c=.o)

all: libraven.a test_raven bench_raven

libraven.a: $(SRC)
	$(CC) $(CFLAGS) -c $(SRC)
	ar rcs $@ *.o

test_raven: libraven.a $(TEST)
	$(CC) $(CFLAGS) -Iinclude -o $@ $(TEST) libraven.a $(LIBS)

bench_raven: libraven.a $(BENCH)
	$(CC) $(CFLAGS) -Iinclude -o $@ $(BENCH) libraven.a $(LIBS)

clean:
	rm -f *.o libraven.a test_raven bench_raven

