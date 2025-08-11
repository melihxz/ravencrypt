CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Iinclude -I.
SRC = src/ravencrypt.c src/chacha20.c src/poly1305.c src/sha256.c src/hkdf.c src/utils.c
TEST = tests/test_ravencrypt.c
BENCH = benchmark/bench_raven.c
OBJ = $(SRC:.c=.o)

all: libraven.a test_raven bench_raven

libraven.a: $(SRC)
	$(CC) $(CFLAGS) -c $(SRC)
	ar rcs $@ *.o

test_raven: libraven.a $(TEST)
	$(CC) $(CFLAGS) -Iinclude -o $@ $(TEST) libraven.a

bench_raven: libraven.a $(BENCH)
	$(CC) $(CFLAGS) -Iinclude -o $@ $(BENCH) libraven.a

clean:
	rm -f *.o libraven.a test_raven bench_raven