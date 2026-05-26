CC ?= gcc
CFLAGS ?= -O3 -march=native -mavx2 -mfma -flto -funroll-loops -fomit-frame-pointer -falign-functions=64 -falign-loops=64 -falign-jumps=32 -falign-labels=32 -fopenmp -std=c11 -Wall -Wextra -Wshadow -DNDEBUG
LDFLAGS ?= -fopenmp -flto

.PHONY: all clean test bench

all: relwehash_c benchmark_c

relwe.o: relwe.c relwe.h
	$(CC) $(CFLAGS) -c relwe.c -o relwe.o

relwehash_c: relwe.c relwe.h
	$(CC) $(CFLAGS) -DRELWE_CLI relwe.c -o relwehash_c $(LDFLAGS)

benchmark_c: benchmark.c relwe.o relwe.h
	$(CC) $(CFLAGS) benchmark.c relwe.o -o benchmark_c $(LDFLAGS)

test: all
	./relwehash_c "self-test"
	./relwehash_c --pure "self-test"
	test "$$(cd go && GOCACHE=/tmp/go-build-cache go run ./cmd/relwehash self-test)" = "$$(./relwehash_c self-test)"
	test "$$(cd go && GOCACHE=/tmp/go-build-cache go run ./cmd/relwehash --rounds 48 self-test)" = "$$(./relwehash_c --rounds 48 self-test)"
	test "$$(cd go && GOCACHE=/tmp/go-build-cache go run ./cmd/relwehash --xof-len 80 self-test)" = "$$(./relwehash_c --xof-len 80 self-test)"
	./benchmark_c --data-mb 1 --iterations 1 --threads 2

bench: benchmark_c
	./benchmark_c --data-mb 64 --iterations 16 --threads 16

clean:
	rm -f relwe.o relwehash_c benchmark_c
