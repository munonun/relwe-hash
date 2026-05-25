#include "relwe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _OPENMP
#include <omp.h>
#endif

static volatile uint64_t bench_guard;

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int parse_int(int argc, char **argv, int *i, int *out) {
    if (*i + 1 >= argc) return -1;
    *out = atoi(argv[++(*i)]);
    return 0;
}

static void run_benchmark(relwe_config cfg, const char *name, int data_mb, int iterations) {
    size_t len = (size_t)data_mb * 1024u * 1024u;
    size_t alloc_len = len ? ((len + 31u) & ~(size_t)31u) : 32u;
    uint8_t *data = (uint8_t *)aligned_alloc(32, alloc_len);
    uint8_t out[64];
    if (!data) {
        fprintf(stderr, "allocation failed\n");
        exit(1);
    }
    for (size_t i = 0; i < len; i++) data[i] = (uint8_t)(i * 131u + i / 17u);

    for (int i = 0; i < 2; i++) relwe_hash(&cfg, data, len, out);
    double start = now_sec();
    uint64_t checksum = 0;
#ifdef _OPENMP
#pragma omp parallel for num_threads(cfg.threads) reduction(^:checksum) if(iterations > 1)
#endif
    for (int i = 0; i < iterations; i++) {
        uint8_t local_out[64];
        relwe_hash(&cfg, data, len, local_out);
        if (i == 0) memcpy(out, local_out, sizeof(out));
        checksum ^= ((uint64_t)local_out[0] << 56) ^ ((uint64_t)local_out[7] << 48) ^ ((uint64_t)local_out[15] << 40) ^ (uint64_t)(uint32_t)i;
    }
    bench_guard ^= checksum ^ out[0];
    double elapsed = now_sec() - start;
    double total_mb = (double)len * (double)iterations / (1024.0 * 1024.0);

    printf("=== %s Benchmark ===\n", name);
    printf("Data size per hash: %d MB\n", data_mb);
    printf("Iterations: %d\n", iterations);
    printf("Threads: %d\n", cfg.threads);
    printf("Total processed: %.2f GB\n", total_mb / 1024.0);
    printf("Elapsed time: %.6f s\n", elapsed);
    printf("Throughput: %.2f MB/s\n\n", total_mb / elapsed);
    free(data);
}

int main(int argc, char **argv) {
    relwe_config cfg;
    relwe_default_config(&cfg);
    int data_mb = 16;
    int iterations = 5;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--data-mb")) { if (parse_int(argc, argv, &i, &data_mb)) return 2; }
        else if (!strcmp(argv[i], "--iterations")) { if (parse_int(argc, argv, &i, &iterations)) return 2; }
        else if (!strcmp(argv[i], "--threads")) { if (parse_int(argc, argv, &i, &cfg.threads)) return 2; }
        else if (!strcmp(argv[i], "--rounds")) { if (parse_int(argc, argv, &i, &cfg.rounds)) return 2; }
        else if (!strcmp(argv[i], "--pure")) { /* Deprecated no-op: pure mode is always used. */ }
    }
    if (data_mb <= 0 || iterations <= 0) return 2;

    run_benchmark(cfg, "C Pure Re-LWE AVX2", data_mb, iterations);
    return 0;
}
