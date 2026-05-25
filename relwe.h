#ifndef RELWE_H
#define RELWE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RELWE_N 256
#define RELWE_Q 3329
#define RELWE_DEFAULT_K 3
#define RELWE_DEFAULT_ROUNDS 32
#define RELWE_DEFAULT_OUTPUT_BITS 256
#define RELWE_DEFAULT_ETA 2

typedef struct {
    int k;
    int rounds;
    int output_bits;
    int eta;
    /* Used by benchmark/batch callers; a single digest is deterministic and serial. */
    int threads;
} relwe_config;

void relwe_default_config(relwe_config *cfg);
void relwe_hash(const relwe_config *cfg, const uint8_t *msg, size_t len, uint8_t *out);
void relwe_hash_hex(const relwe_config *cfg, const uint8_t *msg, size_t len, char *hex_out);
int relwe_hash_file_hex(const relwe_config *cfg, const char *path, char *hex_out);
size_t relwe_digest_size(const relwe_config *cfg);

#ifdef __cplusplus
}
#endif

#endif
