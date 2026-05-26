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
#if SIZE_MAX >= UINT64_C(274877906944)
#define RELWE_XOF_MAX_OUTPUT ((size_t)274877906944ULL)
#else
#define RELWE_XOF_MAX_OUTPUT SIZE_MAX
#endif

#define RELWE_OK 0
#define RELWE_ERR_INVALID_PARAM 1
#define RELWE_ERR_OUTPUT_TOO_SMALL 2
#define RELWE_ERR_OUTPUT_TOO_LARGE 3
#define RELWE_ERR_IO 4

typedef struct {
    int k;
    int rounds;
    int output_bits;
    int eta;
    /* Used by benchmark/batch callers; a single digest is deterministic and serial. */
    int threads;
} relwe_config;

void relwe_default_config(relwe_config *cfg);
void relwe_hash(uint8_t out[32], const uint8_t *msg, size_t len);
int relwe_xof(uint8_t *out, size_t out_len, const uint8_t *msg, size_t len);
int relwe_hash_config(uint8_t *out, size_t out_len, const uint8_t *msg, size_t len, relwe_config cfg);
int relwe_xof_config(uint8_t *out, size_t out_len, const uint8_t *msg, size_t len, relwe_config cfg);
void relwe_hash_hex(const relwe_config *cfg, const uint8_t *msg, size_t len, char *hex_out);
int relwe_hash_file_hex(const relwe_config *cfg, const char *path, char *hex_out);
size_t relwe_digest_size(const relwe_config *cfg);

#ifdef __cplusplus
}
#endif

#endif
