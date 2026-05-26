#include "relwe.h"

#include <stddef.h>
#include <stdint.h>

int main(void) {
    relwe_config cfg;
    uint8_t out[64];

    relwe_default_config(&cfg);
    cfg.output_bits = 512;
    if (relwe_hash_config(out, 32, (const uint8_t *)"self-test", 9, cfg) != RELWE_ERR_OUTPUT_TOO_SMALL) return 1;
    if (relwe_hash_config(out, sizeof(out), (const uint8_t *)"self-test", 9, cfg) != RELWE_OK) return 2;

    cfg.output_bits = 256;
    cfg.k = RELWE_DEFAULT_K + 1;
    if (relwe_hash_config(out, sizeof(out), (const uint8_t *)"self-test", 9, cfg) != RELWE_ERR_INVALID_PARAM) return 3;

    relwe_default_config(&cfg);
    if (RELWE_XOF_MAX_OUTPUT < SIZE_MAX) {
        size_t too_big = RELWE_XOF_MAX_OUTPUT;
        too_big++;
        if (relwe_xof_config(out, too_big, (const uint8_t *)"self-test", 9, cfg) != RELWE_ERR_OUTPUT_TOO_LARGE) return 4;
    }
    if (relwe_xof_config(out, 0, (const uint8_t *)"self-test", 9, cfg) != RELWE_OK) return 5;

    return 0;
}
