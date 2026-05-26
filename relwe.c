#include "relwe.h"

#include <errno.h>
#include <immintrin.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define KMAX RELWE_DEFAULT_K
#define MID 128
#define RELWE_HASH_DOMAIN "RELWE-HASH-v1"
#define RELWE_XOF_DOMAIN "RELWE-XOF-v1"
#if defined(__GNUC__) || defined(__clang__)
#define RELWE_ALIGN64 __attribute__((aligned(64)))
#define RELWE_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define RELWE_ALIGN64
#define RELWE_ALWAYS_INLINE inline
#endif

typedef struct RELWE_ALIGN64 { int c[RELWE_N]; } poly;
typedef struct RELWE_ALIGN64 {
    int fa[RELWE_N], fb[RELWE_N], p0[2 * MID - 1], p2[2 * MID - 1], psum[2 * MID - 1];
    int a_sum[MID], b_sum[MID], tmp[2 * RELWE_N - 1];
} mul_scratch;
typedef struct RELWE_ALIGN64 {
    int lo[RELWE_N], hi[RELWE_N], sum[RELWE_N];
} poly_ntt;
typedef struct RELWE_ALIGN64 { uint32_t state[16], length; uint8_t buf[64]; size_t buf_len; uint64_t total_len; } sponge;
typedef struct RELWE_ALIGN64 { uint32_t state[16], counter; } arx_stream;
typedef struct RELWE_ALIGN64 { uint32_t iv[16], seed[16]; poly state[KMAX], err[KMAX]; } core_state;

static int bit_reverse[RELWE_N], bitrev_i[RELWE_N / 2], bitrev_j[RELWE_N / 2], bitrev_count;
static int stage_twiddles[2][8][RELWE_N / 2];
static int stage_roots[8], stage_inv_roots[8], inv_n, tables_ready;

static RELWE_ALWAYS_INLINE uint32_t rotl32(uint32_t x, int n) { n &= 31; return n ? ((x << n) | (x >> (32 - n))) : x; }
static RELWE_ALWAYS_INLINE uint32_t load32(const uint8_t *p, size_t n) { uint32_t v = 0; for (size_t i = 0; i < n; i++) v |= (uint32_t)p[i] << (8 * i); return v; }
static RELWE_ALWAYS_INLINE int mod_q(int x) { x %= RELWE_Q; if (x < 0) x += RELWE_Q; return x; }
static RELWE_ALWAYS_INLINE int add_mod(int a, int b) { int v = a + b; if (v >= RELWE_Q) v -= RELWE_Q; return v; }
static RELWE_ALWAYS_INLINE int sub_mod(int a, int b) { int v = a - b; if (v < 0) v += RELWE_Q; return v; }
static RELWE_ALWAYS_INLINE int mul_mod(int a, int b) { return (int)((long long)a * b % RELWE_Q); }

static int cpu_threads(void) {
#ifdef _OPENMP
    return omp_get_max_threads();
#else
    return 1;
#endif
}

void relwe_default_config(relwe_config *cfg) {
    cfg->k = RELWE_DEFAULT_K; cfg->rounds = RELWE_DEFAULT_ROUNDS; cfg->output_bits = RELWE_DEFAULT_OUTPUT_BITS;
    cfg->eta = RELWE_DEFAULT_ETA; cfg->threads = cpu_threads();
}

static relwe_config norm_cfg(const relwe_config *in) {
    relwe_config c; relwe_default_config(&c); if (in) c = *in;
    if (c.k != RELWE_DEFAULT_K) c.k = RELWE_DEFAULT_K;
    if (c.rounds <= 0) c.rounds = RELWE_DEFAULT_ROUNDS;
    if (c.output_bits != 256 && c.output_bits != 512) c.output_bits = RELWE_DEFAULT_OUTPUT_BITS;
    if (c.eta <= 0) c.eta = RELWE_DEFAULT_ETA;
    if (c.threads <= 0) c.threads = cpu_threads();
    return c;
}

size_t relwe_digest_size(const relwe_config *cfg) { relwe_config c = norm_cfg(cfg); return (size_t)c.output_bits / 8; }

static int validate_config(relwe_config c) {
    if (c.k != RELWE_DEFAULT_K) return RELWE_ERR_INVALID_PARAM;
    if (c.rounds <= 0) return RELWE_ERR_INVALID_PARAM;
    if (c.output_bits != 256 && c.output_bits != 512) return RELWE_ERR_INVALID_PARAM;
    if (c.eta <= 0) return RELWE_ERR_INVALID_PARAM;
    if (c.threads <= 0) return RELWE_ERR_INVALID_PARAM;
    return RELWE_OK;
}

static int mod_pow(int base, int exp, int mod) {
    long long r = 1, b = base % mod;
    while (exp > 0) { if (exp & 1) r = r * b % mod; b = b * b % mod; exp >>= 1; }
    return (int)r;
}
static int mod_inv(int x, int mod) { return mod_pow(x, mod - 2, mod); }
static int primitive_root_mod(int mod) {
    int factors[16], nf = 0, n = mod - 1;
    for (int d = 2; d * d <= n; d++) if (n % d == 0) { factors[nf++] = d; while (n % d == 0) n /= d; }
    if (n > 1) factors[nf++] = n;
    for (int g = 2; g < mod; g++) {
        int ok = 1;
        for (int i = 0; i < nf; i++) if (mod_pow(g, (mod - 1) / factors[i], mod) == 1) { ok = 0; break; }
        if (ok) return g;
    }
    return 0;
}
static void init_tables(void) {
#ifdef _OPENMP
#pragma omp critical(relwe_tables_init)
#endif
    {
    if (!tables_ready) {
    for (int i = 0; i < RELWE_N; i++) {
        int x = i, rev = 0;
        for (int bit = RELWE_N >> 1; bit > 0; bit >>= 1) { rev = (rev << 1) | (x & 1); x >>= 1; }
        bit_reverse[i] = rev;
        if (i < rev) {
            bitrev_i[bitrev_count] = i;
            bitrev_j[bitrev_count] = rev;
            bitrev_count++;
        }
    }
    int root = primitive_root_mod(RELWE_Q), stage = 0;
    for (int length = 2; length <= RELWE_N; length <<= 1) {
        int r = mod_pow(root, (RELWE_Q - 1) / length, RELWE_Q);
        stage_roots[stage] = r; stage_inv_roots[stage] = mod_inv(r, RELWE_Q); stage++;
    }
    for (int inv = 0; inv < 2; inv++) {
        for (stage = 0; stage < 8; stage++) {
            int length = 2 << stage, half = length >> 1;
            int wlen = inv ? stage_inv_roots[stage] : stage_roots[stage];
            int w = 1;
            for (int i = 0; i < half; i++) {
                stage_twiddles[inv][stage][i] = w;
                w = mul_mod(w, wlen);
            }
        }
    }
    inv_n = mod_inv(RELWE_N, RELWE_Q);
    tables_ready = 1;
    }
    }
}

static void ntt_in_place(int v[RELWE_N], int invert) {
    init_tables();
    for (int k = 0; k < bitrev_count; k++) {
        int i = bitrev_i[k], j = bitrev_j[k], t = v[i];
        v[i] = v[j]; v[j] = t;
    }
    int stage = 0;
    for (int length = 2; length <= RELWE_N; length <<= 1) {
        int half = length >> 1;
        const int *tw = stage_twiddles[invert ? 1 : 0][stage];
        for (int start = 0; start < RELWE_N; start += length) {
            for (int j = 0, off = start; j < half; j++, off++) {
                int u = v[off], x = mul_mod(v[off + half], tw[j]);
                int sum = u + x; if (sum >= RELWE_Q) sum -= RELWE_Q;
                int diff = u - x; if (diff < 0) diff += RELWE_Q;
                v[off] = sum; v[off + half] = diff;
            }
        }
        stage++;
    }
    if (invert) for (int i = 0; i < RELWE_N; i++) v[i] = mul_mod(v[i], inv_n);
}

static void qround(uint32_t s[16], int a, int b, int c, int d) {
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 16); s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 8);  s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 7);
}
static RELWE_ALWAYS_INLINE void arx_round(uint32_t s[16], int r) {
    s[0] += 0x9E3779B9u + (uint32_t)r; s[5] ^= rotl32(s[0], 3 + (r & 15));
    s[10] += rotl32(s[15], 11); s[15] ^= 0xA5A5A5A5u + 0x01010101u * (uint32_t)r;
    qround(s,0,4,8,12); qround(s,1,5,9,13); qround(s,2,6,10,14); qround(s,3,7,11,15);
    qround(s,0,5,10,15); qround(s,1,6,11,12); qround(s,2,7,8,13); qround(s,3,4,9,14);
}
static void first16(const uint32_t *words, size_t n, uint32_t out[16]) {
    for (int i = 0; i < 16; i++) out[i] = (i < (int)n) ? words[i] : (0x9E3779B9u ^ (uint32_t)i * 0x85EBCA6Bu);
}
static void arx_permute_in(uint32_t s[16], int rounds) {
    switch (rounds) {
    case 6:
        for (int r = 0; r < 6; r++) arx_round(s, r);
        return;
    case 8:
        for (int r = 0; r < 8; r++) arx_round(s, r);
        return;
    case 10:
        for (int r = 0; r < 10; r++) arx_round(s, r);
        return;
    case 12:
        for (int r = 0; r < 12; r++) arx_round(s, r);
        return;
    case 16:
        for (int r = 0; r < 16; r++) arx_round(s, r);
        return;
    default:
        for (int r = 0; r < rounds; r++) arx_round(s, r);
    }
}
static void arx_permute(const uint32_t *words, size_t n, int rounds, uint32_t out[16]) { first16(words, n, out); arx_permute_in(out, rounds); }

static void mix_words(const uint32_t *words, size_t n, uint32_t extra, int rounds, uint32_t out[16]) {
    uint32_t s[16] = {0x6A09E667u,0xBB67AE85u,0x3C6EF372u,0xA54FF53Au,0x510E527Fu,0x9B05688Cu,0x1F83D9ABu,0x5BE0CD19u,0xCBBB9D5Du,0x629A292Au,0x9159015Au,0x152FECD8u,0x67332667u,0x8EB44A87u,0xDB0C2E0Du,extra};
    for (size_t idx = 0; idx < n; idx++) {
        int lane = (int)idx & 15; uint32_t w = words[idx];
        s[lane] += w + (uint32_t)idx * 0x9E3779B1u; s[(lane + 5) & 15] ^= rotl32(w, (int)(idx % 23) + 3);
        if (lane == 15) arx_permute_in(s, rounds);
    }
    s[0] ^= (uint32_t)n; s[8] ^= (uint32_t)(n >> 32); arx_permute_in(s, rounds + 6); memcpy(out, s, 64);
}

static void stream_init(arx_stream *st, const uint32_t seed[16], uint32_t domain) {
    uint32_t base[16]; first16(seed, 16, base); base[0] ^= domain; base[1] += domain * 0x9E3779B1u; base[7] ^= rotl32(domain, 13);
    arx_permute(base, 16, 12, st->state); st->counter = 0;
}
static void stream_words(arx_stream *st, uint32_t *out, size_t count) {
    size_t n = 0;
    while (n < count) {
        uint32_t block[16], mixed[16]; memcpy(block, st->state, 64); block[0] += st->counter; block[3] ^= rotl32(st->counter, 17); block[12] += 0xD1B54A32u + st->counter * 0x9E3779B1u;
        arx_permute(block, 16, 10, mixed);
        for (int i = 0; i < 16; i++) mixed[i] += st->state[(i + 5) & 15] + st->counter;
        arx_permute(mixed, 16, 6, st->state); st->counter++;
        for (int i = 0; i < 16 && n < count; i++) out[n++] = mixed[i];
    }
}
static void derive_words(const uint32_t seed[16], uint32_t domain, uint32_t *out, size_t count) { arx_stream st; stream_init(&st, seed, domain); stream_words(&st, out, count); }

static void sponge_init(sponge *s, int k, int rounds, int output_bits, int eta) {
    uint32_t eta_delta = (uint32_t)(eta - RELWE_DEFAULT_ETA);
    uint32_t init[16] = {0x70757265u,0x72656C77u,0x65486173u,0x68327632u,RELWE_N,RELWE_Q,(uint32_t)k,(uint32_t)rounds,(uint32_t)output_bits,0x243F6A88u ^ eta_delta * 0x45D9F3Bu,0x85A308D3u,0x13198A2Eu,0x03707344u,0xA4093822u,0x299F31D0u,0x082EFA98u};
    memcpy(s->state, init, 64); s->buf_len = 0; s->total_len = 0; s->length = 0;
}
static void sponge_absorb_block(sponge *s, const uint8_t *block, size_t len, int full) {
    uint32_t words[16]; size_t wc = len ? (len + 3) / 4 : 1;
    if (len == 64) {
        memcpy(words, block, sizeof(words));
    } else {
        for (int i = 0; i < 16; i++) words[i] = (i < (int)wc) ? load32(block + (size_t)i * 4, len > (size_t)i * 4 ? (((len - (size_t)i * 4) >= 4) ? 4 : len - (size_t)i * 4) : 0) : 0;
    }
    for (int i = 0; i < 16; i++) { int lane = (i * 5 + 3) & 15; s->state[lane] ^= words[i]; s->state[(lane + 7) & 15] += rotl32(words[i] ^ (uint32_t)i, 3 + (i & 15)); }
    if (full) s->state[0] ^= (uint32_t)len; else s->state[0] ^= 0x80000000u | (uint32_t)len;
    s->state[9] += (uint32_t)s->total_len; s->state[13] ^= (uint32_t)(s->total_len >> 32); arx_permute_in(s->state, 8);
}

static void sponge_update(sponge *s, const uint8_t *data, size_t len) {
    if (!len) return;
    s->total_len += len;
    size_t off = 0;
    if (s->buf_len) {
        size_t take = 64 - s->buf_len; if (take > len) take = len; memcpy(s->buf + s->buf_len, data, take); s->buf_len += take; off += take;
        if (s->buf_len == 64) { sponge_absorb_block(s, s->buf, 64, 1); s->buf_len = 0; }
    }
    while (off + 64 <= len) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(data + off + 512, 0, 1);
#endif
        sponge_absorb_block(s, data + off, 64, 1); off += 64;
    }
    if (off < len) { s->buf_len = len - off; memcpy(s->buf, data + off, s->buf_len); }
}
static void sponge_finalize(sponge *s, uint32_t out[16]) {
    uint8_t pad[65]; memcpy(pad, s->buf, s->buf_len); pad[s->buf_len] = 0x80; sponge_absorb_block(s, pad, s->buf_len + 1, 0);
    s->state[1] ^= (uint32_t)s->total_len; s->state[2] ^= (uint32_t)(s->total_len >> 32); s->state[14] ^= 0xFFFFFFFFu; arx_permute_in(s->state, 16); memcpy(out, s->state, 64);
}
static void absorb_bytes_domain(const relwe_config *cfg, const char *domain, const uint8_t *msg, size_t len, uint32_t iv[16]) {
    sponge s; sponge_init(&s, cfg->k, cfg->rounds, cfg->output_bits, cfg->eta);
    sponge_update(&s, (const uint8_t *)domain, strlen(domain));
    sponge_update(&s, msg, len);
    sponge_finalize(&s, iv);
}
static int noise_bound(const relwe_config *cfg) { return 16 * (cfg->eta > 0 ? cfg->eta : RELWE_DEFAULT_ETA); }
static void poly_uniform(poly *p, const uint32_t seed[16], uint32_t domain) { uint32_t w[RELWE_N]; derive_words(seed, domain, w, RELWE_N); for (int i = 0; i < RELWE_N; i++) p->c[i] = (int)(w[i] % RELWE_Q); }
static void poly_small(poly *p, const uint32_t *words, size_t nw, int bound) {
    int width = 2 * bound + 1;
    for (int i = 0; i < RELWE_N; i++) { uint32_t w = words[i % nw]; uint32_t mixed = w ^ rotl32(w, 7) ^ rotl32(w, 19) ^ (uint32_t)i * 0x9E3779B1u; p->c[i] = mod_q((int)((uint64_t)mixed % (uint32_t)width) - bound); }
}
static void initial_state(const relwe_config *cfg, const uint32_t iv[16], poly state[KMAX]) { for (int i = 0; i < cfg->k; i++) poly_uniform(&state[i], iv, 0x10000000u ^ (uint32_t)i * 0x9E3779B1u); }
static void initial_error(const relwe_config *cfg, const uint32_t iv[16], poly err[KMAX]) { uint32_t w[RELWE_N]; for (int i = 0; i < cfg->k; i++) { derive_words(iv, 0x20000000u ^ (uint32_t)i * 0x85EBCA6Bu, w, RELWE_N); poly_small(&err[i], w, RELWE_N, noise_bound(cfg)); } }
static void poly_add(poly *o, const poly *a, const poly *b) {
#ifdef __AVX2__
    __m256i q = _mm256_set1_epi32(RELWE_Q), qm1 = _mm256_set1_epi32(RELWE_Q - 1);
    for (int i = 0; i < RELWE_N; i += 8) {
        __m256i x = _mm256_load_si256((const __m256i *)(a->c + i)), y = _mm256_load_si256((const __m256i *)(b->c + i));
        __m256i s = _mm256_add_epi32(x, y), ge = _mm256_cmpgt_epi32(s, qm1);
        _mm256_store_si256((__m256i *)(o->c + i), _mm256_sub_epi32(s, _mm256_and_si256(ge, q)));
    }
#else
    for (int i = 0; i < RELWE_N; i++) { int v = a->c[i] + b->c[i]; if (v >= RELWE_Q) v -= RELWE_Q; o->c[i] = v; }
#endif
}
static void poly_to_words(const poly *p, uint32_t *out) { for (int i = 0; i < RELWE_N; i += 2) out[i / 2] = (uint32_t)p->c[i] | ((uint32_t)p->c[i + 1] << 16); }

static void pointwise_mul_mod(int *out, const int *a, const int *b) {
    for (int i = 0; i < RELWE_N; i += 8) {
        out[i+0] = mul_mod(a[i+0], b[i+0]);
        out[i+1] = mul_mod(a[i+1], b[i+1]);
        out[i+2] = mul_mod(a[i+2], b[i+2]);
        out[i+3] = mul_mod(a[i+3], b[i+3]);
        out[i+4] = mul_mod(a[i+4], b[i+4]);
        out[i+5] = mul_mod(a[i+5], b[i+5]);
        out[i+6] = mul_mod(a[i+6], b[i+6]);
        out[i+7] = mul_mod(a[i+7], b[i+7]);
    }
}

static void precompute_poly_ntt(poly_ntt *out, const poly *p) {
    memset(out, 0, sizeof(*out));
    memcpy(out->lo, p->c, MID * sizeof(int));
    memcpy(out->hi, p->c + MID, MID * sizeof(int));
#ifdef __AVX2__
    __m256i q = _mm256_set1_epi32(RELWE_Q), qm1 = _mm256_set1_epi32(RELWE_Q - 1);
    for (int i = 0; i < MID; i += 8) {
        __m256i lo = _mm256_load_si256((const __m256i *)(p->c + i));
        __m256i hi = _mm256_load_si256((const __m256i *)(p->c + MID + i));
        __m256i sum = _mm256_add_epi32(lo, hi);
        __m256i ge = _mm256_cmpgt_epi32(sum, qm1);
        _mm256_store_si256((__m256i *)(out->sum + i), _mm256_sub_epi32(sum, _mm256_and_si256(ge, q)));
    }
#else
    for (int i = 0; i < MID; i++) {
        int v = p->c[i] + p->c[i + MID];
        if (v >= RELWE_Q) v -= RELWE_Q;
        out->sum[i] = v;
    }
#endif
    ntt_in_place(out->lo, 0);
    ntt_in_place(out->hi, 0);
    ntt_in_place(out->sum, 0);
}

static void block_conv128_rhs_ntt(int out[2 * MID - 1], const int *a, const int *b_ntt, mul_scratch *s) {
    memset(s->fa, 0, sizeof(s->fa)); memcpy(s->fa, a, MID * sizeof(int));
    ntt_in_place(s->fa, 0);
    pointwise_mul_mod(s->fa, s->fa, b_ntt);
    ntt_in_place(s->fa, 1); memcpy(out, s->fa, (2 * MID - 1) * sizeof(int));
}
static void block_conv128_ntt_pair(int out[2 * MID - 1], const int *a_ntt, const int *b_ntt, mul_scratch *s) {
    pointwise_mul_mod(s->fa, a_ntt, b_ntt);
    ntt_in_place(s->fa, 1); memcpy(out, s->fa, (2 * MID - 1) * sizeof(int));
}
static void finish_karatsuba(poly *out, mul_scratch *s) {
    memset(s->tmp, 0, sizeof(s->tmp)); for (int i = 0; i < 2 * MID - 1; i++) s->tmp[i] = s->p0[i];
    for (int i = 0; i < 2 * MID - 1; i++) s->tmp[i + MID] = add_mod(s->tmp[i + MID], mod_q(s->psum[i] - s->p0[i] - s->p2[i]));
    for (int i = 0; i < 2 * MID - 1; i++) s->tmp[i + RELWE_N] = add_mod(s->tmp[i + RELWE_N], s->p2[i]);
    for (int d = 2 * RELWE_N - 2; d >= RELWE_N; d--) { int c = s->tmp[d]; if (c) { s->tmp[d] = 0; s->tmp[d - MID] = sub_mod(s->tmp[d - MID], c); s->tmp[d - RELWE_N] = sub_mod(s->tmp[d - RELWE_N], c); } }
    memcpy(out->c, s->tmp, RELWE_N * sizeof(int));
}
static void poly_mul_rhs_ntt(poly *out, const poly *p, const poly_ntt *q, mul_scratch *s) {
    const int *a0 = p->c, *a1 = p->c + MID;
    for (int i = 0; i < MID; i++) { int v = a0[i] + a1[i]; if (v >= RELWE_Q) v -= RELWE_Q; s->a_sum[i] = v; }
    block_conv128_rhs_ntt(s->p0, a0, q->lo, s);
    block_conv128_rhs_ntt(s->p2, a1, q->hi, s);
    block_conv128_rhs_ntt(s->psum, s->a_sum, q->sum, s);
    finish_karatsuba(out, s);
}
static void poly_mul_ntt_pair(poly *out, const poly_ntt *p, const poly_ntt *q, mul_scratch *s) {
    block_conv128_ntt_pair(s->p0, p->lo, q->lo, s);
    block_conv128_ntt_pair(s->p2, p->hi, q->hi, s);
    block_conv128_ntt_pair(s->psum, p->sum, q->sum, s);
    finish_karatsuba(out, s);
}

static void init_core(const relwe_config *cfg, const uint32_t iv[16], core_state *cs) {
    memcpy(cs->iv, iv, 64); initial_state(cfg, iv, cs->state); initial_error(cfg, iv, cs->err);
    uint32_t seed_in[19]; memcpy(seed_in, iv, 64); seed_in[16] = (uint32_t)cfg->k; seed_in[17] = (uint32_t)cfg->rounds; seed_in[18] = (uint32_t)cfg->output_bits; mix_words(seed_in, 19, 0x5EED0001u, 12, cs->seed);
}
static void state_feedback(const relwe_config *cfg, const poly state[KMAX], const poly err[KMAX], const uint32_t iv[16], int round, uint32_t out[16]) {
    uint32_t words[16 + 6 + KMAX * RELWE_N]; size_t n = 0; memcpy(words + n, iv, 64); n += 16;
    words[n++] = (uint32_t)round; words[n++] = (uint32_t)cfg->k; words[n++] = (uint32_t)cfg->rounds; words[n++] = (uint32_t)cfg->output_bits; words[n++] = RELWE_N; words[n++] = RELWE_Q;
    for (int i = 0; i < cfg->k; i++) { poly_to_words(&state[i], words + n); n += RELWE_N / 2; }
    for (int i = 0; i < cfg->k; i++) { poly_to_words(&err[i], words + n); n += RELWE_N / 2; }
    mix_words(words, n, 0xFEE1DEADu ^ (uint32_t)round, 6, out);
}
static void round_salt(const relwe_config *cfg, const uint32_t seed[16], const uint32_t feedback[16], const uint32_t iv[16], int round, uint32_t out[16]) {
    uint32_t m[53]; size_t n = 0; memcpy(m + n, iv, 64); n += 16; memcpy(m + n, seed, 64); n += 16; memcpy(m + n, feedback, 64); n += 16;
    m[n++] = (uint32_t)round; m[n++] = (uint32_t)round * 0x9E3779B1u; m[n++] = (uint32_t)cfg->k; m[n++] = RELWE_Q; m[n++] = RELWE_N; mix_words(m, n, 0x5A17C0DEu ^ (uint32_t)round, 10, out);
}
static void arx_error_words(const relwe_config *cfg, const poly prev_err[KMAX], const uint32_t seed[16], const uint32_t salt[16], const poly prev_state[KMAX], uint32_t *words) {
    int prev[KMAX * RELWE_N], st[KMAX * RELWE_N], pc = cfg->k * RELWE_N; for (int i = 0; i < cfg->k; i++) { memcpy(prev + i * RELWE_N, prev_err[i].c, RELWE_N * sizeof(int)); memcpy(st + i * RELWE_N, prev_state[i].c, RELWE_N * sizeof(int)); }
    uint32_t key_in[32], key[16]; memcpy(key_in, seed, 64); memcpy(key_in + 16, salt, 64); mix_words(key_in, 32, 0xA11CE000u ^ (uint32_t)pc, 8, key);
    for (int lane = 0; lane < pc; lane++) {
        uint32_t e = (uint32_t)prev[lane % pc], b = (uint32_t)st[(lane * 5 + 17) % pc], x = (e | (b << 16)) ^ key[lane & 15] ^ ((uint32_t)lane * 0x9E3779B1u);
        uint32_t y = key[(lane * 7 + 3) & 15] + b * 0x85EBCA6Bu + (uint32_t)lane + seed[(lane * 3 + 1) & 15];
        uint32_t z = x ^ rotl32(y, 13) ^ salt[(lane * 5 + 9) & 15] ^ 0xC2B2AE35u;
        for (int r = 0; r < 8; r++) { uint32_t nb = (lane > 0) ? words[lane - 1] : salt[(r + lane) & 15]; x += y + seed[(r * 3 + lane) & 15]; y = rotl32(y ^ z ^ nb, 5 + ((r + lane) % 23)); z += rotl32(x, 7) + salt[(r * 5 + lane) & 15]; x ^= rotl32(z, 16); y += rotl32(x ^ nb, 11); }
        words[lane] = x ^ y ^ z;
    }
}
static void evolve_error(const relwe_config *cfg, const poly prev_err[KMAX], const uint32_t seed[16], const uint32_t salt[16], const poly prev_state[KMAX], poly out[KMAX]) {
    uint32_t words[KMAX * RELWE_N]; arx_error_words(cfg, prev_err, seed, salt, prev_state, words); for (int i = 0; i < cfg->k; i++) poly_small(&out[i], words + i * RELWE_N, RELWE_N, noise_bound(cfg));
}
static void round_matrix_base(const uint32_t seed[16], const uint32_t salt[16], const uint32_t iv[16], int round, uint32_t base[16]) {
    uint32_t in[48]; memcpy(in, iv, 64); memcpy(in + 16, seed, 64); memcpy(in + 32, salt, 64); mix_words(in, 48, 0xA7000000u ^ (uint32_t)round, 8, base);
}
static void round_matrix_poly(const uint32_t base[16], int round, int i, int j, poly *out) {
    poly_uniform(out, base, 0x30000000u ^ (uint32_t)round * 0x9E3779B1u ^ (uint32_t)(i << 8) ^ (uint32_t)j);
}
static void evolve_seed(const relwe_config *cfg, const uint32_t seed[16], const uint32_t salt[16], const poly state[KMAX], const poly err[KMAX], const uint32_t iv[16], int round, uint32_t out[16]) {
    uint32_t words[16 + 16 + 16 + 4 + KMAX * 64]; size_t n = 0; memcpy(words + n, iv, 64); n += 16; memcpy(words + n, seed, 64); n += 16; memcpy(words + n, salt, 64); n += 16;
    words[n++] = (uint32_t)round; words[n++] = (uint32_t)cfg->k; words[n++] = (uint32_t)cfg->rounds; words[n++] = (uint32_t)cfg->output_bits;
    for (int i = 0; i < cfg->k; i++) for (int j = 0; j < RELWE_N; j += 8) words[n++] = (uint32_t)state[i].c[j] | ((uint32_t)state[i].c[(j + 3) % RELWE_N] << 16) | ((uint32_t)i << 28);
    for (int i = 0; i < cfg->k; i++) for (int j = 1; j < RELWE_N; j += 8) words[n++] = (uint32_t)err[i].c[j] | ((uint32_t)err[i].c[(j + 5) % RELWE_N] << 16) | ((uint32_t)i << 29);
    mix_words(words, n, 0x51ED0000u ^ (uint32_t)round, 10, out);
}
static void mix_round(const relwe_config *cfg, core_state *cs, int round) {
    uint32_t feedback[16], salt[16], matrix_base[16], next_seed[16]; poly next_err[KMAX], next_state[KMAX]; poly_ntt state_ntt[KMAX]; mul_scratch scratch;
    state_feedback(cfg, cs->state, cs->err, cs->iv, round, feedback); round_salt(cfg, cs->seed, feedback, cs->iv, round, salt); evolve_error(cfg, cs->err, cs->seed, salt, cs->state, next_err);
    round_matrix_base(cs->seed, salt, cs->iv, round, matrix_base);
    for (int j = 0; j < cfg->k; j++) precompute_poly_ntt(&state_ntt[j], &cs->state[j]);
    for (int i = 0; i < cfg->k; i++) {
        poly acc = {0};
        for (int j = 0; j < cfg->k; j++) { poly m, prod, tmp; round_matrix_poly(matrix_base, round, i, j, &m); poly_mul_rhs_ntt(&prod, &m, &state_ntt[j], &scratch); poly_add(&tmp, &acc, &prod); acc = tmp; }
        poly tweak, tmp; poly_mul_ntt_pair(&tweak, &state_ntt[i], &state_ntt[(i + 1) % cfg->k], &scratch); poly_add(&tmp, &acc, &next_err[i]); poly_add(&next_state[i], &tmp, &tweak);
    }
    evolve_seed(cfg, cs->seed, salt, next_state, next_err, cs->iv, round, next_seed); memcpy(cs->state, next_state, sizeof(next_state)); memcpy(cs->err, next_err, sizeof(next_err)); memcpy(cs->seed, next_seed, 64);
}
static void run_core(const relwe_config *cfg, const uint32_t iv[16], core_state *cs) { init_core(cfg, iv, cs); for (int r = 0; r < cfg->rounds; r++) mix_round(cfg, cs, r); }
static size_t domain_words(const char *domain, uint32_t *out) {
    size_t len = strlen(domain);
    if (!len) { out[0] = 0; return 1; }
    size_t n = (len + 3u) / 4u;
    for (size_t i = 0; i < n; i++) {
        uint32_t v = 0;
        for (size_t j = 0; j < 4 && i * 4 + j < len; j++) v |= (uint32_t)(uint8_t)domain[i * 4 + j] << (8 * j);
        out[i] = v;
    }
    return n;
}
static void squeeze_xof(const relwe_config *cfg, const core_state *cs, const char *domain, uint8_t *out, size_t out_len) {
    if (!out_len) return;
    uint32_t words[16 + 16 + 16 + 5 + KMAX * RELWE_N + KMAX * (RELWE_N / 2)], folded[16], digest[16]; size_t n = 0;
    n += domain_words(domain, words + n);
    memcpy(words + n, cs->iv, 64); n += 16; memcpy(words + n, cs->seed, 64); n += 16;
    words[n++] = RELWE_N; words[n++] = RELWE_Q; words[n++] = (uint32_t)cfg->k; words[n++] = (uint32_t)cfg->rounds; words[n++] = (uint32_t)cfg->output_bits;
    for (int p = 0; p < cfg->k; p++) { int stride = 73 + 2 * p; for (int t = 0; t < RELWE_N; t++) words[n++] = (uint32_t)cs->state[p].c[(t * stride + 17 * p) & 255] | ((uint32_t)cs->state[p].c[(t * 41 + 19 + p) & 255] << 16) | ((uint32_t)(p & 3) << 30); }
    for (int p = 0; p < cfg->k; p++) { int stride = 89 + 2 * p; for (int t = 0; t < RELWE_N; t += 2) words[n++] = (uint32_t)cs->err[p].c[(t * stride + 29 * p) & 255] | ((uint32_t)cs->err[p].c[(t * 53 + 31 + p) & 255] << 16) | ((uint32_t)(p & 3) << 29); }
    size_t domain_len = strlen(domain);
    mix_words(words, n, 0xF1A1F01Du ^ (uint32_t)domain_len, 16, folded); arx_stream st; stream_init(&st, folded, 0xD16E5700u ^ (uint32_t)domain_len);
    size_t done = 0, word_index = 0;
    while (done < out_len) {
        stream_words(&st, digest, 16);
        for (int i = 0; i < 16 && done < out_len; i++, word_index++) {
            uint32_t w = digest[i] ^ folded[word_index & 15];
            w = rotl32(w, (int)((7u + (uint32_t)word_index) & 31u)) ^ folded[(word_index * 5 + 3) & 15];
            for (int b = 0; b < 4 && done < out_len; b++, done++) out[done] = (uint8_t)(w >> (8 * b));
        }
    }
}

static void hash_domain_xof(const relwe_config *cfg, const char *domain, const uint8_t *msg, size_t len, uint8_t *out, size_t out_len) { uint32_t iv[16]; core_state cs; absorb_bytes_domain(cfg, domain, msg, len, iv); run_core(cfg, iv, &cs); squeeze_xof(cfg, &cs, domain, out, out_len); }
static void hash_pure(const relwe_config *cfg, const uint8_t *msg, size_t len, uint8_t *out) { hash_domain_xof(cfg, RELWE_HASH_DOMAIN, msg, len, out, relwe_digest_size(cfg)); }

void relwe_hash(uint8_t out[32], const uint8_t *msg, size_t len) { relwe_config cfg; relwe_default_config(&cfg); hash_domain_xof(&cfg, RELWE_HASH_DOMAIN, msg, len, out, 32); }
int relwe_xof(uint8_t *out, size_t out_len, const uint8_t *msg, size_t len) { relwe_config cfg; relwe_default_config(&cfg); return relwe_xof_config(out, out_len, msg, len, cfg); }
int relwe_hash_config(uint8_t *out, size_t out_len, const uint8_t *msg, size_t len, relwe_config cfg) {
    if (validate_config(cfg)) return RELWE_ERR_INVALID_PARAM;
    if (!out || (!msg && len)) return RELWE_ERR_INVALID_PARAM;
    size_t need = (size_t)cfg.output_bits / 8u;
    if (out_len < need) return RELWE_ERR_OUTPUT_TOO_SMALL;
    hash_pure(&cfg, msg, len, out);
    return RELWE_OK;
}
int relwe_xof_config(uint8_t *out, size_t out_len, const uint8_t *msg, size_t len, relwe_config cfg) {
    if (validate_config(cfg)) return RELWE_ERR_INVALID_PARAM;
    if ((!out && out_len) || (!msg && len)) return RELWE_ERR_INVALID_PARAM;
    if (out_len > RELWE_XOF_MAX_OUTPUT) return RELWE_ERR_OUTPUT_TOO_LARGE;
    if (out_len) hash_domain_xof(&cfg, RELWE_XOF_DOMAIN, msg, len, out, out_len);
    return RELWE_OK;
}
void relwe_hash_hex(const relwe_config *cfg_in, const uint8_t *msg, size_t len, char *hex_out) {
    static const char hd[] = "0123456789abcdef"; uint8_t d[64]; relwe_config cfg; relwe_default_config(&cfg); if (cfg_in) cfg = *cfg_in; size_t n = relwe_digest_size(&cfg);
    if (!hex_out || relwe_hash_config(d, sizeof(d), msg, len, cfg)) { if (hex_out) hex_out[0] = 0; return; }
    for (size_t i = 0; i < n; i++) { hex_out[2*i] = hd[d[i] >> 4]; hex_out[2*i+1] = hd[d[i] & 15]; } hex_out[2*n] = 0;
}
int relwe_hash_file_hex(const relwe_config *cfg, const char *path, char *hex_out) { FILE *f = fopen(path, "rb"); if (!f) return -1; if (fseek(f,0,SEEK_END)) { fclose(f); return -1; } long sz = ftell(f); if (sz < 0) { fclose(f); return -1; } rewind(f); uint8_t *buf = (uint8_t *)malloc((size_t)sz ? (size_t)sz : 1); if (!buf) { fclose(f); return -1; } size_t got = fread(buf,1,(size_t)sz,f); fclose(f); if (got != (size_t)sz) { free(buf); return -1; } relwe_hash_hex(cfg, buf, (size_t)sz, hex_out); free(buf); return hex_out && hex_out[0] ? 0 : -1; }

#ifdef RELWE_CLI
static int next_long(int argc, char **argv, int *i, long min, long max, long *out) {
    if (*i + 1 >= argc) return -1;
    const char *s = argv[++(*i)];
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < min || v > max) return -1;
    *out = v;
    return 0;
}
static int next_size(int argc, char **argv, int *i, size_t max, size_t *out) {
    if (*i + 1 >= argc) return -1;
    const char *s = argv[++(*i)];
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || *end || v > (unsigned long long)max) return -1;
    *out = (size_t)v;
    return 0;
}
static void hex_encode(const uint8_t *in, size_t n, char *out) { static const char hd[] = "0123456789abcdef"; for (size_t i = 0; i < n; i++) { out[2*i] = hd[in[i] >> 4]; out[2*i+1] = hd[in[i] & 15]; } out[2*n] = 0; }
static int read_file_all(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    if (fseek(f,0,SEEK_END)) { fclose(f); return -1; }
    long sz = ftell(f); if (sz < 0) { fclose(f); return -1; }
    rewind(f); uint8_t *buf = (uint8_t *)malloc((size_t)sz ? (size_t)sz : 1); if (!buf) { fclose(f); return -1; }
    size_t got = fread(buf,1,(size_t)sz,f); fclose(f); if (got != (size_t)sz) { free(buf); return -1; }
    *out = buf; *out_len = (size_t)sz; return 0;
}
int main(int argc, char **argv) {
    relwe_config cfg; relwe_default_config(&cfg); const char *file = NULL, *msg = NULL; size_t xof_len = 0; int xof_set = 0;
    for (int i = 1; i < argc; i++) {
        long v = 0;
        if (!strcmp(argv[i], "--file") || !strcmp(argv[i], "-f")) { if (++i >= argc) return 2; file = argv[i]; }
        else if (!strcmp(argv[i], "--threads")) { if (next_long(argc, argv, &i, 1, INT_MAX, &v)) return 2; cfg.threads = (int)v; }
        else if (!strcmp(argv[i], "--rounds")) { if (next_long(argc, argv, &i, 1, INT_MAX, &v)) return 2; cfg.rounds = (int)v; }
        else if (!strcmp(argv[i], "--eta")) { if (next_long(argc, argv, &i, 1, 8, &v)) return 2; cfg.eta = (int)v; }
        else if (!strcmp(argv[i], "--k")) { if (next_long(argc, argv, &i, RELWE_DEFAULT_K, RELWE_DEFAULT_K, &v)) return 2; cfg.k = (int)v; }
        else if (!strcmp(argv[i], "--output-bits")) { if (next_long(argc, argv, &i, 256, 512, &v) || (v != 256 && v != 512)) return 2; cfg.output_bits = (int)v; }
        else if (!strcmp(argv[i], "--xof-len")) { if (next_size(argc, argv, &i, RELWE_XOF_MAX_OUTPUT, &xof_len)) return 2; xof_set = 1; }
        else if (!strcmp(argv[i], "--pure")) { /* Deprecated no-op: pure mode is always used. */ }
        else msg = argv[i];
    }
    if (xof_set) {
        if (xof_len > (SIZE_MAX - 1u) / 2u) return 2;
        uint8_t *out = (uint8_t *)malloc(xof_len ? xof_len : 1), *data = NULL; size_t len = 0;
        char *hex = (char *)malloc(xof_len * 2u + 1u);
        if (!out || !hex) return 1;
        if (file) { if (read_file_all(file, &data, &len)) { fprintf(stderr, "error: %s\n", strerror(errno)); return 1; } }
        else { if (!msg) msg = "The stone was rolled away."; data = (uint8_t *)(uintptr_t)msg; len = strlen(msg); }
        if (relwe_xof_config(out, xof_len, data, len, cfg)) { fprintf(stderr, "error: invalid XOF parameters\n"); return 2; }
        hex_encode(out, xof_len, hex); puts(hex);
        if (file) free(data);
        free(out); free(hex); return 0;
    }
    char hex[129]; if (file) { if (relwe_hash_file_hex(&cfg, file, hex)) { fprintf(stderr, "error: %s\n", strerror(errno)); return 1; } } else { if (!msg) msg = "The stone was rolled away."; relwe_hash_hex(&cfg, (const uint8_t *)msg, strlen(msg), hex); } puts(hex); return 0;
}
#endif
