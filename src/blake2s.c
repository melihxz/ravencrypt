// src/blake2s.c
#include "ravencrypt.h"
#include <string.h>
#include <stdint.h>

/*
 * Minimal BLAKE2s implementation
 * RFC 7693 reference-compatible
 */

#define ROTR32(x, y) (((x) >> (y)) ^ ((x) << (32 - (y))))
#define B2S_IV0 0x6A09E667UL
#define B2S_IV1 0xBB67AE85UL
#define B2S_IV2 0x3C6EF372UL
#define B2S_IV3 0xA54FF53AUL
#define B2S_IV4 0x510E527FUL
#define B2S_IV5 0x9B05688CUL
#define B2S_IV6 0x1F83D9ABUL
#define B2S_IV7 0x5BE0CD19UL

static const uint8_t sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
};

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[64];
    size_t   buflen;
    size_t   outlen;
} blake2s_state;

static void blake2s_set_lastnode(blake2s_state *S) { (void)S; }
static void blake2s_increment_counter(blake2s_state *S, uint32_t inc) {
    S->t[0] += inc;
    if (S->t[0] < inc) S->t[1]++;
}

static void blake2s_init0(blake2s_state *S) {
    S->h[0] = B2S_IV0;
    S->h[1] = B2S_IV1;
    S->h[2] = B2S_IV2;
    S->h[3] = B2S_IV3;
    S->h[4] = B2S_IV4;
    S->h[5] = B2S_IV5;
    S->h[6] = B2S_IV6;
    S->h[7] = B2S_IV7;
}

static void blake2s_init(blake2s_state *S, size_t outlen) {
    blake2s_init0(S);
    S->outlen = outlen;
    S->h[0] ^= 0x01010000 ^ (uint32_t)outlen;
    S->t[0] = S->t[1] = S->f[0] = S->f[1] = 0;
    S->buflen = 0;
}

static void blake2s_compress(blake2s_state *S, const uint8_t block[64]) {
    uint32_t m[16];
    uint32_t v[16];
    size_t i, r;

    for (i = 0; i < 16; ++i)
        m[i] = ((uint32_t)block[i * 4 + 0] << 0) |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);

    for (i = 0; i < 8; ++i) v[i] = S->h[i];
    v[8]  = B2S_IV0;
    v[9]  = B2S_IV1;
    v[10] = B2S_IV2;
    v[11] = B2S_IV3;
    v[12] = S->t[0] ^ B2S_IV4;
    v[13] = S->t[1] ^ B2S_IV5;
    v[14] = S->f[0] ^ B2S_IV6;
    v[15] = S->f[1] ^ B2S_IV7;

#define G(r,i,a,b,c,d)                          \
    do {                                        \
        a = a + b + m[sigma[r][2*i+0]];         \
        d = ROTR32(d ^ a, 16);                  \
        c = c + d;                              \
        b = ROTR32(b ^ c, 12);                  \
        a = a + b + m[sigma[r][2*i+1]];         \
        d = ROTR32(d ^ a, 8);                   \
        c = c + d;                              \
        b = ROTR32(b ^ c, 7);                   \
    } while(0)

#define ROUND(r)                                \
    do {                                        \
        G(r,0,v[ 0],v[ 4],v[ 8],v[12]);         \
        G(r,1,v[ 1],v[ 5],v[ 9],v[13]);         \
        G(r,2,v[ 2],v[ 6],v[10],v[14]);         \
        G(r,3,v[ 3],v[ 7],v[11],v[15]);         \
        G(r,4,v[ 0],v[ 5],v[10],v[15]);         \
        G(r,5,v[ 1],v[ 6],v[11],v[12]);         \
        G(r,6,v[ 2],v[ 7],v[ 8],v[13]);         \
        G(r,7,v[ 3],v[ 4],v[ 9],v[14]);         \
    } while(0)

    for (r = 0; r < 10; ++r) {
        ROUND(r);
    }

    for (i = 0; i < 8; ++i)
        S->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2s_update(blake2s_state *S, const void *pin, size_t inlen) {
    const uint8_t *in = (const uint8_t *)pin;
    while (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = 64 - left;
        if (inlen > fill) {
            memcpy(S->buf + left, in, fill);
            S->buflen += fill;
            blake2s_increment_counter(S, 64);
            blake2s_compress(S, S->buf);
            S->buflen = 0;
            in += fill; inlen -= fill;
        } else {
            memcpy(S->buf + left, in, inlen);
            S->buflen += inlen;
            in += inlen; inlen -= inlen;
        }
    }
}

static void blake2s_final(blake2s_state *S, void *out, size_t outlen) {
    size_t i;
    blake2s_increment_counter(S, (uint32_t)S->buflen);
    S->f[0] = (uint32_t)-1;
    memset(S->buf + S->buflen, 0, 64 - S->buflen);
    blake2s_compress(S, S->buf);
    for (i = 0; i < outlen; ++i)
        ((uint8_t *)out)[i] = (S->h[i >> 2] >> (8 * (i & 3))) & 0xFF;
}

int rc_blake2s_hash(const uint8_t *data, size_t len,
                    uint8_t *out, size_t outlen) {
    if (!out || outlen == 0 || outlen > 32) return -1;
    blake2s_state S;
    blake2s_init(&S, outlen);
    blake2s_update(&S, data, len);
    blake2s_final(&S, out, outlen);
    return 0;
}
