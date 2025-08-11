// blake2s.c
// Minimal Blake2s implementation
// Source: https://blake2.net/blake2s-ref.c

#include "ravencrypt.h"
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[64];
    size_t buflen;
    size_t outlen;
} rc_blake2s_state;

static const uint8_t rc_blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 }
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))

static void rc_blake2s_g(uint32_t v[16], int a, int b, int c, int d, uint32_t x, uint32_t y) {
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 7);
}

static void rc_blake2s_compress(rc_blake2s_state *S, const uint8_t block[64]) {
    uint32_t v[16];
    uint32_t m[16];
    int i;

    for (i = 0; i < 8; i++) v[i] = S->h[i];
    // Blake2s IV sabitleri
    uint32_t iv[8] = {
        0x6A09E667, 0xBB67AE85,
        0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C,
        0x1F83D9AB, 0x5BE0CD19
    };
    for (i = 0; i < 8; i++) v[i + 8] = iv[i];

    v[12] ^= (uint32_t)S->t[0];
    v[13] ^= (uint32_t)S->t[1];
    v[14] ^= (uint32_t)S->f[0];
    v[15] ^= (uint32_t)S->f[1];

    for (i = 0; i < 16; i++) {
        m[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) | ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    }

    for (i = 0; i < 10; i++) {
        const uint8_t *s = rc_blake2s_sigma[i];
        rc_blake2s_g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        rc_blake2s_g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        rc_blake2s_g(v, 2, 6,10, 14, m[s[4]], m[s[5]]);
        rc_blake2s_g(v, 3, 7,11, 15, m[s[6]], m[s[7]]);
        rc_blake2s_g(v, 0, 5,10, 15, m[s[8]], m[s[9]]);
        rc_blake2s_g(v, 1, 6,11, 12, m[s[10]], m[s[11]]);
        rc_blake2s_g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        rc_blake2s_g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (i = 0; i < 8; i++) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

int rc_blake2s_init(rc_blake2s_state *S, size_t outlen) {
    if (!S || outlen == 0 || outlen > 32) return -1;

    const uint32_t iv[8] = {
        0x6A09E667, 0xBB67AE85,
        0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C,
        0x1F83D9AB, 0x5BE0CD19
    };

    memset(S, 0, sizeof(*S));
    memcpy(S->h, iv, sizeof(iv));
    S->outlen = outlen;
    S->t[0] = 0;
    S->t[1] = 0;
    S->f[0] = 0;
    S->f[1] = 0;
    S->buflen = 0;

    S->h[0] ^= 0x01010000 ^ (uint32_t)outlen;

    return 0;
}

int rc_blake2s_update(rc_blake2s_state *S, const void *in, size_t inlen) {
    const uint8_t *input = (const uint8_t *)in;
    size_t left = S->buflen;
    size_t fill = 64 - left;

    if (inlen == 0) return 0;

    size_t offset = 0;

    if (left && inlen >= fill) {
        memcpy(S->buf + left, input, fill);
        S->t[0] += 64;
        if (S->t[0] < 64) S->t[1]++;
        rc_blake2s_compress(S, S->buf);
        offset += fill;
        left = 0;
    }

    while (offset + 64 <= inlen) {
        S->t[0] += 64;
        if (S->t[0] < 64) S->t[1]++;
        rc_blake2s_compress(S, input + offset);
        offset += 64;
    }

    if (offset < inlen) {
        memcpy(S->buf, input + offset, inlen - offset);
        left = inlen - offset;
    }

    S->buflen = left;
    return 0;
}

int rc_blake2s_final(rc_blake2s_state *S, uint8_t *out) {
    size_t i;
    if (!S || !out) return -1;

    if (S->f[0] != 0) return -1; // already finalized

    S->t[0] += (uint32_t)S->buflen;
    if (S->t[0] < (uint32_t)S->buflen) S->t[1]++;
    S->f[0] = (uint32_t)-1;

    // padding rest buffer with zeros
    memset(S->buf + S->buflen, 0, 64 - S->buflen);
    rc_blake2s_compress(S, S->buf);

    for (i = 0; i < S->outlen; i++) {
        out[i] = (uint8_t)(S->h[i >> 2] >> (8 * (i & 3)));
    }

    return 0;
}

void rc_blake2s(const uint8_t *input, size_t inlen, uint8_t *out, size_t outlen) {
    rc_blake2s_state S;
    rc_blake2s_init(&S, outlen);
    rc_blake2s_update(&S, input, inlen);
    rc_blake2s_final(&S, out);
}
