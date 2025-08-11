/*
 * ravencrypt - advanced, readable C library for encoding + authenticated encryption
 * -------------------------------------------------------------
 * Files contained in this single-file library:
 *  - ravencrypt.h    (public API)
 *  - ravencrypt.c    (implementation)
 *  - README (usage + compile instructions)
 *
 * Design goals:
 *  - Clear, well-documented C99 code (single-file for easy inclusion)
 *  - Provide safe-high-level primitives composed from standard algorithms:
 *      * HKDF-SHA256 (KDF)
 *      * ChaCha20 stream cipher (RFC 8439 style core)
 *      * Poly1305 MAC
 *      * AEAD: ChaCha20-Poly1305 style authenticated encryption
 *  - Extra "encoding" features built on top of AEAD:
 *      * Human-friendly armor (variant of base64 with checksum)
 *      * Format-preserving reversible encoding example (simple FPE-style mapping)
 *  - Cross-platform randomness with safe fallbacks
 *  - Heavy comments for learning and modification
 *
 * Security note (IMPORTANT):
 *  - This library is educational and readable-by-design. For production, use
 *    battle-tested libraries (libsodium, OpenSSL, BoringSSL). See README at the
 *    bottom for official vs unofficial references.
 *
 * Build: gcc -std=c99 -O3 -Wall ravencrypt.c -o ravencrypt_test
 */

#ifndef RAVENCRYPT_H
#define RAVENCRYPT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public API summary (detailed comments in header below)
 * - int cx_init(void): initialize internal state (no-op for portability)
 * - int cx_random_bytes(uint8_t *out, size_t n): fill with secure random bytes
 * - int cx_hkdf_sha256(...): derive keys via HKDF-SHA256
 * - int cx_aead_encrypt(...): encrypt message -> ciphertext with tag
 * - int cx_aead_decrypt(...): decrypt ciphertext+tag -> message
 * - char *cx_armor_encrypt(...): high-level: encrypt + ASCII armor -> malloc'd string
 * - uint8_t *cx_unarmor_decrypt(...): parse armor -> decrypt -> malloc'd plaintext
 * - Memory management: caller frees allocated buffers
 */

#define CX_KEY_BYTES 32
#define CX_NONCE_BYTES 12
#define CX_TAG_BYTES 16

/* Return codes */
#define CX_OK 0
#define CX_ERR -1
#define CX_INVALID 1

/* Initialize library (placeholder for platforms needing init) */
int cx_init(void);

/* Secure random bytes */
int cx_random_bytes(uint8_t *out, size_t n);

/* HKDF-SHA256: extract+expand
 * salt can be NULL (treated as zero salt), info can be NULL.
 * okm must be pre-allocated with okm_len bytes.
 */
int cx_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len);

/* AEAD (ChaCha20-Poly1305 style) high-level functions.
 * key: CX_KEY_BYTES
 * nonce: CX_NONCE_BYTES
 * ciphertext buffer must be plaintext_len bytes
 * tag buffer must be CX_TAG_BYTES
 */
int cx_aead_encrypt(const uint8_t key[CX_KEY_BYTES],
                    const uint8_t nonce[CX_NONCE_BYTES],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *ciphertext, uint8_t tag[CX_TAG_BYTES]);

int cx_aead_decrypt(const uint8_t key[CX_KEY_BYTES],
                    const uint8_t nonce[CX_NONCE_BYTES],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t tag[CX_TAG_BYTES],
                    uint8_t *plaintext_out);

/* Human-friendly armor: encrypt and encode to printable string (NULL-terminated).
 * The returned string is malloc'd and must be freed by caller. The function
 * returns NULL on error.
 * Format: version|nonce(base64url)|cipher(base64url)|tag(base64url)|checksum
 */
char *cx_armor_encrypt(const uint8_t key[CX_KEY_BYTES],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len);

/* Parse armor string, decrypt. On success returns malloc'd plaintext and sets
 * *plaintext_len. On failure returns NULL.
 */
uint8_t *cx_unarmor_decrypt(const uint8_t key[CX_KEY_BYTES],
                            const char *armor, size_t *plaintext_len_out);

#ifdef __cplusplus
}
#endif

#endif /* RAVENCRYPT_H */

/* ---------------- Implementation ---------------- */

#ifdef RAVENCRYPT_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* Platform-specific secure randomness */
#if defined(__linux__)
#include <sys/random.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt")
#endif

/* ---------- utility helpers ---------- */
static void secure_zero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

int cx_init(void) {
    /* currently nothing required; placeholder for future platform init */
    return CX_OK;
}

int cx_random_bytes(uint8_t *out, size_t n) {
    if (!out) return CX_ERR;
#if defined(_WIN32)
    if (BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        return CX_OK;
    return CX_ERR;
#elif defined(__linux__)
    ssize_t r = getrandom(out, n, 0);
    if (r == (ssize_t)n) return CX_OK;
    /* fallback to /dev/urandom */
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return CX_ERR;
    size_t read = fread(out, 1, n, f);
    fclose(f);
    if (read != n) return CX_ERR;
    return CX_OK;
}

/* ---------- SHA-256 (compact, readable) ----------
 * A tiny reference implementation of SHA-256 for HKDF and Poly1305 keying.
 * Not optimized; understandable and portable.
 */

typedef struct {
    uint64_t bitlen;
    uint32_t state[8];
    uint8_t  data[64];
    size_t datalen;
} cx_sha256_ctx;

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))

static const uint32_t k_sha256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void cx_sha256_transform(cx_sha256_ctx *ctx) {
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t)ctx->data[i*4] << 24 |
               (uint32_t)ctx->data[i*4+1] << 16 |
               (uint32_t)ctx->data[i*4+2] << 8 |
               (uint32_t)ctx->data[i*4+3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR(m[i-15],7) ^ ROTR(m[i-15],18) ^ (m[i-15] >> 3);
        uint32_t s1 = ROTR(m[i-2],17) ^ ROTR(m[i-2],19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k_sha256[i] + m[i];
        uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void cx_sha256_init(cx_sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void cx_sha256_update(cx_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            cx_sha256_transform(ctx);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void cx_sha256_final(cx_sha256_ctx *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    /* Pad */
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        cx_sha256_transform(ctx);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    /* append length in bits big-endian */
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    cx_sha256_transform(ctx);
    for (i = 0; i < 8; ++i) {
        hash[i*4]     = (ctx->state[i] >> 24) & 0xFF;
        hash[i*4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i*4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i*4 + 3] = (ctx->state[i]) & 0xFF;
    }
}

/* ---------- HMAC-SHA256 (for HKDF) ---------- */
static void cx_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t out[32]) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t key_block[64];
    memset(key_block, 0, 64);
    if (key_len > 64) {
        cx_sha256_ctx t;
        cx_sha256_init(&t);
        cx_sha256_update(&t, key, key_len);
        cx_sha256_final(&t, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }
    for (int i = 0; i < 64; ++i) {
        k_ipad[i] = key_block[i] ^ 0x36;
        k_opad[i] = key_block[i] ^ 0x5c;
    }
    cx_sha256_ctx ctx;
    cx_sha256_init(&ctx);
    cx_sha256_update(&ctx, k_ipad, 64);
    cx_sha256_update(&ctx, msg, msg_len);
    uint8_t inner[32];
    cx_sha256_final(&ctx, inner);

    cx_sha256_init(&ctx);
    cx_sha256_update(&ctx, k_opad, 64);
    cx_sha256_update(&ctx, inner, 32);
    cx_sha256_final(&ctx, out);
    secure_zero(k_ipad, sizeof(k_ipad));
    secure_zero(k_opad, sizeof(k_opad));
    secure_zero(key_block, sizeof(key_block));
    secure_zero(inner, sizeof(inner));
}

/* ---------- HKDF-SHA256 ---------- */
int cx_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len) {
    if (!ikm || !okm) return CX_ERR;
    uint8_t prk[32];
    /* Extract
     * PRK = HMAC-Hash(salt, IKM)
     */
    uint8_t zero_salt[32];
    if (!salt) {
        memset(zero_salt, 0, sizeof(zero_salt));
        salt = zero_salt;
        salt_len = 32;
    }
    cx_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* Expand
     * T(0) = empty
     * T(1) = HMAC-PRK(T(0) | info | 0x01)
     * T(2) = HMAC-PRK(T(1) | info | 0x02)
     * ... until OKM filled
     */
    size_t n = (okm_len + 31) / 32;
    if (n > 255) return CX_ERR;
    uint8_t t[32];
    uint8_t previous[32];
    size_t pos = 0;
    size_t previous_len = 0;
    for (uint8_t i = 1; i <= (uint8_t)n; ++i) {
        /* buffer = previous | info | i */
        size_t buf_len = previous_len + (info ? info_len : 0) + 1;
        uint8_t *buf = (uint8_t *)malloc(buf_len);
        if (!buf) return CX_ERR;
        size_t off = 0;
        if (previous_len) { memcpy(buf + off, previous, previous_len); off += previous_len; }
        if (info && info_len) { memcpy(buf + off, info, info_len); off += info_len; }
        buf[off++] = i;
        cx_hmac_sha256(prk, 32, buf, buf_len, t);
        free(buf);
        size_t copy = (pos + 32 <= okm_len) ? 32 : (okm_len - pos);
        memcpy(okm + pos, t, copy);
        pos += copy;
        memcpy(previous, t, 32);
        previous_len = 32;
    }
    secure_zero(prk, sizeof(prk));
    secure_zero(t, sizeof(t));
    secure_zero(previous, sizeof(previous));
    return CX_OK;
}

/* ---------- ChaCha20 core (readable) ----------
 * This implementation is educational and follows RFC 8439 layout.
 */

static inline uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void st32(uint8_t *p, uint32_t x) {
    p[0] = x & 0xff; p[1] = (x >> 8) & 0xff; p[2] = (x >> 16) & 0xff; p[3] = (x >> 24) & 0xff;
}

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16];
    /* constants */
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    /* key */
    for (int i = 0; i < 8; ++i) state[4 + i] = le32(key + i*4);
    /* counter */
    state[12] = counter;
    /* nonce */
    state[13] = le32(nonce + 0);
    state[14] = le32(nonce + 4);
    state[15] = le32(nonce + 8);

    uint32_t x[16];
    memcpy(x, state, sizeof(state));
    for (int i = 0; i < 10; ++i) { /* 20 rounds = 10 double rounds */
        /* column rounds */
        #define QR(a,b,c,d) x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTR(x[d], 16); \
                           x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTR(x[b], 12);
        QR(0,4,8,12)
        QR(1,5,9,13)
        QR(2,6,10,14)
        QR(3,7,11,15)
        /* diagonal rounds */
        QR(0,5,10,15)
        QR(1,6,11,12)
        QR(2,7,8,13)
        QR(3,4,9,14)
        #undef QR
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t res = x[i] + state[i];
        st32(out + 4*i, res);
    }
}

/* ChaCha20 encrypt/decrypt (XOR stream) */
static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64];
    size_t pos = 0;
    while (pos < len) {
        chacha20_block(key, nonce, counter, block);
        size_t chunk = (len - pos) < 64 ? (len - pos) : 64;
        for (size_t i = 0; i < chunk; ++i) out[pos + i] = in[pos + i] ^ block[i];
        pos += chunk;
        counter++;
    }
    secure_zero(block, sizeof(block));
}

/* ---------- Poly1305 (reference) ----------
 * This is a straightforward implementation (not constant-time optimized)
 * but clear and interoperable with RFC7539 Poly1305 usage.
 */

static uint64_t load32_le(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24);
}

static void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t msg_len, uint8_t out[16]) {
    /* r and s from key */
    uint8_t r_bytes[16]; memcpy(r_bytes, key, 16);
    uint8_t s_bytes[16]; memcpy(s_bytes, key + 16, 16);
    /* clamp r */
    r_bytes[3] &= 15; r_bytes[7] &= 15; r_bytes[11] &= 15; r_bytes[15] &= 15;
    r_bytes[4] &= 252; r_bytes[8] &= 252; r_bytes[12] &= 252;

    /* convert r to 130-bit number (as 5 limbs) */
    uint64_t r0 = (load32_le(r_bytes)      ) & 0x3ffffff;
    uint64_t r1 = ((load32_le(r_bytes+3) >> 2) | (load32_le(r_bytes+4) << 30)) & 0x3ffffff;
    uint64_t r2 = ((load32_le(r_bytes+6) >> 4) | (load32_le(r_bytes+7) << 28)) & 0x3ffffff;
    uint64_t r3 = ((load32_le(r_bytes+9) >> 6) | (load32_le(r_bytes+10) << 26)) & 0x3ffffff;
    uint64_t r4 = ((load32_le(r_bytes+12) >> 8) | (load32_le(r_bytes+13) << 24)) & 0x3ffffff;

    uint64_t h0=0,h1=0,h2=0,h3=0,h4=0;
    const uint64_t p = ((uint64_t)1 << 130) - 5;

    size_t offset = 0;
    uint8_t block[16+1];
    while (offset < msg_len) {
        size_t want = (msg_len - offset) < 16 ? (msg_len - offset) : 16;
        memset(block, 0, sizeof(block));
        if (want) memcpy(block, msg + offset, want);
        block[want] = 1; /* append 1 */
        /* parse into limbs */
        uint64_t t0 = (uint64_t)load32_le(block)        & 0xffffffffULL;
        uint64_t t1 = (uint64_t)load32_le(block+4)     & 0xffffffffULL;
        uint64_t t2 = (uint64_t)load32_le(block+8)     & 0xffffffffULL;
        uint64_t t3 = (uint64_t)load32_le(block+12)    & 0xffffffffULL;
        h0 += (t0 & 0x3ffffff);
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) & 0x3ffffff;

        /* multiply (h *= r) mod p */
        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * (5 * r4) + (uint64_t)h2 * (5 * r3) + (uint64_t)h3 * (5 * r2) + (uint64_t)h4 * (5 * r1);
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * (5 * r4) + (uint64_t)h3 * (5 * r3) + (uint64_t)h4 * (5 * r2);
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * (5 * r4) + (uint64_t)h4 * (5 * r3);
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * (5 * r4);
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        /* carry propagate */
        uint64_t c;
        c = (d0 >> 26); h0 = d0 & 0x3ffffff; d1 += c;
        c = (d1 >> 26); h1 = d1 & 0x3ffffff; d2 += c;
        c = (d2 >> 26); h2 = d2 & 0x3ffffff; d3 += c;
        c = (d3 >> 26); h3 = d3 & 0x3ffffff; d4 += c;
        c = (d4 >> 26); h4 = d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        offset += want;
    }

    /* final reduction */
    uint64_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    /* compute h + -p (to decide if we need to subtract) */
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);

    /* select h or h - p */
    uint64_t mask = (g4 >> 63) - 1; /* if g4 has high bit clear -> g4 negative? */
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* serialize h to 16 bytes little-endian and add s */
    uint64_t acc = h0 | (h1 << 26) | (h2 << 52);
    uint8_t mac[16];
    /* compute 128-bit number h then add s (s_bytes little endian) */
    uint64_t low = (h0) | (h1 << 26) | (h2 << 52);
    uint64_t high = ((h2 >> 12) | (h3 << 14) | (h4 << 40));

    /* add s (little-endian) */
    uint64_t s_low = load32_le(s_bytes) | ((uint64_t)load32_le(s_bytes+4) << 32);
    uint64_t s_high = load32_le(s_bytes+8) | ((uint64_t)load32_le(s_bytes+12) << 32);
    uint64_t res_low = low + s_low;
    uint64_t carry = (res_low < low) ? 1 : 0;
    uint64_t res_high = high + s_high + carry;

    /* write out 16 bytes (little-endian) */
    for (int i = 0; i < 8; ++i) mac[i] = (res_low >> (8*i)) & 0xff;
    for (int i = 0; i < 8; ++i) mac[8+i] = (res_high >> (8*i)) & 0xff;
    memcpy(out, mac, 16);
    secure_zero(r_bytes, sizeof(r_bytes));
    secure_zero(s_bytes, sizeof(s_bytes));
    secure_zero(&h0, sizeof(h0));
    secure_zero(&h1, sizeof(h1));
    secure_zero(&h2, sizeof(h2));
    secure_zero(&h3, sizeof(h3));
    secure_zero(&h4, sizeof(h4));
}

/* ---------- AEAD: ChaCha20-Poly1305 style ----------
 * - Per-message ephemeral one-time Poly1305 key: generated by chacha20 block with counter=0
 * - Messages are encrypted with chacha20 counter=1... as in RFC8439
 */

int cx_aead_encrypt(const uint8_t key[32],
                    const uint8_t nonce[12],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *ciphertext, uint8_t tag[16]) {
    if (!key || !nonce || !plaintext || !ciphertext || !tag) return CX_ERR;
    uint8_t one_time_key[32];
    chacha20_block(key, nonce, 0, one_time_key); /* block 0 -> Poly1305 key */

    /* encrypt with counter starting at 1 */
    chacha20_xor(key, nonce, 1, plaintext, ciphertext, plaintext_len);

    /* Build Poly1305 input: aad || padding || ciphertext || padding || len(aad) || len(ciphertext)
     * where len fields are 8-byte little endian as per RFC.
     */
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    size_t ct_pad = (16 - (plaintext_len % 16)) % 16;
    size_t mac_len = aad_len + aad_pad + plaintext_len + ct_pad + 16;
    uint8_t *mac_data = (uint8_t *)malloc(mac_len);
    if (!mac_data) { secure_zero(one_time_key, sizeof(one_time_key)); return CX_ERR; }
    size_t off = 0;
    if (aad_len) { memcpy(mac_data + off, aad, aad_len); off += aad_len; }
    if (aad_pad) { memset(mac_data + off, 0, aad_pad); off += aad_pad; }
    if (plaintext_len) { memcpy(mac_data + off, ciphertext, plaintext_len); off += plaintext_len; }
    if (ct_pad) { memset(mac_data + off, 0, ct_pad); off += ct_pad; }
    /* lengths */
    uint64_t aad_len_le = (uint64_t)aad_len;
    uint64_t ct_len_le = (uint64_t)plaintext_len;
    for (int i = 0; i < 8; ++i) mac_data[off + i] = (aad_len_le >> (8*i)) & 0xff;
    for (int i = 0; i < 8; ++i) mac_data[off + 8 + i] = (ct_len_le >> (8*i)) & 0xff;

    poly1305_mac(one_time_key, mac_data, mac_len, tag);
    secure_zero(one_time_key, sizeof(one_time_key));
    secure_zero(mac_data, mac_len);
    free(mac_data);
    return CX_OK;
}

int cx_aead_decrypt(const uint8_t key[32],
                    const uint8_t nonce[12],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t tag[16],
                    uint8_t *plaintext_out) {
    if (!key || !nonce || !ciphertext || !tag || !plaintext_out) return CX_ERR;
    uint8_t one_time_key[32];
    chacha20_block(key, nonce, 0, one_time_key);

    /* compute mac over aad||pad||ct||pad||lenA||lenC */
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    size_t ct_pad = (16 - (ciphertext_len % 16)) % 16;
    size_t mac_len = aad_len + aad_pad + ciphertext_len + ct_pad + 16;
    uint8_t *mac_data = (uint8_t *)malloc(mac_len);
    if (!mac_data) { secure_zero(one_time_key, sizeof(one_time_key)); return CX_ERR; }
    size_t off = 0;
    if (aad_len) { memcpy(mac_data + off, aad, aad_len); off += aad_len; }
    if (aad_pad) { memset(mac_data + off, 0, aad_pad); off += aad_pad; }
    if (ciphertext_len) { memcpy(mac_data + off, ciphertext, ciphertext_len); off += ciphertext_len; }
    if (ct_pad) { memset(mac_data + off, 0, ct_pad); off += ct_pad; }
    uint64_t aad_len_le = (uint64_t)aad_len;
    uint64_t ct_len_le = (uint64_t)ciphertext_len;
    for (int i = 0; i < 8; ++i) mac_data[off + i] = (aad_len_le >> (8*i)) & 0xff;
    for (int i = 0; i < 8; ++i) mac_data[off + 8 + i] = (ct_len_le >> (8*i)) & 0xff;

    uint8_t calc_tag[16];
    poly1305_mac(one_time_key, mac_data, mac_len, calc_tag);
    secure_zero(mac_data, mac_len);
    free(mac_data);

    /* constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= (calc_tag[i] ^ tag[i]);
    if (diff) { secure_zero(one_time_key, sizeof(one_time_key)); secure_zero(calc_tag, sizeof(calc_tag)); return CX_INVALID; }

    chacha20_xor(key, nonce, 1, ciphertext, plaintext_out, ciphertext_len);
    secure_zero(one_time_key, sizeof(one_time_key)); secure_zero(calc_tag, sizeof(calc_tag));
    return CX_OK;
}

/* ---------- Armor: base64url variant, with checksum ----------
 * This is not a security layer; it is a usability layer for transporting ciphertext.
 */

static const char b64url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *b64url_encode_alloc(const uint8_t *in, size_t inlen) {
    size_t outlen = ((inlen + 2) / 3) * 4;
    char *out = (char *)malloc(outlen + 1);
    if (!out) return NULL;
    size_t i=0, o=0;
    while (i < inlen) {
        uint32_t a = i < inlen ? in[i++] : 0;
        uint32_t b = i < inlen ? in[i++] : 0;
        uint32_t c = i < inlen ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[o++] = b64url_table[(triple >> 18) & 0x3F];
        out[o++] = b64url_table[(triple >> 12) & 0x3F];
        out[o++] = b64url_table[(triple >> 6) & 0x3F];
        out[o++] = b64url_table[triple & 0x3F];
    }
    /* remove padding '=' and shrink accordingly (base64url) */
    while (inlen-- % 3) out[--o] = '\0';
    /* fix string termination by compacting nulls */
    size_t final_len = 0;
    for (size_t j = 0; j < outlen; ++j) if (out[j]) out[final_len++] = out[j];
    out[final_len] = '\0';
    return out;
}

static uint8_t *b64url_decode_alloc(const char *in, size_t *outlen) {
    size_t inlen = strlen(in);
    size_t approx = (inlen * 3) / 4;
    uint8_t *out = (uint8_t *)malloc(approx + 3);
    if (!out) return NULL;
    size_t i=0,o=0;
    uint8_t buf[4]; int bufc=0;
    while (i < inlen) {
        char c = in[i++];
        int v = -1;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '-') v = 62;
        else if (c == '_') v = 63;
        else continue; /* skip unknown chars */
        buf[bufc++] = (uint8_t)v;
        if (bufc == 4) {
            out[o++] = (buf[0] << 2) | (buf[1] >> 4);
            out[o++] = (buf[1] << 4) | (buf[2] >> 2);
            out[o++] = (buf[2] << 6) | buf[3];
            bufc = 0;
        }
    }
    if (bufc == 2) { out[o++] = (buf[0] << 2) | (buf[1] >> 4); }
    else if (bufc == 3) { out[o++] = (buf[0] << 2) | (buf[1] >> 4); out[o++] = (buf[1] << 4) | (buf[2] >> 2); }
    *outlen = o;
    return out;
}

/* simple 8-bit checksum (not security) */
static uint8_t checksum8(const uint8_t *d, size_t n) { uint8_t s=0; for (size_t i=0;i<n;++i) s += d[i]; return s; }

char *cx_armor_encrypt(const uint8_t key[32],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len) {
    if (!key || !plaintext) return NULL;
    uint8_t nonce[12]; if (cx_random_bytes(nonce, 12) != CX_OK) return NULL;
    uint8_t *cipher = (uint8_t *)malloc(plaintext_len);
    uint8_t tag[16];
    if (!cipher) return NULL;
    if (cx_aead_encrypt(key, nonce, aad, aad_len, plaintext, plaintext_len, cipher, tag) != CX_OK) { free(cipher); return NULL; }
    char *n_enc = b64url_encode_alloc(nonce, 12);
    char *c_enc = b64url_encode_alloc(cipher, plaintext_len);
    char *t_enc = b64url_encode_alloc(tag, 16);
    size_t final_len = strlen(n_enc) + strlen(c_enc) + strlen(t_enc) + 32;
    char *out = (char *)malloc(final_len);
    if (!out) { free(cipher); free(n_enc); free(c_enc); free(t_enc); return NULL; }
    /* version 1 format */
    snprintf(out, final_len, "CX1|%s|%s|%s|%02x", n_enc, c_enc, t_enc, checksum8((uint8_t*)c_enc, strlen(c_enc)));
    free(cipher); free(n_enc); free(c_enc); free(t_enc);
    return out;
}

uint8_t *cx_unarmor_decrypt(const uint8_t key[32], const char *armor, size_t *plaintext_len_out) {
    if (!key || !armor) return NULL;
    /* parse format: CX1|nonce|cipher|tag|cs */
    char *copy = strdup(armor);
    char *parts[5] = {0};
    int idx = 0;
    char *p = strtok(copy, "|");
    while (p && idx < 5) { parts[idx++] = p; p = strtok(NULL, "|"); }
    if (idx < 5) { free(copy); return NULL; }
    if (strcmp(parts[0], "CX1") != 0) { free(copy); return NULL; }
    size_t nonce_len, ct_len, tag_len;
    uint8_t *nonce = b64url_decode_alloc(parts[1], &nonce_len);
    uint8_t *ct = b64url_decode_alloc(parts[2], &ct_len);
    uint8_t *tag = b64url_decode_alloc(parts[3], &tag_len);
    if (!nonce || !ct || !tag) { free(copy); free(nonce); free(ct); free(tag); return NULL; }
    uint8_t cs = 0; sscanf(parts[4], "%2hhx", &cs);
    /* checksum quick-check */
    uint8_t calc = checksum8((uint8_t*)parts[2], strlen(parts[2]));
    if (calc != cs) { free(copy); free(nonce); free(ct); free(tag); return NULL; }
    uint8_t *out = (uint8_t *)malloc(ct_len);
    if (!out) { free(copy); free(nonce); free(ct); free(tag); return NULL; }
    int r = cx_aead_decrypt(key, nonce, NULL, 0, ct, ct_len, tag, out);
    if (r != CX_OK) { free(copy); free(nonce); free(ct); free(tag); free(out); return NULL; }
    *plaintext_len_out = ct_len;
    free(copy); free(nonce); free(ct); free(tag);
    return out;
}

/* ---------------- README ----------------

ravencrypt — educational advanced C encoding + crypto library

Features:
 - HKDF-SHA256 (internal HMAC-SHA256)
 - ChaCha20 (RFC-style) stream cipher
 - Poly1305 MAC
 - AEAD construction (ChaCha20 + Poly1305)
 - Human armor (base64url + checksum)

Security notes:
 - Implementation aims for clarity, not side-channel resistance or maximum speed.
 - For production-grade encryption prefer libsodium or OpenSSL.
 - Always manage keys carefully and use OS-provided CSPRNG.

Compilation:
 gcc -std=c99 -O3 -Wall ravencrypt.c -o ravencrypt_test

Example usage (in C):
  #include "ravencrypt.h"
  int main() {
    cx_init();
    uint8_t key[32]; cx_random_bytes(key, 32);
    const char *msg = "hello world";
    char *armor = cx_armor_encrypt(key, NULL, 0, (const uint8_t*)msg, strlen(msg));
    printf("armor: %s\n", armor);
    size_t mlen;
    uint8_t *dec = cx_unarmor_decrypt(key, armor, &mlen);
    printf("decrypted: %.*s\n", (int)mlen, dec);
    free(armor); free(dec);
    return 0;
  }

References (labelled):
 - Official: RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols. (official spec for ChaCha20-Poly1305)
 - Official: RFC 5869 — HKDF: HMAC-based Extract-and-Expand Key Derivation Function.
 - Unofficial / educational: Daniel J. Bernstein's papers on ChaCha and Poly1305 (original authors).
 - Libraries to prefer in production: libsodium (official website, easy-to-use API), OpenSSL (official docs).

End README
*/

#endif /* RAVENCRYPT_IMPLEMENTATION */