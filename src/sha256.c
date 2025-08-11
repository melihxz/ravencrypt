/* Compact SHA-256 and HMAC-SHA256 implementation (readable, test-covered) */
#include "ravencrypt.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Implementation details identical to the prototype but separated */
/* ... For brevity in this presentation, the full SHA256/HMAC code is provided
 * here verbatim from a clear reference implementation (as in prototype).
 * When extracting, put the full sha256/hmac functions into this file. */

/* We'll include a minimal working implementation: */

typedef struct { uint64_t bitlen; uint32_t state[8]; uint8_t data[64]; size_t datalen; } rc_sha256_ctx;
#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static const uint32_t rc_k[64] = { /* same constants as standard */
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

static void rc_sha256_transform(rc_sha256_ctx *ctx) {
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t)ctx->data[i*4] << 24 | (uint32_t)ctx->data[i*4+1] << 16 | (uint32_t)ctx->data[i*4+2] << 8 | (uint32_t)ctx->data[i*4+3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR(m[i-15],7) ^ ROTR(m[i-15],18) ^ (m[i-15] >> 3);
        uint32_t s1 = ROTR(m[i-2],17) ^ ROTR(m[i-2],19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }
    uint32_t a=ctx->state[0], b=ctx->state[1], c=ctx->state[2], d=ctx->state[3];
    uint32_t e=ctx->state[4], f=ctx->state[5], g=ctx->state[6], h=ctx->state[7];
    for (int i=0;i<64;++i) {
        uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + rc_k[i] + m[i];
        uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h=g; g=f; f=e; e=d + temp1; d=c; c=b; b=a; a=temp1 + temp2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void rc_sha256_init(rc_sha256_ctx *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85; ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c; ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void rc_sha256_update(rc_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i=0;i<len;++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) { rc_sha256_transform(ctx); ctx->bitlen += 512; ctx->datalen = 0; }
    }
}

static void rc_sha256_final(rc_sha256_ctx *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    if (ctx->datalen < 56) { ctx->data[i++] = 0x80; while (i < 56) ctx->data[i++] = 0x00; }
    else { ctx->data[i++] = 0x80; while (i < 64) ctx->data[i++] = 0x00; rc_sha256_transform(ctx); memset(ctx->data,0,56); }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen; ctx->data[62] = ctx->bitlen >> 8; ctx->data[61] = ctx->bitlen >> 16; ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32; ctx->data[58] = ctx->bitlen >> 40; ctx->data[57] = ctx->bitlen >> 48; ctx->data[56] = ctx->bitlen >> 56;
    rc_sha256_transform(ctx);
    for (i=0;i<8;++i) { hash[i*4] = (ctx->state[i] >> 24) & 0xFF; hash[i*4+1] = (ctx->state[i] >> 16) & 0xFF; hash[i*4+2] = (ctx->state[i] >> 8) & 0xFF; hash[i*4+3] = ctx->state[i] & 0xFF; }
}

static void rc_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    uint8_t key_block[64]; memset(key_block,0,64);
    if (key_len > 64) { rc_sha256_ctx t; rc_sha256_init(&t); rc_sha256_update(&t,key,key_len); rc_sha256_final(&t,key_block); }
    else memcpy(key_block,key,key_len);
    uint8_t k_ipad[64], k_opad[64];
    for (int i=0;i<64;++i) { k_ipad[i] = key_block[i] ^ 0x36; k_opad[i] = key_block[i] ^ 0x5c; }
    rc_sha256_ctx ctx; rc_sha256_init(&ctx); rc_sha256_update(&ctx,k_ipad,64); rc_sha256_update(&ctx,msg,msg_len); uint8_t inner[32]; rc_sha256_final(&ctx, inner);
    rc_sha256_init(&ctx); rc_sha256_update(&ctx,k_opad,64); rc_sha256_update(&ctx,inner,32); rc_sha256_final(&ctx,out);
    rc_secure_zero(key_block,64); rc_secure_zero(k_ipad,64); rc_secure_zero(k_opad,64); rc_secure_zero(inner,32);
}

/* expose HMAC for HKDF module */
void rc_internal_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    rc_hmac_sha256(key,key_len,msg,msg_len,out);
}