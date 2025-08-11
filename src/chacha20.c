#include "ravencrypt.h"
#include <string.h>
#include <stdint.h>

static inline uint32_t rc_le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static inline void rc_st32(uint8_t *p, uint32_t x) { p[0]=x & 0xff; p[1]=(x>>8)&0xff; p[2]=(x>>16)&0xff; p[3]=(x>>24)&0xff; }

static void rc_chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16];
    state[0]=0x61707865; state[1]=0x3320646e; state[2]=0x79622d32; state[3]=0x6b206574;
    for (int i=0;i<8;++i) state[4+i]=rc_le32(key + i*4);
    state[12] = counter;
    state[13] = rc_le32(nonce + 0); state[14]=rc_le32(nonce+4); state[15]=rc_le32(nonce+8);
    uint32_t x[16]; memcpy(x,state,sizeof(state));
    #define QR(a,b,c,d) x[a]+=x[b]; x[d]^=x[a]; x[d]=((x[d]>>16)|(x[d]<<16)); x[c]+=x[d]; x[b]^=x[c]; x[b]=((x[b]>>12)|(x[b]<<20));
    for (int i=0;i<10;++i) {
        QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
        QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
    }
    #undef QR
    for (int i=0;i<16;++i) { uint32_t res = x[i] + state[i]; rc_st32(out + 4*i, res); }
}

void rc_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64]; size_t pos=0;
    while (pos < len) {
        rc_chacha20_block(key, nonce, counter, block);
        size_t chunk = (len - pos) < 64 ? (len - pos) : 64;
        for (size_t i=0;i<chunk;++i) out[pos + i] = in[pos + i] ^ block[i];
        pos += chunk; counter++;
    }
    rc_secure_zero(block, sizeof(block));
}

/* expose block generator for Poly1305 key */
void rc_chacha20_block_for_poly(const uint8_t key[32], const uint8_t nonce[12], uint8_t out[64]) { rc_chacha20_block(key, nonce, 0, out); }