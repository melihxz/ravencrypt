#include "ravencrypt.h"
#include <stdint.h>
#include <string.h>

/* Poly1305 implementation (clear, portable). It is sufficient for test and
 * compatibility. For heavy production consider libsodium's implementation. */

static uint64_t rc_load32_le(const uint8_t *p) { return (uint64_t)p[0] | ((uint64_t)p[1]<<8) | ((uint64_t)p[2]<<16) | ((uint64_t)p[3]<<24); }

void rc_poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t msg_len, uint8_t out[16]) {
    uint8_t r_bytes[16]; uint8_t s_bytes[16]; memcpy(r_bytes, key, 16); memcpy(s_bytes, key+16, 16);
    r_bytes[3] &= 15; r_bytes[7] &= 15; r_bytes[11] &= 15; r_bytes[15] &= 15; r_bytes[4] &= 252; r_bytes[8] &= 252; r_bytes[12] &= 252;
    uint64_t r0 = (rc_load32_le(r_bytes)      ) & 0x3ffffff;
    uint64_t r1 = ((rc_load32_le(r_bytes+3) >> 2) | (rc_load32_le(r_bytes+4) << 30)) & 0x3ffffff;
    uint64_t r2 = ((rc_load32_le(r_bytes+6) >> 4) | (rc_load32_le(r_bytes+7) << 28)) & 0x3ffffff;
    uint64_t r3 = ((rc_load32_le(r_bytes+9) >> 6) | (rc_load32_le(r_bytes+10) << 26)) & 0x3ffffff;
    uint64_t r4 = ((rc_load32_le(r_bytes+12) >> 8) | (rc_load32_le(r_bytes+13) << 24)) & 0x3ffffff;
    uint64_t h0=0,h1=0,h2=0,h3=0,h4=0;
    size_t offset=0; uint8_t block[17];
    while (offset < msg_len) {
        size_t want = (msg_len - offset) < 16 ? (msg_len - offset) : 16;
        memset(block,0,17); if (want) memcpy(block, msg + offset, want); block[want]=1;
        uint64_t t0 = rc_load32_le(block); uint64_t t1 = rc_load32_le(block+4); uint64_t t2 = rc_load32_le(block+8); uint64_t t3 = rc_load32_le(block+12);
        h0 += (t0 & 0x3ffffff);
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) & 0x3ffffff;
        uint64_t d0 = h0 * r0 + h1 * (5 * r4) + h2 * (5 * r3) + h3 * (5 * r2) + h4 * (5 * r1);
        uint64_t d1 = h0 * r1 + h1 * r0 + h2 * (5 * r4) + h3 * (5 * r3) + h4 * (5 * r2);
        uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r4) + h4 * (5 * r3);
        uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r4);
        uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        uint64_t c;
        c = (d0 >> 26); h0 = d0 & 0x3ffffff; d1 += c;
        c = (d1 >> 26); h1 = d1 & 0x3ffffff; d2 += c;
        c = (d2 >> 26); h2 = d2 & 0x3ffffff; d3 += c;
        c = (d3 >> 26); h3 = d3 & 0x3ffffff; d4 += c;
        c = (d4 >> 26); h4 = d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        offset += want;
    }
    uint64_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);
    uint64_t mask = (g4 >> 63) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);
    uint64_t low = h0 | (h1 << 26) | (h2 << 52);
    uint64_t high = ((h2 >> 12) | (h3 << 14) | (h4 << 40));
    uint64_t s_low = rc_load32_le(s_bytes) | ((uint64_t)rc_load32_le(s_bytes+4) << 32);
    uint64_t s_high = rc_load32_le(s_bytes+8) | ((uint64_t)rc_load32_le(s_bytes+12) << 32);
    uint64_t res_low = low + s_low; uint64_t carry = (res_low < low) ? 1 : 0; uint64_t res_high = high + s_high + carry;
    for (int i=0;i<8;++i) out[i] = (res_low >> (8*i)) & 0xff;
    for (int i=0;i<8;++i) out[8+i] = (res_high >> (8*i)) & 0xff;
    rc_secure_zero(r_bytes, sizeof(r_bytes)); rc_secure_zero(s_bytes, sizeof(s_bytes));
}