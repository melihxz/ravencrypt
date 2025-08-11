#include "ravencrypt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* forward declarations of internal functions from modules */
void rc_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);
void rc_chacha20_block_for_poly(const uint8_t key[32], const uint8_t nonce[12], uint8_t out32[32]);
void rc_poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t msg_len, uint8_t out[16]);

int rc_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, uint8_t tag[16]) {
    if (!key || !nonce || !plaintext || !ciphertext || !tag) return RAVEN_ERR;
    uint8_t one_time_key[32];
    rc_chacha20_block_for_poly(key, nonce, one_time_key);
    rc_chacha20_xor(key, nonce, 1, plaintext, ciphertext, plaintext_len);
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    size_t ct_pad = (16 - (plaintext_len % 16)) % 16;
    size_t mac_len = aad_len + aad_pad + plaintext_len + ct_pad + 16;
    uint8_t *mac_data = malloc(mac_len);
    if (!mac_data) { rc_secure_zero(one_time_key, sizeof(one_time_key)); return RAVEN_ERR; }
    size_t off=0; if (aad_len) { memcpy(mac_data+off,aad,aad_len); off+=aad_len; } if (aad_pad) { memset(mac_data+off,0,aad_pad); off+=aad_pad; }
    if (plaintext_len) { memcpy(mac_data+off,ciphertext,plaintext_len); off+=plaintext_len; } if (ct_pad) { memset(mac_data+off,0,ct_pad); off+=ct_pad; }
    uint64_t a_le = (uint64_t)aad_len; uint64_t c_le = (uint64_t)plaintext_len;
    for (int i=0;i<8;++i) mac_data[off + i] = (a_le >> (8*i)) & 0xff;
    for (int i=0;i<8;++i) mac_data[off + 8 + i] = (c_le >> (8*i)) & 0xff;
    rc_poly1305_mac(one_time_key, mac_data, mac_len, tag);
    rc_secure_zero(one_time_key,sizeof(one_time_key)); rc_secure_zero(mac_data,mac_len); free(mac_data);
    return RAVEN_OK;
}

int rc_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t tag[16], uint8_t *plaintext_out) {
    if (!key || !nonce || !ciphertext || !plaintext_out || !tag) return RAVEN_ERR;
    uint8_t one_time_key[32]; rc_chacha20_block_for_poly(key, nonce, one_time_key);
    size_t aad_pad = (16 - (aad_len % 16)) % 16; size_t ct_pad = (16 - (ciphertext_len % 16)) % 16;
    size_t mac_len = aad_len + aad_pad + ciphertext_len + ct_pad + 16; uint8_t *mac_data = malloc(mac_len);
    if (!mac_data) { rc_secure_zero(one_time_key,sizeof(one_time_key)); return RAVEN_ERR; }
    size_t off=0; if (aad_len) { memcpy(mac_data+off,aad,aad_len); off+=aad_len; } if (aad_pad) { memset(mac_data+off,0,aad_pad); off+=aad_pad; }
    if (ciphertext_len) { memcpy(mac_data+off,ciphertext,ciphertext_len); off+=ciphertext_len; } if (ct_pad) { memset(mac_data+off,0,ct_pad); off+=ct_pad; }
    uint64_t a_le = (uint64_t)aad_len; uint64_t c_le = (uint64_t)ciphertext_len;
    for (int i=0;i<8;++i) mac_data[off + i] = (a_le >> (8*i)) & 0xff;
    for (int i=0;i<8;++i) mac_data[off + 8 + i] = (c_le >> (8*i)) & 0xff;
    uint8_t calc_tag[16]; rc_poly1305_mac(one_time_key, mac_data, mac_len, calc_tag);
    rc_secure_zero(mac_data, mac_len); free(mac_data);
    uint8_t diff = 0; for (int i=0;i<16;++i) diff |= calc_tag[i] ^ tag[i]; if (diff) { rc_secure_zero(one_time_key,sizeof(one_time_key)); rc_secure_zero(calc_tag,sizeof(calc_tag)); return RAVEN_INVALID; }
    rc_chacha20_xor(key, nonce, 1, ciphertext, plaintext_out, ciphertext_len);
    rc_secure_zero(one_time_key,sizeof(one_time_key)); rc_secure_zero(calc_tag,sizeof(calc_tag));
    return RAVEN_OK;
}

char *rc_armor_encrypt(const uint8_t key[32], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t plaintext_len) {
    if (!key || !plaintext) return NULL;
    uint8_t nonce[12]; if (rc_random_bytes(nonce,12) != RAVEN_OK) return NULL;
    uint8_t *ct = malloc(plaintext_len);
    uint8_t tag[16]; if (!ct) return NULL;
    if (rc_aead_encrypt(key, nonce, aad, aad_len, plaintext, plaintext_len, ct, tag) != RAVEN_OK) { free(ct); return NULL; }
    char *n_enc = rc_b64url_encode_alloc(nonce,12);
    char *c_enc = rc_b64url_encode_alloc(ct, plaintext_len);
    char *t_enc = rc_b64url_encode_alloc(tag,16);
    size_t sz = strlen(n_enc) + strlen(c_enc) + strlen(t_enc) + 32;
    char *out = malloc(sz);
    if (!out) { free(ct); free(n_enc); free(c_enc); free(t_enc); return NULL; }
    snprintf(out, sz, "RAV1|%s|%s|%s|%02x", n_enc, c_enc, t_enc, rc_checksum8((uint8_t*)c_enc, strlen(c_enc)));
    rc_secure_zero(ct, plaintext_len); free(ct); free(n_enc); free(c_enc); free(t_enc);
    return out;
}

uint8_t *rc_unarmor_decrypt(const uint8_t key[32], const char *armor, size_t *plaintext_len_out) {
    if (!key || !armor) return NULL;
    char *copy = strdup(armor);
    char *parts[5] = {0}; int idx=0;
    char *tok = strtok(copy, "|"); while (tok && idx < 5) { parts[idx++] = tok; tok = strtok(NULL, "|"); }
    if (idx < 5) { free(copy); return NULL; }
    if (strcmp(parts[0], "RAV1") != 0) { free(copy); return NULL; }
    size_t nonce_len, ct_len, tag_len; uint8_t *nonce = rc_b64url_decode_alloc(parts[1], &nonce_len);
    uint8_t *ct = rc_b64url_decode_alloc(parts[2], &ct_len); uint8_t *tag = rc_b64url_decode_alloc(parts[3], &tag_len);
    if (!nonce || !ct || !tag) { free(copy); free(nonce); free(ct); free(tag); return NULL; }
    uint8_t cs = 0; sscanf(parts[4], "%2hhx", &cs);
    uint8_t calc = rc_checksum8((uint8_t*)parts[2], strlen(parts[2])); if (calc != cs) { free(copy); free(nonce); free(ct); free(tag); return NULL; }
    uint8_t *out = malloc(ct_len);
    if (!out) { free(copy); free(nonce); free(ct); free(tag); return NULL; }
    int r = rc_aead_decrypt(key, nonce, NULL, 0, ct, ct_len, tag, out);
    if (r != RAVEN_OK) { free(copy); free(nonce); free(ct); free(tag); free(out); return NULL; }
    *plaintext_len_out = ct_len; free(copy); free(nonce); free(ct); free(tag); return out;
}

/* AES-GCM wrapper: uses OpenSSL if available */
#ifdef USE_OPENSSL
#include <openssl/evp.h>
int rc_aes_gcm_encrypt(const uint8_t *key, size_t key_len, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, uint8_t tag[16]) {
    if (!key || !iv || !plaintext || !ciphertext || !tag) return RAVEN_ERR;
    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_gcm(); else if (key_len == 24) cipher = EVP_aes_192_gcm(); else if (key_len == 32) cipher = EVP_aes_256_gcm(); else return RAVEN_ERR;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return RAVEN_ERR;
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    int outlen=0;
    if (aad && aad_len) { if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; } }
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plaintext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    int tmplen=0; if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    EVP_CIPHER_CTX_free(ctx); return RAVEN_OK;
}

int rc_aes_gcm_decrypt(const uint8_t *key, size_t key_len, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t tag[16], uint8_t *plaintext_out) {
    if (!key || !iv || !ciphertext || !plaintext_out || !tag) return RAVEN_ERR;
    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_gcm(); else if (key_len == 24) cipher = EVP_aes_192_gcm(); else if (key_len == 32) cipher = EVP_aes_256_gcm(); else return RAVEN_ERR;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return RAVEN_ERR;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    int outlen=0;
    if (aad && aad_len) { if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; } }
    if (EVP_DecryptUpdate(ctx, plaintext_out, &outlen, ciphertext, (int)ciphertext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_ERR; }
    if (EVP_DecryptFinal_ex(ctx, plaintext_out + outlen, &outlen) != 1) { EVP_CIPHER_CTX_free(ctx); return RAVEN_INVALID; }
    EVP_CIPHER_CTX_free(ctx); return RAVEN_OK;
}
#else
int rc_aes_gcm_encrypt(const uint8_t *key, size_t key_len, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, uint8_t tag[16]) {
    /* OpenSSL not available; return error. User can compile with -DUSE_OPENSSL and link -lcrypto */
    (void)key; (void)key_len; (void)iv; (void)aad; (void)aad_len; (void)plaintext; (void)plaintext_len; (void)ciphertext; (void)tag;
    return RAVEN_ERR;
}
int rc_aes_gcm_decrypt(const uint8_t *key, size_t key_len, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t tag[16], uint8_t *plaintext_out) {
    (void)key; (void)key_len; (void)iv; (void)aad; (void)aad_len; (void)ciphertext; (void)ciphertext_len; (void)tag; (void)plaintext_out;
    return RAVEN_ERR;
}
#endif

/* BLAKE2s implementation (compact reference, produces up to 32 bytes) */
/* This is a small, portable implementation adapted from the public domain
 * reference. It focuses on correctness and simplicity rather than speed. */

#include <stddef.h>

/* BLAKE2s constants and helper functions */
static const uint32_t blake2s_iv[8] = {
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static inline uint32_t rotr32(uint32_t w, unsigned c) { return (w >> c) | (w << (32 - c)); }

static void blake2s_compress(uint32_t h[8], const uint8_t block[64], uint64_t t, int last) {
    static const uint8_t sigma[10][16] = {
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
    uint32_t v[16];
    for (int i = 0; i < 8; ++i) v[i] = h[i];
    for (int i = 0; i < 8; ++i) v[i+8] = blake2s_iv[i];
    v[12] ^= (uint32_t)t;
    v[13] ^= (uint32_t)(t >> 32);
    if (last) v[14] = ~v[14];
    uint32_t m[16]; for (int i=0;i<16;++i) { m[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) | ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24); }
    for (int round = 0; round < 10; ++round) {
        #define G(a,b,c,d,x,y) \
            a = a + b + x; d = rotr32(d ^ a, 16); c = c + d; b = rotr32(b ^ c, 12); \
            a = a + b + y; d = rotr32(d ^ a, 8); c = c + d; b = rotr32(b ^ c, 7);
        G(v[0], v[4], v[8], v[12], m[sigma[round][0]], m[sigma[round][1]]);
        G(v[1], v[5], v[9], v[13], m[sigma[round][2]], m[sigma[round][3]]);
        G(v[2], v[6], v[10], v[14], m[sigma[round][4]], m[sigma[round][5]]);
        G(v[3], v[7], v[11], v[15], m[sigma[round][6]], m[sigma[round][7]]);
        G(v[0], v[5], v[10], v[15], m[sigma[round][8]], m[sigma[round][9]]);
        G(v[1], v[6], v[11], v[12], m[sigma[round][10]], m[sigma[round][11]]);
        G(v[2], v[7], v[8], v[13], m[sigma[round][12]], m[sigma[round][13]]);
        G(v[3], v[4], v[9], v[14], m[sigma[round][14]], m[sigma[round][15]]);
        #undef G
    }
    for (int i = 0; i < 8; ++i) h[i] = h[i] ^ v[i] ^ v[i+8];
}

int rc_blake2s(const uint8_t *in, size_t inlen, uint8_t *out32, size_t outlen) {
    if (!out32 || outlen == 0 || outlen > 32) return RAVEN_ERR;
    uint32_t h[8]; for (int i=0;i<8;++i) h[i] = blake2s_iv[i];
    h[0] ^= 0x01010000 ^ (uint32_t)outlen;
    uint8_t block[64]; size_t offset = 0; uint64_t t = 0;
    while (inlen - offset > 64) {
        memcpy(block, in + offset, 64);
        t += 64; blake2s_compress(h, block, t, 0);
        offset += 64;
    }
    size_t rem = inlen - offset; memset(block,0,64); if (rem) memcpy(block, in+offset, rem);
    t += rem; blake2s_compress(h, block, t, 1);
    /* produce digest */
    for (size_t i = 0; i < outlen; ++i) {
        size_t idx = i / 4; size_t off = (i % 4) * 8;
        out32[i] = (h[idx] >> (8*(i%4))) & 0xff;
    }
    return RAVEN_OK;
}