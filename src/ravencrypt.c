#include "ravencrypt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* forward declarations of internal functions from modules */
void rc_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);
void rc_chacha20_block_for_poly(const uint8_t key[32], const uint8_t nonce[12], uint8_t out[64]);
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
