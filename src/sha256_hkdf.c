// sha256_hkdf.c
#include "ravencrypt.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

void rc_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outlen = 0;
    if (!ctx) return;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

void rc_hmac_sha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[32]) {
    unsigned int outlen = 0;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &outlen);
}

int rc_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t *okm, size_t okm_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;

    if (EVP_PKEY_derive_init(pctx) <= 0) goto fail;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto fail;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) goto fail;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) <= 0) goto fail;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, NULL, 0) <= 0) goto fail;
    if (EVP_PKEY_derive(pctx, okm, &okm_len) <= 0) goto fail;

    EVP_PKEY_CTX_free(pctx);
    return 1;

fail:
    EVP_PKEY_CTX_free(pctx);
    return 0;
}
