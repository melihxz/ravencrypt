#include "ravencrypt.h"
#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>

static int hkdf_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t *prk, unsigned int *prk_len
) {
    uint8_t null_salt[EVP_MAX_MD_SIZE] = {0};
    if (!salt) {
        salt = null_salt;
        salt_len = EVP_MD_size(EVP_sha256());
    }

    unsigned char *result = HMAC(
        EVP_sha256(),
        salt, (int)salt_len,
        ikm, ikm_len,
        prk,
        prk_len
    );

    return (result != NULL) ? 1 : 0;
}

static int hkdf_expand(
    const uint8_t *prk, unsigned int prk_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
) {
    size_t hash_len = EVP_MD_size(EVP_sha256());
    size_t N = (okm_len + hash_len - 1) / hash_len; // ceil(okm_len / hash_len)
    if (N > 255) return 0; // limit

    uint8_t T[EVP_MAX_MD_SIZE];
    size_t T_len = 0;
    size_t pos = 0;

    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) return 0;

    for (uint8_t i = 1; i <= N; i++) {
        if (!HMAC_Init_ex(ctx, prk, prk_len, EVP_sha256(), NULL)) {
            HMAC_CTX_free(ctx);
            return 0;
        }
        if (T_len > 0) {
            if (!HMAC_Update(ctx, T, T_len)) {
                HMAC_CTX_free(ctx);
                return 0;
            }
        }
        if (info && info_len > 0) {
            if (!HMAC_Update(ctx, info, info_len)) {
                HMAC_CTX_free(ctx);
                return 0;
            }
        }
        if (!HMAC_Update(ctx, &i, 1)) {
            HMAC_CTX_free(ctx);
            return 0;
        }

        if (!HMAC_Final(ctx, T, (unsigned int *)&T_len)) {
            HMAC_CTX_free(ctx);
            return 0;
        }

        size_t copy_len = (pos + T_len > okm_len) ? (okm_len - pos) : T_len;
        memcpy(okm + pos, T, copy_len);
        pos += copy_len;
    }

    HMAC_CTX_free(ctx);
    return 1;
}

raven_error_t raven_kdf_hkdf(
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_key,
    size_t out_key_len
) {
    if (!ikm || !out_key) return RAVEN_ERR_NULL_POINTER;

    uint8_t prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;

    if (!hkdf_extract(salt, salt_len, ikm, ikm_len, prk, &prk_len)) {
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (!hkdf_expand(prk, prk_len, info, info_len, out_key, out_key_len)) {
        raven_secure_zero(prk, sizeof(prk));
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    raven_secure_zero(prk, sizeof(prk));
    return RAVEN_OK;
}
