#include "ravencrypt.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h> // ignore the error

raven_error_t raven_kdf_argon2(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *out_key,
    size_t out_key_len
) {
    if (!password || !salt || !out_key) return RAVEN_ERR_NULL_POINTER;

    if (sodium_init() < 0) {
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    uint32_t t_cost = 3;          
    uint32_t m_cost = (1 << 16);
    uint32_t parallelism = 4;

    if (crypto_pwhash(
            out_key, out_key_len,
            (const char *)password, password_len,
            salt,
            t_cost, m_cost,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        // Başarısız oldu
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    return RAVEN_OK;
}
