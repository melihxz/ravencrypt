#include "ravencrypt.h"
#include <string.h>

raven_error_t raven_generate_session_key(
    const raven_key_t *master_key,
    raven_session_key_t *session_key,
    uint64_t session_id
) {
    if (!master_key || !session_key) return RAVEN_ERR_NULL_POINTER;

    uint8_t salt[8];
    for (int i = 0; i < 8; i++) {
        salt[i] = (session_id >> (8 * i)) & 0xFF;
    }

    const uint8_t info[] = "ravencrypt session key";

    raven_error_t ret = raven_kdf_hkdf(
        master_key->key,
        master_key->key_len,
        salt,
        sizeof(salt),
        info,
        sizeof(info) - 1,
        session_key->session_key,
        RAVEN_KEY_LEN_256
    );

    if (ret == RAVEN_OK) {
        session_key->key_len = RAVEN_KEY_LEN_256;
        session_key->session_id = session_id;
    }

    return ret;
}

void raven_session_key_free(raven_session_key_t *session_key) {
    if (session_key) {
        raven_secure_zero(session_key->session_key, session_key->key_len);
        session_key->key_len = 0;
        session_key->session_id = 0;
    }
}
