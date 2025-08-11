#include "ravencrypt.h"
#include <stdlib.h>
#include <string.h>

int rc_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len) {
    if (!ikm || !okm) return RAVEN_ERR;
    uint8_t prk[32];
    uint8_t zero_salt[32];
    if (!salt) { memset(zero_salt,0,32); salt = zero_salt; salt_len = 32; }
    rc_internal_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    size_t n = (okm_len + 31) / 32; if (n > 255) return RAVEN_ERR;
    uint8_t t[32]; uint8_t previous[32]; size_t pos = 0; size_t prev_len = 0;
    for (uint8_t i=1;i<=n;++i) {
        size_t buf_len = prev_len + (info?info_len:0) + 1;
        uint8_t *buf = malloc(buf_len);
        if (!buf) return RAVEN_ERR;
        size_t off=0; if (prev_len) { memcpy(buf+off,previous,prev_len); off+=prev_len; }
        if (info && info_len) { memcpy(buf+off,info,info_len); off+=info_len; }
        buf[off++] = i;
        rc_internal_hmac_sha256(prk, 32, buf, buf_len, t);
        free(buf);
        size_t copy = (pos + 32 <= okm_len) ? 32 : (okm_len - pos);
        memcpy(okm + pos, t, copy);
        pos += copy; memcpy(previous, t, 32); prev_len = 32;
    }
    rc_secure_zero(prk,32); rc_secure_zero(t,32); rc_secure_zero(previous,32);
    return RAVEN_OK;
}