#ifndef RAVENCRYPT_H
#define RAVENCRYPT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAVEN_KEY_BYTES 32
#define RAVEN_NONCE_BYTES 12
#define RAVEN_TAG_BYTES 16

#define RAVEN_OK 0
#define RAVEN_ERR -1
#define RAVEN_INVALID 1

/* Initialization */
int rc_init(void);
int rc_random_bytes(uint8_t *out, size_t n);

/* Utilities (exposed for modular build) */
void rc_secure_zero(void *p, size_t n);
char *rc_b64url_encode_alloc(const uint8_t *in, size_t inlen);
uint8_t *rc_b64url_decode_alloc(const char *in, size_t *outlen);
uint8_t rc_checksum8(const uint8_t *d, size_t n);
int rc_safe_memcmp(const void *a, const void *b, size_t n);

/* Internal HMAC hook (used by HKDF) */
void rc_internal_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* AEAD (ChaCha20-Poly1305) */
int rc_aead_encrypt(const uint8_t key[RAVEN_KEY_BYTES],
                    const uint8_t nonce[RAVEN_NONCE_BYTES],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *ciphertext, uint8_t tag[RAVEN_TAG_BYTES]);

int rc_aead_decrypt(const uint8_t key[RAVEN_KEY_BYTES],
                    const uint8_t nonce[RAVEN_NONCE_BYTES],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t tag[RAVEN_TAG_BYTES],
                    uint8_t *plaintext_out);

/* AES-GCM (wrapper: OpenSSL if available). Non-OpenSSL builds will return RAVEN_ERR.
 * key must be 16/24/32 bytes depending on AES-128/192/256.
 */
int rc_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                       const uint8_t iv[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *ciphertext, uint8_t tag[16]);

int rc_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                       const uint8_t iv[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t tag[16], uint8_t *plaintext_out);

/* BLAKE2s hashing function (pure C, produces up to 32-byte output) */
int rc_blake2s(const uint8_t *in, size_t inlen, uint8_t *out32, size_t outlen);

/* High-level armor helpers */
char *rc_armor_encrypt(const uint8_t key[RAVEN_KEY_BYTES],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len);

uint8_t *rc_unarmor_decrypt(const uint8_t key[RAVEN_KEY_BYTES],
                            const char *armor, size_t *plaintext_len_out);

/* HKDF */
int rc_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* RAVENCRYPT_H */