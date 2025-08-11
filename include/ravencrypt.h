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

int rc_init(void);
int rc_random_bytes(uint8_t *out, size_t n);

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

char *rc_armor_encrypt(const uint8_t key[RAVEN_KEY_BYTES],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len);

uint8_t *rc_unarmor_decrypt(const uint8_t key[RAVEN_KEY_BYTES],
                            const char *armor, size_t *plaintext_len_out);

int rc_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* RAVENCRYPT_H */