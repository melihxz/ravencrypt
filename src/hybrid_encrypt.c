#include "ravencrypt.h"
#include <stdlib.h>
#include <string.h>

raven_error_t raven_hybrid_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const raven_key_t *key1,
    const raven_key_t *key2,
    raven_hybrid_encrypted_t *output
) {
    if (!plaintext || !key1 || !key2 || !output) return RAVEN_ERR_NULL_POINTER;

    raven_error_t ret;

    ret = aes_gcm_encrypt(plaintext, plaintext_len, key1->key, &output->aes_part);
    if (ret != RAVEN_OK) return ret;

    ret = chacha20_poly1305_encrypt(plaintext, plaintext_len, key2->key, &output->chacha_part);
    if (ret != RAVEN_OK) {
        free(output->aes_part.ciphertext);
        return ret;
    }

    return RAVEN_OK;
}

raven_error_t raven_hybrid_decrypt(
    const raven_hybrid_encrypted_t *input,
    const raven_key_t *key1,
    const raven_key_t *key2,
    uint8_t *plaintext,
    size_t *plaintext_len
) {
    if (!input || !key1 || !key2 || !plaintext || !plaintext_len) return RAVEN_ERR_NULL_POINTER;

    raven_error_t ret;

    ret = aes_gcm_decrypt(
        input->aes_part.ciphertext,
        input->aes_part.ciphertext_len,
        key1->key,
        input->aes_part.mac,
        input->aes_part.nonce,
        plaintext,
        plaintext_len
    );

    if (ret != RAVEN_OK) {
        ret = chacha20_poly1305_decrypt(
            input->chacha_part.ciphertext,
            input->chacha_part.ciphertext_len,
            key2->key,
            input->chacha_part.mac,
            input->chacha_part.nonce,
            plaintext,
            plaintext_len
        );
    }

    return ret;
}
