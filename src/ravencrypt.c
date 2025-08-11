#include "ravencrypt.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

void raven_secure_zero(void *ptr, size_t len) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#else
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) *p++ = 0;
#endif
}

raven_error_t raven_encrypt(
    raven_cipher_t cipher,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const raven_key_t *key,
    raven_encrypted_t *output
) {
    if (!plaintext || !key || !output) return RAVEN_ERR_NULL_POINTER;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return RAVEN_ERR_MEMORY;

    const EVP_CIPHER *evp_cipher = NULL;

    switch (cipher) {
        case RAVEN_CIPHER_AES_GCM:
            if (key->key_len != 32) {
                EVP_CIPHER_CTX_free(ctx);
                return RAVEN_ERR_INVALID_PARAM;
            }
            evp_cipher = EVP_aes_256_gcm();
            break;
        case RAVEN_CIPHER_CHACHA20_POLY1305:
            if (key->key_len != 32) {
                EVP_CIPHER_CTX_free(ctx);
                return RAVEN_ERR_INVALID_PARAM;
            }
            evp_cipher = EVP_chacha20_poly1305();
            break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return RAVEN_ERR_INVALID_PARAM;
    }

    output->nonce[0] = 0;
    output->nonce[1] = 0;
    output->nonce[2] = 0;
    if (!RAND_bytes(output->nonce, RAVEN_NONCE_LEN)) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_EncryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, RAVEN_NONCE_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key->key, output->nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    int outlen = (int)plaintext_len + EVP_CIPHER_block_size(evp_cipher);
    output->ciphertext = (uint8_t*)malloc(outlen);
    if (!output->ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_MEMORY;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, output->ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        free(output->ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }
    output->ciphertext_len = (size_t)len;

    if (EVP_EncryptFinal_ex(ctx, output->ciphertext + len, &len) != 1) {
        free(output->ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }
    output->ciphertext_len += (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, RAVEN_MAC_LEN, output->mac) != 1) {
        free(output->ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    EVP_CIPHER_CTX_free(ctx);
    return RAVEN_OK;
}

raven_error_t raven_decrypt(
    raven_cipher_t cipher,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t mac[RAVEN_MAC_LEN],
    const uint8_t nonce[RAVEN_NONCE_LEN],
    const raven_key_t *key,
    uint8_t *plaintext,
    size_t *plaintext_len
) {
    if (!ciphertext || !key || !plaintext || !plaintext_len || !mac || !nonce)
        return RAVEN_ERR_NULL_POINTER;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return RAVEN_ERR_MEMORY;

    const EVP_CIPHER *evp_cipher = NULL;
    switch (cipher) {
        case RAVEN_CIPHER_AES_GCM:
            if (key->key_len != 32) {
                EVP_CIPHER_CTX_free(ctx);
                return RAVEN_ERR_INVALID_PARAM;
            }
            evp_cipher = EVP_aes_256_gcm();
            break;
        case RAVEN_CIPHER_CHACHA20_POLY1305:
            if (key->key_len != 32) {
                EVP_CIPHER_CTX_free(ctx);
                return RAVEN_ERR_INVALID_PARAM;
            }
            evp_cipher = EVP_chacha20_poly1305();
            break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return RAVEN_ERR_INVALID_PARAM;
    }

    if (EVP_DecryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, RAVEN_NONCE_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key->key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }
    size_t plaintext_len_local = (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, RAVEN_MAC_LEN, (void *)mac) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }
    plaintext_len_local += (size_t)len;
    *plaintext_len = plaintext_len_local;

    EVP_CIPHER_CTX_free(ctx);
    return RAVEN_OK;
}
