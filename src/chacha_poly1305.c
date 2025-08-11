#include "ravencrypt.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>

raven_error_t chacha20_poly1305_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[RAVEN_KEY_LEN_256],
    raven_encrypted_t *output
) {
    if (!plaintext || !key || !output) return RAVEN_ERR_NULL_POINTER;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return RAVEN_ERR_MEMORY;

    if (RAND_bytes(output->nonce, RAVEN_NONCE_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, RAVEN_NONCE_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, output->nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    int outlen = (int)plaintext_len + EVP_CIPHER_block_size(EVP_chacha20_poly1305());
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

raven_error_t chacha20_poly1305_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[RAVEN_KEY_LEN_256],
    const uint8_t mac[RAVEN_MAC_LEN],
    const uint8_t nonce[RAVEN_NONCE_LEN],
    uint8_t *plaintext,
    size_t *plaintext_len
) {
    if (!ciphertext || !key || !mac || !nonce || !plaintext || !plaintext_len)
        return RAVEN_ERR_NULL_POINTER;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return RAVEN_ERR_MEMORY;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, RAVEN_NONCE_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return RAVEN_ERR_CRYPTO_FAIL;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
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
