#include "ravencrypt.h"

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <string.h>

int rc_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto err;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1)
        goto err;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto err;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
            goto err;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1)
        goto err;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto err;
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto err;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int rc_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;
    int ret = -1;

    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto end;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1)
        goto end;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto end;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
            goto end;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1)
        goto end;
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1)
        goto end;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        goto end;
    plaintext_len += len;

    ret = plaintext_len;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#else // USE_OPENSSL not defined

int rc_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *ciphertext, uint8_t *tag) {
    (void)key; (void)iv; (void)iv_len;
    (void)aad; (void)aad_len;
    (void)plaintext; (void)plaintext_len;
    (void)ciphertext; (void)tag;
    return -1; // Not supported
}

int rc_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *tag, uint8_t *plaintext) {
    (void)key; (void)iv; (void)iv_len;
    (void)aad; (void)aad_len;
    (void)ciphertext; (void)ciphertext_len;
    (void)tag; (void)plaintext;
    return -1; // Not supported
}

#endif
