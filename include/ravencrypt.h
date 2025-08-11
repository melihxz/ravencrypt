#ifndef RAVENCRYPT_H
#define RAVENCRYPT_H

#include <stdint.h>
#include <stddef.h>
#include <bits/time.h>
#include <linux/time.h>

// Sabitler
#define RAVEN_KEY_LEN_256 32
#define RAVEN_NONCE_LEN 12
#define RAVEN_MAC_LEN 16

// Hata kodları
typedef enum {
    RAVEN_OK = 0,
    RAVEN_ERR_NULL_POINTER,
    RAVEN_ERR_MEMORY,
    RAVEN_ERR_CRYPTO_FAIL,
    RAVEN_ERR_INVALID_PARAM,
} raven_error_t;

// Şifreleme algoritmaları
typedef enum {
    RAVEN_CIPHER_AES_GCM = 1,
    RAVEN_CIPHER_CHACHA20_POLY1305 = 2,
} raven_cipher_t;

// Anahtar yapısı
typedef struct {
    uint8_t key[RAVEN_KEY_LEN_256];
    size_t key_len;
} raven_key_t;

// Şifrelenmiş çıktı yapısı
typedef struct {
    uint8_t *ciphertext;
    size_t ciphertext_len;

    uint8_t mac[RAVEN_MAC_LEN];
    uint8_t nonce[RAVEN_NONCE_LEN];
} raven_encrypted_t;

// Oturum anahtarı yapısı (forward secrecy için)
typedef struct {
    uint8_t session_key[RAVEN_KEY_LEN_256];
    size_t key_len;
    uint64_t session_id;
} raven_session_key_t;

// Hibrit şifreleme yapısı
typedef struct {
    raven_encrypted_t aes_part;
    raven_encrypted_t chacha_part;
} raven_hybrid_encrypted_t;

// API Fonksiyonları

// Genel şifreleme ve şifre çözme
raven_error_t raven_encrypt(
    raven_cipher_t cipher,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const raven_key_t *key,
    raven_encrypted_t *output
);

raven_error_t raven_decrypt(
    raven_cipher_t cipher,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t mac[RAVEN_MAC_LEN],
    const uint8_t nonce[RAVEN_NONCE_LEN],
    const raven_key_t *key,
    uint8_t *plaintext,
    size_t *plaintext_len
);

// Argon2 KDF prototipi
raven_error_t raven_kdf_argon2(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *out_key,
    size_t out_key_len
);


// KDF: HKDF (SHA256 tabanlı)
raven_error_t raven_kdf_hkdf(
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_key,
    size_t out_key_len
);

// Oturum anahtarı oluşturma ve temizleme
raven_error_t raven_generate_session_key(
    const raven_key_t *master_key,
    raven_session_key_t *session_key,
    uint64_t session_id
);

void raven_session_key_free(raven_session_key_t *session_key);

// Hibrit şifreleme API'si
raven_error_t raven_hybrid_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const raven_key_t *key1,
    const raven_key_t *key2,
    raven_hybrid_encrypted_t *output
);

raven_error_t raven_hybrid_decrypt(
    const raven_hybrid_encrypted_t *input,
    const raven_key_t *key1,
    const raven_key_t *key2,
    uint8_t *plaintext,
    size_t *plaintext_len
);

// Yardımcı fonksiyonlar
void raven_secure_zero(void *ptr, size_t len);

#endif // RAVENCRYPT_H
