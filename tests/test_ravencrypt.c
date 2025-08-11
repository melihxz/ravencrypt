#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ravencrypt.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s:", label);
    for (size_t i = 0; i < len; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("Ravencrypt test starting...\n");

    // Anahtar oluştur
    raven_key_t key = {0};
    for (size_t i = 0; i < RAVEN_KEY_LEN_256; i++) {
        key.key[i] = (uint8_t)i;
    }
    key.key_len = RAVEN_KEY_LEN_256;

    const char *plaintext = "Hi world!";
    size_t plaintext_len = strlen(plaintext);

    raven_encrypted_t encrypted = {0};

    // AES-GCM ile şifrele
    if (raven_encrypt(RAVEN_CIPHER_AES_GCM, (const uint8_t*)plaintext, plaintext_len, &key, &encrypted) != RAVEN_OK) {
        printf("Unsuccessful!\n");
        return 1;
    }
    print_hex("AES-GCM ECrypted", encrypted.ciphertext, encrypted.ciphertext_len);
    print_hex("AES-GCM MAC", encrypted.mac, RAVEN_MAC_LEN);
    print_hex("AES-GCM Nonce", encrypted.nonce, RAVEN_NONCE_LEN);

    uint8_t *decrypted = malloc(plaintext_len + 1);
    size_t decrypted_len = 0;

    // AES-GCM ile şifre çöz
    if (raven_decrypt(RAVEN_CIPHER_AES_GCM,
                      encrypted.ciphertext,
                      encrypted.ciphertext_len,
                      encrypted.mac,
                      encrypted.nonce,
                      &key,
                      decrypted,
                      &decrypted_len) != RAVEN_OK) {
        printf("AES-GCM unsuccessful!\n");
        free(encrypted.ciphertext);
        free(decrypted);
        return 1;
    }
    decrypted[decrypted_len] = 0;
    printf("AES-GCM Dcrypted: %s\n", decrypted);

    free(encrypted.ciphertext);
    free(decrypted);

    // Aynı işlemi ChaCha20-Poly1305 için yapalım
    raven_encrypted_t chacha_encrypted = {0};

    if (raven_encrypt(RAVEN_CIPHER_CHACHA20_POLY1305, (const uint8_t*)plaintext, plaintext_len, &key, &chacha_encrypted) != RAVEN_OK) {
        printf("ChaCha20-Poly1305 crpyting unsuccesful!\n");
        return 1;
    }
    print_hex("ChaCha20-Poly1305 Ecrypted", chacha_encrypted.ciphertext, chacha_encrypted.ciphertext_len);
    print_hex("ChaCha20-Poly1305 MAC", chacha_encrypted.mac, RAVEN_MAC_LEN);
    print_hex("ChaCha20-Poly1305 Nonce", chacha_encrypted.nonce, RAVEN_NONCE_LEN);

    decrypted = malloc(plaintext_len + 1);
    decrypted_len = 0;

    if (raven_decrypt(RAVEN_CIPHER_CHACHA20_POLY1305,
                      chacha_encrypted.ciphertext,
                      chacha_encrypted.ciphertext_len,
                      chacha_encrypted.mac,
                      chacha_encrypted.nonce,
                      &key,
                      decrypted,
                      &decrypted_len) != RAVEN_OK) {
        printf("ChaCha20-Poly1305 unsuccessful!\n");
        free(chacha_encrypted.ciphertext);
        free(decrypted);
        return 1;
    }
    decrypted[decrypted_len] = 0;
    printf("ChaCha20-Poly1305 Dcrypted: %s\n", decrypted);

    free(chacha_encrypted.ciphertext);
    free(decrypted);

    printf("Tests are good.\n");
    return 0;
}
