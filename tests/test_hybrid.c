#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ravencrypt.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s:", label);
    for (size_t i = 0; i < len; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("Ravencrypt test is starting...\n");

    raven_key_t key1 = {0};
    raven_key_t key2 = {0};

    for (size_t i = 0; i < RAVEN_KEY_LEN_256; i++) {
        key1.key[i] = (uint8_t)(i + 1);
        key2.key[i] = (uint8_t)(255 - i);
    }
    key1.key_len = RAVEN_KEY_LEN_256;
    key2.key_len = RAVEN_KEY_LEN_256;

    const char *plaintext = "ABCDEFG1234567890ihatecoding";
    size_t plaintext_len = strlen(plaintext);

    raven_hybrid_encrypted_t encrypted = {0};
    uint8_t *decrypted = malloc(plaintext_len + 1);
    size_t decrypted_len = 0;

    if (!decrypted) {
        printf("Mem thing unsuccessful\n");
        return 1;
    }

    if (raven_hybrid_encrypt((const uint8_t*)plaintext, plaintext_len, &key1, &key2, &encrypted) != RAVEN_OK) {
        printf("Unsuccessful!\n");
        free(decrypted);
        return 1;
    }

    print_hex("AES-GCM Encrypted", encrypted.aes_part.ciphertext, encrypted.aes_part.ciphertext_len);
    print_hex("ChaCha20-Poly1305 Encrypted", encrypted.chacha_part.ciphertext, encrypted.chacha_part.ciphertext_len);

    if (raven_hybrid_decrypt(&encrypted, &key1, &key2, decrypted, &decrypted_len) != RAVEN_OK) {
        printf("Unsuccessful!\n");
        free(encrypted.aes_part.ciphertext);
        free(encrypted.chacha_part.ciphertext);
        free(decrypted);
        return 1;
    }

    decrypted[decrypted_len] = '\0';
    printf("Decrypted: %s\n", decrypted);

    free(encrypted.aes_part.ciphertext);
    free(encrypted.chacha_part.ciphertext);
    free(decrypted);

    printf("Successful.\n");
    return 0;
}
