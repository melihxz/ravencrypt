#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ravencrypt.h"


#define BENCH_PLAINTEXT_SIZE (1024 * 1024) // 1MB

// Zaman ölçüm fonksiyonu (mikrosaniye)
static long long time_diff_us(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000000LL + (end->tv_nsec - start->tv_nsec) / 1000LL;
}

int main() {
    printf("Ravencrypt benchmark başlıyor...\n");

    raven_key_t key = {0};
    for (size_t i = 0; i < RAVEN_KEY_LEN_256; i++) {
        key.key[i] = (uint8_t)(i + 1);
    }
    key.key_len = RAVEN_KEY_LEN_256;

    srand((unsigned int)time(NULL));

    uint8_t *plaintext = malloc(BENCH_PLAINTEXT_SIZE);
    if (!plaintext) {
        fprintf(stderr, "Bellek tahsis edilemedi!\n");
        return 1;
    }

    // Rastgele veri üret
    for (size_t i = 0; i < BENCH_PLAINTEXT_SIZE; i++) {
        plaintext[i] = (uint8_t)(rand() % 256);
    }

    raven_encrypted_t encrypted = {0};
    uint8_t *decrypted = malloc(BENCH_PLAINTEXT_SIZE);
    size_t decrypted_len = 0;
    if (!decrypted) {
        fprintf(stderr, "Bellek tahsis edilemedi!\n");
        free(plaintext);
        return 1;
    }

    struct timespec start, end;
    long long enc_time, dec_time;

    // AES-GCM Benchmark
    memset(&encrypted, 0, sizeof(encrypted));
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (raven_encrypt(RAVEN_CIPHER_AES_GCM, plaintext, BENCH_PLAINTEXT_SIZE, &key, &encrypted) != RAVEN_OK) {
        fprintf(stderr, "AES-GCM şifreleme başarısız!\n");
        free(plaintext);
        free(decrypted);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    enc_time = time_diff_us(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (raven_decrypt(RAVEN_CIPHER_AES_GCM,
                      encrypted.ciphertext,
                      encrypted.ciphertext_len,
                      encrypted.mac,
                      encrypted.nonce,
                      &key,
                      decrypted,
                      &decrypted_len) != RAVEN_OK) {
        fprintf(stderr, "AES-GCM şifre çözme başarısız!\n");
        if(encrypted.ciphertext) free(encrypted.ciphertext);
        free(plaintext);
        free(decrypted);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    dec_time = time_diff_us(&start, &end);

    printf("AES-GCM 1MB şifreleme: %lld mikro saniye\n", enc_time);
    printf("AES-GCM 1MB şifre çözme: %lld mikro saniye\n", dec_time);

    if(encrypted.ciphertext) {
        free(encrypted.ciphertext);
        encrypted.ciphertext = NULL;
    }

    // ChaCha20-Poly1305 Benchmark
    memset(&encrypted, 0, sizeof(encrypted));
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (raven_encrypt(RAVEN_CIPHER_CHACHA20_POLY1305, plaintext, BENCH_PLAINTEXT_SIZE, &key, &encrypted) != RAVEN_OK) {
        fprintf(stderr, "ChaCha20-Poly1305 şifreleme başarısız!\n");
        free(plaintext);
        free(decrypted);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    enc_time = time_diff_us(&start, &end);

    clock_gettime(CLOCK_MONOTONIC, &start);
    if (raven_decrypt(RAVEN_CIPHER_CHACHA20_POLY1305,
                      encrypted.ciphertext,
                      encrypted.ciphertext_len,
                      encrypted.mac,
                      encrypted.nonce,
                      &key,
                      decrypted,
                      &decrypted_len) != RAVEN_OK) {
        fprintf(stderr, "ChaCha20-Poly1305 şifre çözme başarısız!\n");
        if(encrypted.ciphertext) free(encrypted.ciphertext);
        free(plaintext);
        free(decrypted);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    dec_time = time_diff_us(&start, &end);

    printf("ChaCha20-Poly1305 1MB şifreleme: %lld mikro saniye\n", enc_time);
    printf("ChaCha20-Poly1305 1MB şifre çözme: %lld mikro saniye\n", dec_time);

    if(encrypted.ciphertext) {
        free(encrypted.ciphertext);
        encrypted.ciphertext = NULL;
    }

    free(plaintext);
    free(decrypted);

    printf("Benchmark tamamlandı.\n");
    return 0;
}
