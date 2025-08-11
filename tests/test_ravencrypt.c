#include "ravencrypt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void panic(const char *m) { fprintf(stderr, "TEST FAIL: %s", m); exit(2); }

int main(void) {
    rc_init();
    uint8_t key[32]; if (rc_random_bytes(key,32) != RAVEN_OK) panic("random key");
    const char *msg = "The quick brown fox jumps over the lazy dog";
    char *armor = rc_armor_encrypt(key, NULL, 0, (const uint8_t*)msg, strlen(msg));
    if (!armor) panic("armor encrypt failed");
    printf("armor: %s", armor);
    size_t mlen; uint8_t *dec = rc_unarmor_decrypt(key, armor, &mlen);
    if (!dec) panic("unarmor decrypt failed");
    if (mlen != strlen(msg) || memcmp(dec, msg, mlen) != 0) panic("plaintext mismatch");
    printf("roundtrip OK.");
    free(armor); free(dec);
    /* tamper detection */
    char *bad = strdup("RAV1|AAAA|BBBB|CCCC|00"); uint8_t *d2 = rc_unarmor_decrypt(key, bad, &mlen);
    if (d2) { free(d2); free(bad); panic("tamper not detected"); }
    free(bad);
    printf("tamper detection OK.");

    /* AES-GCM (if available) smoke test */
#ifdef USE_OPENSSL
    uint8_t aes_key[32]; rc_random_bytes(aes_key,32);
    uint8_t iv[12]; rc_random_bytes(iv,12);
    uint8_t *ct = malloc(strlen(msg)); uint8_t tag[16];
    if (rc_aes_gcm_encrypt(aes_key, 32, iv, NULL,0, (const uint8_t*)msg, strlen(msg), ct, tag) != RAVEN_OK) panic("aes-gcm encrypt");
    uint8_t *pt = malloc(strlen(msg)); if (rc_aes_gcm_decrypt(aes_key,32, iv, NULL,0, ct, strlen(msg), tag, pt) != RAVEN_OK) panic("aes-gcm decrypt");
    if (memcmp(pt, msg, strlen(msg)) != 0) panic("aes-gcm mismatch");
    free(ct); free(pt);
    printf("AES-GCM smoke OK.
");
#else
    printf("AES-GCM not available (compile with -DUSE_OPENSSL and link -lcrypto to enable).");
#endif

    /* BLAKE2s smoke test */
    uint8_t out32[32]; if (rc_blake2s((const uint8_t*)msg, strlen(msg), out32, 32) != RAVEN_OK) panic("blake2s");
    printf("BLAKE2s OK (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x", out32[0],out32[1],out32[2],out32[3],out32[4],out32[5],out32[6],out32[7]);

    return 0;
}
