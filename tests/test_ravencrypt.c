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
    return 0;
}