#include "ravencrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main(int argc, char **argv) {
    rc_init(); uint8_t key[32]; rc_random_bytes(key,32);
    size_t len = 1024*1024; uint8_t *in = malloc(len); uint8_t *out = malloc(len);
    rc_random_bytes(in, len);
    uint8_t nonce[12]; rc_random_bytes(nonce,12);
    uint8_t tag[16];
    clock_t t0 = clock();
    rc_aead_encrypt(key, nonce, NULL,0, in, len, out, tag);
    clock_t t1 = clock(); double secs = (double)(t1 - t0)/CLOCKS_PER_SEC;
    printf("ChaCha20-Poly1305 encrypt %zu bytes in %.6fs -> %.2f MB/s", len, secs, (len/1024.0/1024.0)/secs);
#ifdef USE_OPENSSL
    uint8_t aes_key[32]; rc_random_bytes(aes_key,32);
    t0 = clock(); rc_aes_gcm_encrypt(aes_key,32,nonce,NULL,0,in,len,out,tag); t1 = clock(); secs = (double)(t1 - t0)/CLOCKS_PER_SEC;
    printf("AES-GCM encrypt %zu bytes in %.6fs -> %.2f MB/s
", len, secs, (len/1024.0/1024.0)/secs);
#endif
    free(in); free(out);
    return 0;
}
