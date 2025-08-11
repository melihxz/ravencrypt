#include <stdio.h>
#include <string.h>
#include "ravencrypt.h"

int main() {
    const char *password = "ruhicenet123";
    const uint8_t salt[16] = {0};
    uint8_t key[32];

    if (raven_kdf_argon2((const uint8_t*)password, strlen(password), salt, sizeof(salt), key, sizeof(key)) != RAVEN_OK) {
        printf("Argon2 KDF unsuccessful!\n");
        return 1;
    }

    printf("Argon2 created keys: ");
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}
