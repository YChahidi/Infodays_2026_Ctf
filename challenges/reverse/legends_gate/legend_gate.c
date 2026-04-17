#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "legend_secret.h"

static uint32_t vm_seed() {
    uint32_t x = 0xC0FFEE;
    x ^= 3;
    x = (x << 5) | (x >> 27);
    return x;
}

static uint8_t vm(uint8_t v, int i, uint32_t seed) {
    uint8_t k = (seed ^ (i * 0x27) ^ (i >> 2)) & 0xFF;
    return v ^ k;
}

static void decrypt(uint8_t *buf, size_t len) {
    uint32_t seed = vm_seed();
    for (size_t i = 0; i < len; i++)
        buf[i] = vm(buf[i], i, seed);
}

static int ctcmp(const char *a, const char *b, size_t n) {
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++)
        r |= a[i] ^ b[i];
    return r;
}

int main() {
    char input[64];

    printf("Enter code: ");
    fflush(stdout);

    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;

    uint8_t pass[PASS_LEN];
    memcpy(pass, enc_pass, PASS_LEN);

    decrypt(pass, PASS_LEN);

    if (strlen(input) == PASS_LEN &&
        ctcmp(input, (char*)pass, PASS_LEN) == 0) {

        uint8_t flag[FLAG_LEN];
        memcpy(flag, enc_flag, FLAG_LEN);

        decrypt(flag, FLAG_LEN);

        printf("[+] Access Granted!\n");
        printf("%s\n", flag);
    } else {
        printf("[!] Unauthorized\n");
    }

    return 0;
}
