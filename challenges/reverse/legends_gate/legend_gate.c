#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "legend_secret.h"

/* =========================
   SEED
   ========================= */
static uint32_t vm_seed() {
    uint32_t x = 0xC0FFEE;
    x ^= 3;
    x = (x << 5) | (x >> 27);
    return x;
}

/* =========================
   VM (password only)
   ========================= */
static uint8_t vm(uint8_t v, int i, uint32_t seed) {
    uint8_t k = (seed ^ (i * 0x27) ^ (i >> 2)) & 0xFF;
    return v ^ k;
}

/* =========================
   PASSWORD DECRYPT
   ========================= */
static void decrypt(uint8_t *buf, size_t len) {
    uint32_t seed = vm_seed();
    for (size_t i = 0; i < len; i++) {
        buf[i] = vm(buf[i], i, seed);
    }
}

/* =========================
   CONSTANT TIME COMPARE
   ========================= */
static int ctcmp(const char *a, const char *b, size_t n) {
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++) {
        r |= a[i] ^ b[i];
    }
    return r;
}

/* =========================
   FLAG (FIX FINAL)
   ========================= */
static void print_flag() {
    FILE *f = fopen("flag.txt", "r");
    if (!f) {
        printf("[!] Missing flag.txt\n");
        return;
    }

    char flag[128] = {0};

    if (!fgets(flag, sizeof(flag), f)) {
        fclose(f);
        return;
    }

    fclose(f);

    flag[strcspn(flag, "\n")] = 0;

    /* IMPORTANT: NO VM ON FLAG (fix corruption) */

    printf("[+] Access Granted!\n");
    printf("%s\n", flag);
}

/* =========================
   MAIN
   ========================= */
int main() {
    char input[64] = {0};

    printf("Enter code: ");
    fflush(stdout);

    if (!fgets(input, sizeof(input), stdin))
        return 1;

    input[strcspn(input, "\n")] = 0;

    uint8_t pass[PASS_LEN];
    memcpy(pass, enc_pass, PASS_LEN);

    decrypt(pass, PASS_LEN);

    if (strlen(input) == PASS_LEN &&
        ctcmp(input, (char*)pass, PASS_LEN) == 0) {

        print_flag();
    } else {
        printf("[!] Unauthorized\n");
    }

    return 0;
}
