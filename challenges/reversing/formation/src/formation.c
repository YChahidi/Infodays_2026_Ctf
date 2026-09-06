#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MEM_SIZE 256
#define MAX_STEPS 200000

typedef struct {
    uint32_t r[3];
    uint8_t mem[MEM_SIZE];
    uint16_t pc;
    int halt;
    uint64_t checksum;
} VM;

/* ================= ROTATE ================= */
static inline uint32_t rol(uint32_t v, int r) {
    return (v << r) | (v >> (32 - r));
}

/* ================= FAKE PATH ================= */
int fake_validate(uint8_t *in) {
    for (int i = 0; i < 16; i++) {
        if ((in[i] ^ 0x42) != i)
            return 0;
    }
    return 1;
}

/* ================= TRIGGER ================= */
int trigger_fake(uint8_t *in) {
    uint32_t t = 0;
    for (int i = 0; i < 16; i++)
        t ^= in[i] * (i + 1);

    return ((t ^ 0xDEADBEEF) & 1);
}

/* ================= EXPECTED GEN ================= */
void gen_expected(uint8_t *exp) {
    uint32_t seed = 0xC0FFEE;

    for (int i = 0; i < 16; i++) {
        seed = seed * 1103515245 + 12345;
        exp[i] = ((seed >> 16) ^ (i * 0x5A)) + 0x33;
    }
}

/* ================= VM PROGRAM (ENCRYPTED) ================= */
/* This is just a placeholder pattern — logic is in vm_exec */
uint8_t enc_prog[] = {
    0xAA,0xB1,0xC3,0xD4,0x91,0x22,0x13,0x37,
    0x42,0x99,0xFE,0xED,0xBE,0xEF,0x01,0x02
};

uint8_t PROGRAM[sizeof(enc_prog)];

/* ================= VM EXEC ================= */
void vm_exec(VM *vm, uint8_t *input) {
    uint8_t expected[16];
    gen_expected(expected);

    uint32_t state = 0xA5;

    for (int i = 0; i < 16; i++) {
        uint32_t x = input[i];

        /* nonlinear chain */
        x ^= state;
        x = (x * 7) + (state ^ 0x3D);
        x = rol(x, i % 5);
        x ^= (i * 11);

        state = x;

        /* accumulate checksum */
        vm->checksum ^= (uint64_t)x * 0x9e3779b97f4a7c15ULL;
        vm->checksum += (uint64_t)(state << 13);
        vm->checksum ^= (uint64_t)(i << 29);

        /* fake anti-analysis noise */
        if (((x * x + x) % 2) == (x % 2)) {
            vm->r[0] ^= x;
        }

        /* self-modifying flavor (lightweight) */
        PROGRAM[i % sizeof(PROGRAM)] ^= (uint8_t)(x & 0xFF);

        if ((x & 0xFF) != expected[i]) {
            vm->halt = 1;
            return;
        }
    }
}

/* ================= MAIN ================= */
int main() {
    char input[64];
    const char *flag = getenv("FLAG");

    if (!flag) {
        puts("FLAG not set");
        return 1;
    }

    puts("╔══════════════════════════════════════╗");
    puts("║  MOROCCO 2030 — ELITE FORMATION VM   ║");
    puts("╚══════════════════════════════════════╝");
    puts("Enter 16-byte formation:");

    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;

    if (strlen(input) != 16) {
        puts("Invalid length.");
        return 1;
    }

    uint8_t *in = (uint8_t*)input;

    /* ===== FAKE PATH ===== */
    if (trigger_fake(in)) {
        if (fake_validate(in)) {
            puts("✓ Almost... but wrong formation.");
        } else {
            puts("✗ Rejected.");
        }
        return 0;
    }

    /* ===== DECRYPT PROGRAM ===== */
    for (size_t i = 0; i < sizeof(enc_prog); i++) {
        PROGRAM[i] = enc_prog[i] ^ ((i * 7) + 0xAA);
    }

    /* ===== VM EXEC ===== */
    VM vm;
    memset(&vm, 0, sizeof(vm));

    vm_exec(&vm, in);

    /* ===== FINAL CHECK ===== */
    if (vm.checksum == 0xCAFEBABEDEADBEEF) {
        puts("✓ Elite formation accepted.");
        printf("Flag: %s\n", flag);
    } else {
        puts("✗ Formation rejected.");
    }

    return 0;
}
