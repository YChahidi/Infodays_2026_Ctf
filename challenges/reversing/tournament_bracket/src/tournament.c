/*
 * Infodays 2026 — Tournament Bracket
 *
 * A three-round gauntlet. Each round unlocks a flag if you supply the
 * correct passphrase. Three flags total.
 *
 *   Round 1 (Group Stage)  — XOR check against a static key
 *   Round 2 (Knockout)     — custom bytecode VM
 *   Round 3 (Final)        — linear constraint system
 *
 * Flags are XOR-encrypted in .rodata with the round passphrase as the
 * key. You cannot read them with `strings`. You have to solve.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* === GENERATED — do not edit by hand === */
static const unsigned char R1_KEY[] = {
    0x8e,0x69,0xb9,0xcb,0x66,0x30,0x40,0x08,0xf6,0xcf,0x13,0x3f,
    0x0c,0xf4,
};
static const int R1_KEY_LEN = sizeof(R1_KEY);
static const unsigned char R1_TGT[] = {
    0xfa,0x00,0xd2,0xa2,0x39,0x44,0x21,0x63,0x97,0x90,0x71,0x5e,
    0x6e,0x8d,
};
static const int R1_TGT_LEN = sizeof(R1_TGT);
static const unsigned char FLAG1_ENC[] = {
    0x3d,0x27,0x2d,0x26,0x1b,0x35,0x38,0x38,0x1a,0x0c,0x03,0x00,
    0x0f,0x37,0x1b,0x25,0x02,0x04,0x36,0x00,0x12,0x34,0x06,0x2d,
    0x0d,0x14,0x12,0x26,0x07,0x1d,0x0a,0x0e,0x3a,0x2b,0x12,0x1e,
    0x13,0x29,0x0b,0x17,0x07,0x1d,0x2b,0x08,0x5c,0x0f,0x6d,0x17,
    0x55,0x5b,0x58,0x22,
};
static const int FLAG1_ENC_LEN = sizeof(FLAG1_ENC);

static const unsigned char VM_PROG[] = {
    0x01,0x00,0x03,0x00,0x01,0x73,0x05,0x01,0x9f,0x04,0x01,0x7a,
    0x07,0x08,0x03,0x01,0x01,0x42,0x05,0x01,0x29,0x04,0x01,0x98,
    0x07,0x08,0x03,0x02,0x01,0x64,0x05,0x01,0xba,0x04,0x01,0x63,
    0x07,0x08,0x03,0x03,0x01,0xc6,0x05,0x01,0x43,0x04,0x01,0x79,
    0x07,0x08,0x03,0x04,0x01,0xb3,0x05,0x01,0xa7,0x04,0x01,0xbf,
    0x07,0x08,0x03,0x05,0x01,0x56,0x05,0x01,0x45,0x04,0x01,0xf0,
    0x07,0x08,0x03,0x06,0x01,0x9d,0x05,0x01,0xfa,0x04,0x01,0xf6,
    0x07,0x08,0x03,0x07,0x01,0xfa,0x05,0x01,0x54,0x04,0x01,0x3c,
    0x07,0x08,0x03,0x08,0x01,0x06,0x05,0x01,0x4f,0x04,0x01,0x24,
    0x07,0x08,0x03,0x09,0x01,0xb2,0x05,0x01,0x56,0x04,0x01,0x47,
    0x07,0x08,0x03,0x0a,0x01,0x82,0x05,0x01,0x86,0x04,0x01,0x6f,
    0x07,0x08,0x03,0x0b,0x01,0x04,0x05,0x01,0x65,0x04,0x01,0x16,
    0x07,0x08,0x09,
};
static const int VM_PROG_LEN = sizeof(VM_PROG);
static const unsigned char FLAG2_ENC[] = {
    0x3b,0x21,0x33,0x3b,0x21,0x1e,0x36,0x3d,0x1e,0x0c,0x06,0x0e,
    0x1f,0x21,0x1a,0x38,0x0c,0x32,0x06,0x1a,0x16,0x00,0x0c,0x01,
    0x1d,0x0c,0x1e,0x1b,0x10,0x2b,0x30,0x0c,0x09,0x30,0x10,0x30,
    0x1e,0x0e,0x1b,0x10,0x00,0x3b,0x30,0x0f,0x52,0x39,0x55,0x0c,
    0x46,0x5f,0x4c,0x09,
};
static const int FLAG2_ENC_LEN = sizeof(FLAG2_ENC);

static const int R3_COEF[16][3] = {
    {99, 151, 20},
    {148, 66, 80},
    {166, 18, 174},
    {66, 153, 79},
    {100, 133, 150},
    {195, 32, 109},
    {44, 116, 125},
    {140, 84, 155},
    {33, 174, 176},
    {95, 116, 186},
    {136, 57, 43},
    {97, 70, 118},
    {81, 21, 166},
    {63, 129, 49},
    {68, 76, 53},
    {85, 25, 25},
};
static const unsigned int R3_TGT[16] = {
    28239u,
    31408u,
    38102u,
    31695u,
    42878u,
    39136u,
    30219u,
    41095u,
    42307u,
    43588u,
    25766u,
    31867u,
    27829u,
    27378u,
    22920u,
    15685u,
};
static const unsigned char FLAG3_ENC[] = {
    0x39,0x2b,0x28,0x2e,0x28,0x35,0x20,0x0c,0x08,0x3b,0x0e,0x0e,
    0x19,0x21,0x1a,0x38,0x19,0x08,0x07,0x15,0x1f,0x2b,0x0b,0x3e,
    0x1a,0x1b,0x0a,0x0b,0x2b,0x1b,0x1d,0x11,0x2f,0x11,0x1c,0x0e,
    0x1c,0x1c,0x00,0x00,0x12,0x5f,0x09,0x5d,0x17,0x5b,0x45,0x4d,
    0x0d,
};
static const int FLAG3_ENC_LEN = sizeof(FLAG3_ENC);

static void print_decoded(const unsigned char *enc, int n,
                          const unsigned char *key, int klen) {{
    for (int i = 0; i < n; i++) {{
        putchar(enc[i] ^ key[i % klen]);
    }}
    putchar('\n');
}}

static int check_round1(const char *inp) {{
    int n = R1_KEY_LEN;
    if ((int)strlen(inp) < n) return 0;
    for (int i = 0; i < n; i++) {{
        unsigned char b = (unsigned char)inp[i];
        if ((b ^ R1_KEY[i]) != R1_TGT[i]) return 0;
    }}
    return 1;
}}

static int run_vm(const char *inp) {{
    unsigned char st[256];
    int sp = 0;
    int pc = 0;
    while (pc < VM_PROG_LEN) {{
        unsigned char op = VM_PROG[pc++];
        switch (op) {{
        case 0x01: st[sp++] = VM_PROG[pc++]; break;
        case 0x03: {{
            int idx = VM_PROG[pc++];
            st[sp++] = (unsigned char)inp[idx];
            break;
        }}
        case 0x04: {{
            unsigned char a = st[--sp];
            unsigned char b = st[--sp];
            st[sp++] = a ^ b;
            break;
        }}
        case 0x05: {{
            unsigned char a = st[--sp];
            unsigned char b = st[--sp];
            st[sp++] = (unsigned char)(a + b);
            break;
        }}
        case 0x07: {{
            unsigned char a = st[--sp];
            unsigned char b = st[--sp];
            st[sp++] = (a != b) ? 1 : 0;
            break;
        }}
        case 0x08: {{
            unsigned char a = st[--sp];
            unsigned char b = st[--sp];
            st[sp++] = a | b;
            break;
        }}
        case 0x09:
            return (sp > 0 && st[sp - 1] == 0);
        default:
            return 0;
        }}
    }}
    return 0;
}}

static int check_round2(const char *inp) {{
    if ((int)strlen(inp) < 12) return 0;
    return run_vm(inp);
}}

static int check_round3(const char *inp) {{
    if ((int)strlen(inp) < 16) return 0;
    for (int i = 0; i < 16; i++) {{
        unsigned int s = 0;
        s += (unsigned int)R3_COEF[i][0] * (unsigned char)inp[i];
        s += (unsigned int)R3_COEF[i][1] * (unsigned char)inp[(i + 1) % 16];
        s += (unsigned int)R3_COEF[i][2] * (unsigned char)inp[(i + 7) % 16];
        if (s != R3_TGT[i]) return 0;
    }}
    return 1;
}}

int main(void) {{
    char buf[256];

    puts("================================================");
    puts(" Infodays 2026 - Tournament Bracket");
    puts(" Three rounds. Three flags. One binary.");
    puts("================================================");

    printf("\n[Round 1: Group Stage] Passphrase: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (!check_round1(buf)) {{
        puts("[X] Knocked out in the group stage.");
        return 1;
    }}
    printf("[+] Flag 1: ");
    print_decoded(FLAG1_ENC, FLAG1_ENC_LEN,
                  (unsigned char *)buf, (int)strlen(buf));

    printf("\n[Round 2: Knockout] Passphrase: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (!check_round2(buf)) {{
        puts("[X] Eliminated in the knockout round.");
        return 1;
    }}
    printf("[+] Flag 2: ");
    print_decoded(FLAG2_ENC, FLAG2_ENC_LEN,
                  (unsigned char *)buf, (int)strlen(buf));

    printf("\n[Round 3: Final] Passphrase: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (!check_round3(buf)) {{
        puts("[X] Lost in the final.");
        return 1;
    }}
    printf("[+] Flag 3: ");
    print_decoded(FLAG3_ENC, FLAG3_ENC_LEN,
                  (unsigned char *)buf, (int)strlen(buf));

    puts("\n[*] You raised the trophy. Well played.");
    return 0;
}}
