#!/usr/bin/env python3
"""
Build-time generator for tournament_bracket.

Produces a fresh src/tournament.c with:
  - random 8-byte hex suffix shared across all 3 flags (per-team uniqueness)
  - randomised XOR keys / targets for round 1
  - randomised add/xor keys + VM bytecode for round 2
  - randomised linear-system coefficients + targets for round 3
  - flag bodies XOR-encrypted in .rodata against the correct passphrases

The three passphrases themselves stay constant (tiki_taka_baby / route_one_go /
penalty_shootout) so the intended-solution writeups remain valid — what
changes per build is the ENCRYPTION layer and the HEX SUFFIX baked into
each flag.

Usage:
    python3 gen.py [--hex HEX8]          # write to src/tournament.c
    python3 gen.py --print-flags         # print the three flags to stdout and exit
"""

from __future__ import annotations

import argparse
import os
import random
import secrets
import sys
from pathlib import Path

PASS1 = b"tiki_taka_baby"       # 14 bytes
PASS2 = b"route_one_go"          # 12 bytes
PASS3 = b"penalty_shootout"      # 16 bytes

HERE = Path(__file__).resolve().parent
SRC_PATH = HERE / "src" / "tournament.c"


def carr(name: str, data: bytes, w: int = 12) -> str:
    out = [f"static const unsigned char {name}[] = {{"]
    line = "    "
    for i, b in enumerate(data):
        line += f"0x{b:02x},"
        if (i + 1) % w == 0:
            out.append(line)
            line = "    "
    if line.strip():
        out.append(line)
    out.append("};")
    out.append(f"static const int {name}_LEN = sizeof({name});")
    return "\n".join(out)


def build_constants(rand_hex: str) -> tuple[str, tuple[bytes, bytes, bytes]]:
    """Return (C-block, (flag1, flag2, flag3))."""
    rng = random.Random(secrets.randbits(128))

    flag1 = f"INFODAYS{{SaamNoLimits_group_stage_survived_{rand_hex}}}".encode()
    flag2 = f"INFODAYS{{SaamNoLimits_knockout_blow_landed_{rand_hex}}}".encode()
    flag3 = f"INFODAYS{{SaamNoLimits_raised_the_trophy_{rand_hex}}}".encode()

    # Round 1: XOR check
    r1_key = bytes(rng.randint(0, 255) for _ in PASS1)
    r1_tgt = bytes(p ^ k for p, k in zip(PASS1, r1_key))
    flag1_enc = bytes(f ^ PASS1[i % len(PASS1)] for i, f in enumerate(flag1))

    # Round 2: VM bytecode
    k_add = [rng.randint(0, 255) for _ in PASS2]
    k_xor = [rng.randint(0, 255) for _ in PASS2]
    t2 = [((p + a) & 0xff) ^ x for p, a, x in zip(PASS2, k_add, k_xor)]

    prog = bytearray()
    prog += bytes([0x01, 0x00])  # PUSH 0 (acc seed)
    for i in range(len(PASS2)):
        prog += bytes([0x03, i])            # LOAD_INP i
        prog += bytes([0x01, k_add[i]])     # PUSH K_add[i]
        prog += bytes([0x05])               # ADD
        prog += bytes([0x01, k_xor[i]])     # PUSH K_xor[i]
        prog += bytes([0x04])               # XOR
        prog += bytes([0x01, t2[i]])        # PUSH T[i]
        prog += bytes([0x07])               # CMP_NE
        prog += bytes([0x08])               # OR
    prog += bytes([0x09])                   # HALT

    flag2_enc = bytes(f ^ PASS2[i % len(PASS2)] for i, f in enumerate(flag2))

    # Round 3: linear system over ASCII
    c = [(rng.randint(17, 199), rng.randint(17, 199), rng.randint(17, 199))
         for _ in range(16)]
    t3 = []
    for i in range(16):
        c0, c1, c2 = c[i]
        s = c0 * PASS3[i] + c1 * PASS3[(i + 1) % 16] + c2 * PASS3[(i + 7) % 16]
        t3.append(s)
    flag3_enc = bytes(f ^ PASS3[i % len(PASS3)] for i, f in enumerate(flag3))

    lines: list[str] = []
    lines.append("/* === GENERATED — do not edit by hand === */")
    lines.append(carr("R1_KEY", r1_key))
    lines.append(carr("R1_TGT", r1_tgt))
    lines.append(carr("FLAG1_ENC", flag1_enc))
    lines.append("")
    lines.append(carr("VM_PROG", bytes(prog)))
    lines.append(carr("FLAG2_ENC", flag2_enc))
    lines.append("")
    lines.append("static const int R3_COEF[16][3] = {")
    for ci in c:
        lines.append(f"    {{{ci[0]}, {ci[1]}, {ci[2]}}},")
    lines.append("};")
    lines.append("static const unsigned int R3_TGT[16] = {")
    for ti in t3:
        lines.append(f"    {ti}u,")
    lines.append("};")
    lines.append(carr("FLAG3_ENC", flag3_enc))

    return "\n".join(lines), (flag1, flag2, flag3)


CFILE_TEMPLATE = r"""/*
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

{CONSTANTS}

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
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", default=None, help="override the random hex suffix")
    ap.add_argument("--print-flags", action="store_true")
    ap.add_argument("--out", default=str(SRC_PATH))
    args = ap.parse_args()

    rand_hex = args.hex or secrets.token_hex(4)
    constants, flags = build_constants(rand_hex)

    if args.print_flags:
        for f in flags:
            print(f.decode())
        return 0

    source = CFILE_TEMPLATE.replace("{CONSTANTS}", constants)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(source)
    # Emit the hex and the three flags to a side-channel file the
    # entrypoint can read for logging / CTFd admin use.
    side = out.parent.parent / "state" / "flags.txt"
    side.parent.mkdir(parents=True, exist_ok=True)
    side.write_text("\n".join(f.decode() for f in flags) + "\n")
    print(f"[gen] hex={rand_hex}")
    print(f"[gen] wrote {out}")
    print(f"[gen] flags -> {side}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
