#!/usr/bin/env python3
import random

# ---------------- PARAMETERS ---------------- #
a = 1103515245
b = 1664525
c = 12345
d = 1013904223
m = 2**31


def step(x, y):
    x_new = (a * x + c + y) % m
    y_new = (b * y + d + x) % m
    return x_new, y_new


def step3(x, y):
    for _ in range(3):
        x, y = step(x, y)
    return x, y


# ---------------- ENCRYPT ---------------- #
def encrypt(text, x, y):
    out = []

    for ch in text:
        x, y = step3(x, y)

        ks = (x ^ (y >> 8)) & 0xFFFF

        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + ks) % 26 + base))

        elif ch.isdigit():
            out.append(str((int(ch) + ks) % 10))

        else:
            out.append(ch)

    return ''.join(out), x, y


# ---------------- FLAG ---------------- #
FLAG = "INFODAYS{FINAL_BOSS_LCG_CRYPTO}"


# ---------------- SEED ---------------- #
x0 = random.randint(1_000_000_000, 1_500_000_000)
y0 = random.randint(1_000_000_000, 1_500_000_000)

SCORE = "3107202612345678"

score_ct, x1, y1 = encrypt(SCORE, x0, y0)
flag_ct, _, _ = encrypt(FLAG, x1, y1)


# ---------------- OUTPUT ---------------- #
with open("player_handout.txt", "w") as f:
    f.write(f"""
============================================================
FINAL BOSS - COACH FORMATION
============================================================

Score cipher:
{score_ct}

Flag cipher:
{flag_ct}

Constraints:
- Coupled LCG system (hidden)
- 16-bit XOR-masked leakage
- 3-step evolution per character

Goal:
Recover flag.
============================================================
""")

print("[+] FINAL BOSS GENERATED")
