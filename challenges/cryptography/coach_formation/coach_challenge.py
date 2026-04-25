#!/usr/bin/env python3
import random

# ---------------- LCG ---------------- #
class LCG:
    def __init__(self, seed, a=1103515245, c=12345, m=2**31):
        self.state = seed
        self.a = a
        self.c = c
        self.m = m

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state


# ---------------- SAFE STREAM STEP ---------------- #
def lcg_step(x, a, c, m, k=3):
    # iterative version (stable, portable)
    for _ in range(k):
        x = (a * x + c) % m
    return x


# ---------------- ENCRYPTION ---------------- #
def encrypt(text, seed):
    a, c, m = 1103515245, 12345, 2**31

    x = seed
    out = []

    for ch in text:
        x = lcg_step(x, a, c, m, k=3)

        ks = x & 0xFFFF  # 16-bit leakage (hard mode)

        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + ks) % 26 + base))

        elif ch.isdigit():
            out.append(str((int(ch) + ks) % 10))

        else:
            out.append(ch)

    return ''.join(out)


# ---------------- FLAG ---------------- #
def read_flag():
    try:
        with open("flag.txt", "r") as f:
            return f.read().strip()
    except:
        return "INFODAYS{DEFAULT_FLAG}"


# ---------------- GENERATION ---------------- #
SEED = random.randint(1_000_000_000, 1_500_000_000)

FLAG = read_flag()
SCORE = "3107202612345678"

FLAG_CIPHER = encrypt(FLAG, SEED)
SCORE_CIPHER = encrypt(SCORE, SEED)


# ---------------- OUTPUT ---------------- #
with open("player_handout.txt", "w") as f:
    f.write(f"""
============================================================
COACH FORMATION - HARD MODE (STABLE)
============================================================

Encrypted score:
{SCORE_CIPHER}

Encrypted flag:
{FLAG_CIPHER}

LCG parameters:
a = 1103515245
c = 12345
m = 2^31

Leakage:
ks = (LCG_state & 0xFFFF)
k-step = 3 (decimated stream)

Goal:
Recover seed and decrypt flag.
============================================================
""")

with open("SECRET.txt", "w") as f:
    f.write(f"SEED: {SEED}\nFLAG: {FLAG}\n")

print("[+] Challenge generated successfully")
