#!/usr/bin/env python3
import random

# ---------------- PARAMETERS ---------------- #
p = 2**31 - 1  # prime modulus (important)

a = 1103515245 % p
b = 1664525 % p
c = 12345
d = 1013904223


# ---------------- STEP FUNCTION ---------------- #
def step(x, y):
    x_new = (a * x + y + c) % p
    y_new = (b * y + x + d) % p
    return x_new, y_new


def step_k(x, y, k=3):
    for _ in range(k):
        x, y = step(x, y)
    return x, y


# ---------------- KEYSTREAM ---------------- #
def ks(x, y, prev_x):
    return (x * y + prev_x) % p


# ---------------- ENCRYPT ---------------- #
def encrypt(msg, x, y):
    out = []
    prev_x = x

    for ch in msg:
        x, y = step_k(x, y)
        k = ks(x, y, prev_x)
        prev_x = x

        # IMPORTANT FIX: store bytes, not chars
        out.append((ord(ch) + (k % 256)) % 256)

    return bytes(out), x, y


# ---------------- FLAG / SCORE ---------------- #
FLAG = "INFODAYS{FINAL_BOSS_LINEARIZED_CTF}"
SCORE = "3107202612345678"


# ---------------- SEED ---------------- #
x0 = random.randint(10**9, 2*10**9)
y0 = random.randint(10**9, 2*10**9)


# ---------------- ENCRYPT ---------------- #
score_ct, x1, y1 = encrypt(SCORE, x0, y0)
flag_ct, _, _ = encrypt(FLAG, x1, y1)


# ---------------- OUTPUT ---------------- #
with open("player_handout.txt", "w") as f:
    f.write(f"""
========================================
FINAL BOSS CTF - COUPLED NONLINEAR SYSTEM
========================================

Score cipher:
{score_ct.hex()}

Flag cipher:
{flag_ct.hex()}

Rules:
- Coupled nonlinear recurrence system
- 3-step evolution per character
- Hidden state (x, y)
- Byte-wise encryption (mod 256)

Goal:
Recover flag.

========================================
""")

print("[+] FINAL BOSS GENERATED")
