#!/usr/bin/env python3
"""
Coach Formation - LINHART-MORAIN MODE
Run this to generate the challenge and player handout
"""

import random

class LCG:
    def __init__(self, seed, a=1103515245, c=12345, m=2**31):
        self.state = seed
        self.a = a
        self.c = c
        self.m = m

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

def encrypt(plaintext, seed):
    lcg = LCG(seed)
    ciphertext = []
    for char in plaintext:
        if char.isalpha():
            ks = lcg.next() % 26
            base = ord('A') if char.isupper() else ord('a')
            encrypted = chr((ord(char) - base + ks) % 26 + base)
            ciphertext.append(encrypted)
        elif char.isdigit():
            ks = lcg.next() % 10
            encrypted = str((int(char) + ks) % 10)
            ciphertext.append(encrypted)
        else:
            ciphertext.append(char)
    return ''.join(ciphertext)

# Generate random seed
SEED = random.randint(1000000000, 1500000000)
FLAG = "INFODAYS{L1NH4RT_M0R41N_LLL_4TT4CK_2026}"

msg1_plain = "COACH USE FOUR FOUR TWO"
msg2_plain = "PASS TO LEFT WING NOW"

msg1_cipher = encrypt(msg1_plain, SEED)
msg2_cipher = encrypt(msg2_plain, SEED)
flag_cipher = encrypt(FLAG, SEED)

# Create player handout file
handout_file = "player_handout.txt"
with open(handout_file, "w") as f:
    f.write("="*60 + "\n")
    f.write("COACH FORMATION CHALLENGE - ULTRA HARD\n")
    f.write("="*60 + "\n\n")
    f.write("You have intercepted three encrypted messages:\n\n")
    f.write(f"Message 1: {msg1_cipher}\n")
    f.write(f"Translation: {msg1_plain}\n\n")
    f.write(f"Message 2: {msg2_cipher}\n")
    f.write(f"Translation: {msg2_plain}\n\n")
    f.write(f"Flag ciphertext: {flag_cipher}\n\n")
    f.write("="*60 + "\n")
    f.write("Decrypt the flag. No hints.\n")
    f.write("="*60 + "\n")

# Also create a secret file for you
secret_file = "SECRET.txt"
with open(secret_file, "w") as f:
    f.write("="*60 + "\n")
    f.write("COACH FORMATION - SECRET (DO NOT SHARE)\n")
    f.write("="*60 + "\n\n")
    f.write(f"Seed: {SEED}\n")
    f.write(f"Flag: {FLAG}\n\n")
    f.write("Verification:\n")
    f.write(f"Message 1 decrypt: {msg1_plain}\n")
    f.write(f"Message 2 decrypt: {msg2_plain}\n")
    f.write(f"Flag decrypt: {FLAG}\n")
    f.write("="*60 + "\n")

print("="*60)
print("CHALLENGE GENERATED SUCCESSFULLY!")
print("="*60)
print(f"\n[+] Player handout saved to: {handout_file}")
print(f"[+] Secret info saved to: {secret_file}")
print("\n" + "="*60)
print("\n=== PLAYER HANDOUT (copy this) ===\n")
print(f"Message 1: {msg1_cipher}")
print(f"Message 1 means: {msg1_plain}\n")
print(f"Message 2: {msg2_cipher}")
print(f"Message 2 means: {msg2_plain}\n")
print(f"Flag ciphertext: {flag_cipher}\n")
print("="*60)
