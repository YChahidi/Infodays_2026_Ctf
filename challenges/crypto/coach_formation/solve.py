#!/usr/bin/env python3
import re
import sys

# LCG parameters
a = 1103515245
c = 12345
m = 2**31

def extract_keystream(plain, cipher):
    ks = []
    # IMPORTANT: Only extract for alphanumeric chars to match generator's lcg.next() calls
    for p, ciph in zip(plain, cipher):
        if p.isalpha():
            ks.append(("A", (ord(ciph.upper()) - ord(p.upper())) % 26))
        elif p.isdigit():
            ks.append(("D", (int(ciph) - int(p)) % 10))
    return ks

def check_seed_fast(seed, ks):
    state = seed
    for typ, val in ks[:10]: # Check first 10 for a solid match
        state = (a * state + c) % m
        if typ == "A":
            if state % 26 != val: return False
        else:
            if state % 10 != val: return False
    return True

def decrypt(ciphertext, seed):
    state = seed
    out = []
    for ch in ciphertext:
        if ch.isalpha() or ch.isdigit():
            state = (a * state + c) % m
            if ch.isalpha():
                ks_val = state % 26
                base = ord('A') if ch.isupper() else ord('a')
                out.append(chr((ord(ch) - base - ks_val) % 26 + base))
            else:
                ks_val = state % 10
                out.append(str((int(ch) - ks_val) % 10))
        else:
            out.append(ch)
    return ''.join(out)

# ===== LOAD DATA =====
try:
    with open("player_handout.txt") as f:
        content = f.read()
    msg1_cipher = re.search(r"Message 1: ([A-Z ]+)", content).group(1).strip()
    flag_cipher = re.search(r"Flag ciphertext: ([A-Z0-9{}_]+)", content).group(1).strip()
except:
    print("[-] Error reading player_handout.txt")
    sys.exit(1)

msg1_plain = "COACH USE FOUR FOUR TWO"
ks = extract_keystream(msg1_plain, msg1_cipher)

# ===== CALCULATE STARTING RESIDUE =====
# This ensures we only check seeds that satisfy (a*seed + c) % m % 26 == ks[0]
print("[*] Finding valid residue...")
residue = -1
for r in range(26):
    if ((a * r + c) % m) % 26 == ks[0][1]:
        residue = r
        break

# ===== SEARCH =====
# If the seed is outside 1.0B-1.5B, we check the full 0-2^31 range.
print(f"[*] Starting optimized search (Residue: {residue})...")
found = False
# Checking 0 to m in steps of 26
for seed in range(residue, m, 26):
    if check_seed_fast(seed, ks):
        flag = decrypt(flag_cipher, seed)
        if flag.startswith("INFODAYS"):
            print(f"\n[+] Seed found: {seed}")
            print(f"[+] FLAG: {flag}")
            found = True
            break

if not found:
    print("[-] No seed found. Check if msg1_plain matches the ciphertext exactly.")
