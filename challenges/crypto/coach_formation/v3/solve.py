#!/usr/bin/env python3

from z3 import *
from tqdm import tqdm

score_ct = bytes.fromhex("1ca45f907df73b22c5cbcebbd75dee87")
score_pt = b"3107202612345678"

MOD = 2**31 - 1

a = 1103515245 % MOD
b = 1664525 % MOD
c = 12345
d = 1013904223

n = len(score_pt)

# ---------------- SYMBOLIC STATE ---------------- #
x = [Int(f"x{i}") for i in range(n+1)]
y = [Int(f"y{i}") for i in range(n+1)]

s = Solver()

print("[*] building constraints...")

for i in tqdm(range(n)):

    # symbolic recurrence (IMPORTANT FIX)
    x_next = (a * x[i] + y[i] + c) % MOD
    y_next = (b * y[i] + x[i] + d) % MOD

    s.add(x[i+1] == x_next)
    s.add(y[i+1] == y_next)

    # correct keystream definition
    k = (x[i+1] * y[i+1] + x[i]) % MOD

    # encryption constraint
    s.add(((score_pt[i] + (k % 256)) % 256) == score_ct[i])

print("[*] solving...")

if s.check() == sat:
    m = s.model()

    print("\n[+] SAT FOUND (valid model)\n")

    print("[+] x0 =", m[x[0]])
    print("[+] y0 =", m[y[0]])

else:
    print("[-] UNSAT (check model consistency)")
