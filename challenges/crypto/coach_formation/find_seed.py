#!/usr/bin/env python3
"""
Find seed by brute forcing plaintext score
"""

A = 1103515245
C = 12345
M = 2**31

cipher = "70440327"
cipher_digits = [int(c) for c in cipher]

# Score is likely between 0 and 99,999,999 (8 digits)
print("Searching for plaintext score that yields seed in 1B-1.5B range...")
print("This will take a few minutes...")

found_seed = None
found_plain = None

# Try all possible 8-digit plaintext scores (0 to 99,999,999)
for plain_num in range(0, 100_000_000):
    if plain_num % 5_000_000 == 0:
        print(f"  Progress: {plain_num/1_000_000:.1f}M / 100M")
    
    plain = f"{plain_num:08d}"
    plain_digits = [int(p) for p in plain]
    
    # Recover keystream
    keystream = [(c - p) % 10 for c, p in zip(cipher_digits, plain_digits)]
    
    # Now find seed that produces this keystream
    # We need s1 % 10 = keystream[0]
    # s2 % 10 = keystream[1], etc.
    
    # We can solve using the same search but with target = keystream
    # Use residue method
    possible_residues = []
    for r in range(10):
        if ((A * r + C) % M) % 10 == keystream[0]:
            possible_residues.append(r)
    
    for residue in possible_residues:
        # Search in the specified range
        start = ((1_000_000_000 - residue + 9) // 10) * 10 + residue
        for seed in range(start, 1_500_000_000, 10):
            s = seed
            valid = True
            for expected in keystream:
                s = (A * s + C) % M
                if s % 10 != expected:
                    valid = False
                    break
            if valid:
                found_seed = seed
                found_plain = plain
                break
        if found_seed:
            break
    
    if found_seed:
        break

if found_seed:
    print(f"\n[+] SUCCESS!")
    print(f"Plaintext score: {found_plain}")
    print(f"Keystream: {[(c - p) % 10 for c, p in zip(cipher_digits, [int(x) for x in found_plain])]}")
    print(f"Seed: {found_seed}")
else:
    print("\n[-] No plaintext found that yields seed in 1B-1.5B range")
