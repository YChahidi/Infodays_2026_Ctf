#!/usr/bin/env python3
"""
Solve: Coach Formation — LLL lattice attack on LCG
"""

import re
import sys
import time

A = 1103515245
C = 12345
M = 2**31

def decrypt(ciphertext, seed):
    s = seed
    out = []
    for ch in ciphertext:
        if ch.isalpha() or ch.isdigit():
            s = (A * s + C) % M
            if ch.isalpha():
                ks = s % 26
                base = ord('A') if ch.isupper() else ord('a')
                out.append(chr((ord(ch) - base - ks) % 26 + base))
            else:
                ks = s % 10
                out.append(str((int(ch) - ks) % 10))
        else:
            out.append(ch)
    return ''.join(out)

def lattice_attack(score_cipher):
    """LLL lattice attack - tries all candidates from reduced basis"""
    try:
        from fpylll import IntegerMatrix, LLL
    except ImportError:
        return None
    
    n = len(score_cipher)
    t = [int(ch) for ch in score_cipher]
    
    # Build lattice
    dim = n + 1
    B = IntegerMatrix(dim, dim)
    
    for i in range(dim):
        B[i, i] = 1
    
    for i in range(n):
        B[i, 0] = pow(A, i, M)
        B[i, i+1] = 10
        # Compute cumulative constant
        const = 0
        for j in range(i):
            const = (const + pow(A, j, M)) % M
        const = (const * C) % M
        B[i, dim-1] = (const - t[i]) % M
    
    B[n, 0] = M
    
    LLL.reduction(B)
    
    # Try ALL rows and combinations
    candidates = set()
    for i in range(dim):
        for j in range(dim):
            cand = abs(B[i, j]) % M
            if 0 < cand < M:
                candidates.add(cand)
            # Also try with modulus
            cand2 = (M - cand) % M
            if 0 < cand2 < M:
                candidates.add(cand2)
    
    # Try each candidate
    for seed in sorted(candidates):
        s = seed
        valid = True
        for expected in t:
            s = (A * s + C) % M
            if s % 10 != expected:
                valid = False
                break
        if valid:
            return seed
    
    return None

def bruteforce_attack(score_cipher):
    """Optimized brute force with progress indicator"""
    target = [int(ch) for ch in score_cipher]
    t0 = target[0]
    
    # Find valid residues for seed mod 10
    valid_residues = []
    for r in range(10):
        s1 = (A * r + C) % M
        if s1 % 10 == t0:
            valid_residues.append(r)
    
    print(f"[*] Valid residues: {valid_residues}")
    
    for residue in valid_residues:
        print(f"[*] Trying residue {residue}...")
        start = 1_000_000_000 + residue
        total = (1_500_000_000 - start) // 10
        count = 0
        
        for seed in range(start, 1_500_000_000, 10):
            count += 1
            if count % 5_000_000 == 0:
                print(f"    Progress: {count}/{total} ({count*100/total:.1f}%)")
            
            s = seed
            ok = True
            for t_val in target:
                s = (A * s + C) % M
                if s % 10 != t_val:
                    ok = False
                    break
            if ok:
                return seed
    return None

def load_handout(path="player_handout.txt"):
    with open(path) as f:
        text = f.read()
    score = re.search(r"\[1\].*?:\s+([0-9]+)", text, re.S).group(1).strip()
    flag_c = re.search(r"\[2\].*?:\s+([A-Z0-9{}_]+)", text, re.S).group(1).strip()
    return score, flag_c

def main():
    print("=" * 60)
    print(" Coach Formation — LLL lattice solve")
    print("=" * 60)
    
    if "--score" in sys.argv and "--flag" in sys.argv:
        si = sys.argv.index("--score")
        fi = sys.argv.index("--flag")
        score_cipher = sys.argv[si + 1]
        flag_cipher = sys.argv[fi + 1]
    else:
        try:
            score_cipher, flag_cipher = load_handout()
        except Exception as e:
            print(f"[-] Could not read player_handout.txt: {e}")
            sys.exit(1)
    
    print(f"[*] Score cipher : {score_cipher}")
    print(f"[*] Flag cipher  : {flag_cipher}\n")
    
    # Try LLL
    print("[*] Attempting LLL lattice attack...")
    t0 = time.time()
    seed = lattice_attack(score_cipher)
    
    if seed is not None:
        elapsed = time.time() - t0
        print(f"[+] LLL succeeded in {elapsed:.2f}s — seed = {seed}")
    else:
        print("[*] LLL failed, falling back to brute force...")
        print("[*] This may take 30-60 seconds...")
        t0 = time.time()
        seed = bruteforce_attack(score_cipher)
        if seed is not None:
            elapsed = time.time() - t0
            print(f"[+] Brute force succeeded in {elapsed:.1f}s — seed = {seed}")
        else:
            print("[-] Could not recover seed.")
            sys.exit(1)
    
    # Decrypt flag - skip the 8 score digits
    s = seed
    for _ in range(8):
        s = (A * s + C) % M
    
    flag = decrypt(flag_cipher, s)
    
    print(f"\n{'='*60}")
    print(f"  FLAG: {flag}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
