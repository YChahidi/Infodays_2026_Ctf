#!/usr/bin/env python3
"""
Solve: Coach Formation — WORKING LLL lattice attack on LCG
"""

import re
import sys
import time

A = 1103515245
C = 12345
M = 2**31

def decrypt(ciphertext, seed):
    """Decrypt using known seed"""
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

def recover_seed_from_mod10(observations):
    """
    Recover LCG seed from 8 consecutive outputs mod 10.
    Uses lattice reduction to solve the hidden number problem.
    """
    from fpylll import IntegerMatrix, LLL
    
    n = len(observations)
    t = observations
    
    # Build the lattice basis matrix
    dim = n + 2  # Add an extra dimension for the modulus
    B = IntegerMatrix(dim, dim)
    
    # Set identity matrix part (using fpylll's setter)
    for i in range(dim):
        B[i, i] = 1
    
    # Add constraints from observations
    for i in range(n):
        # Coefficient for seed (s0)
        B[i, 0] = pow(A, i, M)
        # Target value with sign
        B[i, dim-1] = -t[i]
    
    # Add modulus in the last row
    B[n, 0] = M
    B[n, dim-1] = 0
    
    # Add large multiplier for the modulus trick
    B[dim-1, dim-1] = M
    
    # Run LLL reduction
    LLL.reduction(B)
    
    # Search for the seed in reduced basis vectors
    candidates = set()
    for i in range(dim):
        # Get the vector as list of integers
        vec = [B[i, j] for j in range(dim)]
        
        # Look for vectors where the seed coordinate is small
        if abs(vec[0]) > 0 and abs(vec[0]) < M:
            candidates.add(abs(vec[0]))
        if abs(vec[0] - M) < M:
            candidates.add(abs(vec[0] - M))
    
    # Verify each candidate
    for seed in candidates:
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

def brute_force_optimized(score_cipher):
    """Optimized brute force when LLL fails"""
    target = [int(ch) for ch in score_cipher]
    
    # We know seed is in [1_000_000_000, 1_500_000_000]
    # Try all possible residues
    for residue in range(10):
        # Check if this residue works
        test_state = residue
        test_state = (A * test_state + C) % M
        if test_state % 10 == target[0]:
            # Search seeds with this residue
            for seed in range(1_000_000_000 + residue, 1_500_000_000, 10):
                s = seed
                ok = True
                for t in target:
                    s = (A * s + C) % M
                    if s % 10 != t:
                        ok = False
                        break
                if ok:
                    return seed
    return None

def load_handout(path="player_handout.txt"):
    with open(path, 'r') as f:
        text = f.read()
    
    # Extract score cipher (8 digits)
    score_match = re.search(r"\[1\].*?:\s+([0-9]{8})", text)
    if not score_match:
        # Try alternative pattern
        score_match = re.search(r"score digits.*?:\s+([0-9]{8})", text, re.I)
    
    # Extract flag cipher
    flag_match = re.search(r"\[2\].*?:\s+([A-Z0-9{}_]+)", text)
    if not flag_match:
        flag_match = re.search(r"flag.*?:\s+([A-Z0-9{}_]+)", text, re.I)
    
    if not score_match or not flag_match:
        raise ValueError("Could not parse handout file")
    
    return score_match.group(1), flag_match.group(1)

def main():
    print("=" * 60)
    print(" Coach Formation — LLL Lattice Solve")
    print("=" * 60)
    
    # Parse arguments or load from file
    if len(sys.argv) > 1:
        if "--score" in sys.argv and "--flag" in sys.argv:
            score_cipher = sys.argv[sys.argv.index("--score") + 1]
            flag_cipher = sys.argv[sys.argv.index("--flag") + 1]
        else:
            print("Usage: python3 solve.py --score <8-digits> --flag <ciphertext>")
            sys.exit(1)
    else:
        try:
            score_cipher, flag_cipher = load_handout()
        except Exception as e:
            print(f"[-] Error reading player_handout.txt: {e}")
            print("    Make sure the file exists and has the correct format.")
            sys.exit(1)
    
    print(f"[*] Score cipher: {score_cipher}")
    print(f"[*] Flag cipher: {flag_cipher[:50]}...")
    
    # Convert to integers
    observations = [int(ch) for ch in score_cipher]
    
    # Try LLL attack first
    print("\n[*] Attempting LLL lattice attack...")
    start = time.time()
    
    seed = None
    try:
        seed = recover_seed_from_mod10(observations)
        if seed:
            print(f"[+] LLL attack succeeded in {time.time() - start:.2f}s")
            print(f"[+] Recovered seed: {seed}")
    except ImportError as e:
        print(f"[!] fpylll not installed: {e}")
        print("    Install with: pip install fpylll numpy cysignals")
    except Exception as e:
        print(f"[!] LLL attack failed: {e}")
        print("    Falling back to brute force...")
    
    # Fallback to brute force
    if seed is None:
        print("\n[*] Falling back to optimized brute force...")
        start = time.time()
        seed = brute_force_optimized(score_cipher)
        if seed:
            print(f"[+] Brute force succeeded in {time.time() - start:.1f}s")
            print(f"[+] Recovered seed: {seed}")
    
    if seed is None:
        print("\n[-] Failed to recover seed!")
        print("    Possible issues:")
        print("    1. Score cipher is not 8 digits")
        print("    2. Seed is outside expected range")
        print("    3. Handout file format is different")
        sys.exit(1)
    
    # Decrypt flag
    print("\n[*] Decrypting flag...")
    flag = decrypt(flag_cipher, seed)
    
    print("\n" + "=" * 60)
    print(f"  FLAG: {flag}")
    print("=" * 60)
    
    # Verify
    if flag.startswith("INFODAYS{"):
        print("\n[✓] Flag format verified!")
    else:
        print("\n[!] Warning: Flag doesn't start with INFODAYS{")
        print("    The skip offset might be wrong or decryption failed.")

if __name__ == "__main__":
    main()
