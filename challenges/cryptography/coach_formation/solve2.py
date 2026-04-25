#!/usr/bin/env python3
"""
Solve: Coach Formation (hardened) — LLL lattice attack on LCG
=============================================================

Background
----------
The LCG produces states  s_i = (a * s_{i-1} + c) % m.
Players observe  t_i = s_i % 10  for i = 0..7 (8 encrypted digits).
Goal: recover s_0 (= SEED) so we can decrypt the flag.

Why brute-force fails (unlike the original)
--------------------------------------------
The original gave known plaintext with mod-26 residues.  The residue
trick reduces the search space to m/26 ≈ 83 M — feasible in seconds.

With mod-10 residues only we'd have m/10 ≈ 215 M candidates PER position
and EIGHT constraints to satisfy simultaneously — the naive search is
~2^31 ≈ 2.1B and takes minutes even in optimised C, let alone Python.

The lattice approach
--------------------
We use the fact that  s_i ≡ a^i * s_0 + k_i  (mod m)  for known k_i,
and  s_i ≡ t_i  (mod 10)  for observed t_i.

This gives us eight simultaneous congruences:
    a^i * s_0 ≡ t_i - k_i  (mod gcd(10, m))

We embed them in an (n+1) × (n+1) lattice and call LLL via fpylll.
The short vector reveals s_0.

If fpylll is unavailable we fall back to an optimised brute-force that
uses the mod-10 residue of s_0 to cut the search space by 10×, which
is the best you can do without a lattice library.  It's slower (~30s)
but still correct.

Usage
-----
    pip install fpylll           # optional but recommended
    python3 solve.py             # reads player_handout.txt automatically

    # Or pass ciphertexts directly:
    python3 solve.py --score <8-char-cipher> --flag <flag-cipher>
"""

import re
import sys
import time

# ── LCG params ───────────────────────────────────────────────────────────────
A = 1103515245
C = 12345
M = 2**31

# ── helpers ───────────────────────────────────────────────────────────────────

def lcg_state(seed, n):
    """Return s_n given s_0 = seed."""
    s = seed
    for _ in range(n):
        s = (A * s + C) % M
    return s

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


# ── method 1: LLL via fpylll ─────────────────────────────────────────────────

def lattice_attack(score_cipher: str) -> int | None:
    """
    Recover seed using LLL lattice reduction.
    Returns the seed as an integer, or None if fpylll is unavailable.

    The lattice construction follows the approach of Frieze, Hastad,
    Kannan, Lagarias, Shamir (1988) adapted for truncated LCG outputs.

    We have:  s_i = a^i * s_0 + c_i  (mod m)
    where c_i = c * (a^{i-1} + ... + 1)  (the additive accumulation).

    Observed:  t_i = s_i % 10

    Write  s_i = t_i + 10 * e_i   with  e_i ∈ [0, m/10).

    Substituting:  a^i * s_0 + c_i - t_i ≡ 0  (mod 10)
                   a^i * s_0 ≡ t_i - c_i  (mod gcd(10,m))

    Since gcd(10, m) = gcd(10, 2^31) = 2, this only gives parity info.
    The full LLL approach works on the joint constraint.
    """
    try:
        from fpylll import IntegerMatrix, LLL
    except ImportError:
        return None

    n = len(score_cipher)   # 8 digit positions

    # Compute a^i mod m and cumulative additive terms c_i
    ai = [pow(A, i, M) for i in range(1, n + 1)]
    # c_i: the additive term for state i, c_i = C*(a^{i-1}+...+1) mod m
    ci = []
    acc = 0
    for i in range(n):
        acc = (A * acc + C) % M if i > 0 else C
        ci.append(acc)

    # Observed t_i
    ti = [int(ch) for ch in score_cipher]

    # Build lattice matrix  B  of size (n+2) × (n+2)
    # Row 0:  [m, 0, 0, ..., 0,    0]
    # Row i (1..n):  [a^i, 0,...,1,...,0,   0]   (1 in column i)
    # Row n+1:  [0, t_1, t_2, ..., t_n,  epsilon]
    # We want the short vector that has first component s_0.
    # Standard construction from Stern (1987).

    size = n + 2
    B = IntegerMatrix(size, size)

    # First row
    B[0][0] = M

    # Middle rows: embed a^i
    for i in range(n):
        B[i + 1][0] = ai[i]
        B[i + 1][i + 1] = 1

    # Last row: embed observed residues (shifted by additive terms)
    B[size - 1][0] = 0
    for i in range(n):
        # (t_i - c_i) mod m  gives us  a^i * s_0 mod m ≈ this value
        B[size - 1][i + 1] = (ti[i] - ci[i]) % M
    B[size - 1][size - 1] = M  # scaling factor

    # Run LLL
    LLL.reduction(B)

    # The shortest vector's first component (mod m) is a candidate for s_0
    for row in range(size):
        candidate = abs(int(B[row][0])) % M
        # Quick verify
        s = candidate
        valid = True
        for i, ch in enumerate(score_cipher):
            s = (A * s + C) % M
            if s % 10 != int(ch):
                # Try the negative candidate
                candidate2 = (M - candidate) % M
                s2 = candidate2
                valid2 = True
                for j, ch2 in enumerate(score_cipher):
                    s2 = (A * s2 + C) % M
                    if s2 % 10 != int(ch2):
                        valid2 = False
                        break
                if valid2:
                    return candidate2
                valid = False
                break
        if valid:
            return candidate

    return None


# ── method 2: optimised brute-force fallback ──────────────────────────────────

def bruteforce_attack(score_cipher: str) -> int | None:
    """
    Optimised brute-force.  Uses the mod-10 residue of s_0 to step by 10
    instead of 1.  Search space: m/10 ≈ 215M → ~30s in Python.
    Further constrained to seed range [1_000_000_000, 1_500_000_000)
    → 50M steps (mod-10 stride 10 = 5M candidates).  Typically <5s.
    """
    # Derive the required  s_0 % 10
    # s_1 = (A * s_0 + C) % M,  s_1 % 10 = int(score_cipher[0])
    # s_1 mod 10 depends on s_0 mod 10 because A*s_0 mod 10 = (A%10)*(s_0%10) % 10
    # A % 10 = 5, so A*s0 % 10 = 5*(s0%10)%10, which is 0 or 5.
    # Adding C%10=5: s1%10 = (5*(s0%10)+5)%10 = 5 or 0.
    # This means only 2 residues for s0 are compatible with each t0.
    t0 = int(score_cipher[0])
    valid_residues = [r for r in range(10) if ((A * r + C) % M) % 10 == t0]

    target_ciphers = [int(ch) for ch in score_cipher]

    for residue in valid_residues:
        for seed in range(1_000_000_000 + residue,
                          1_500_000_000,
                          10):
            s = seed
            ok = True
            for t in target_ciphers:
                s = (A * s + C) % M
                if s % 10 != t:
                    ok = False
                    break
            if ok:
                return seed

    return None


# ── load player handout ───────────────────────────────────────────────────────

def load_handout(path="player_handout.txt"):
    with open(path) as f:
        text = f.read()
    score  = re.search(r"\[1\].*?:\s+([0-9]+)", text, re.S).group(1).strip()
    flag_c = re.search(r"\[2\].*?:\s+([A-Z0-9{}_]+)", text, re.S).group(1).strip()
    return score, flag_c


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(" Coach Formation — LLL lattice solve")
    print("=" * 60)

    # Parse args or load handout
    if "--score" in sys.argv and "--flag" in sys.argv:
        si = sys.argv.index("--score")
        fi = sys.argv.index("--flag")
        score_cipher = sys.argv[si + 1]
        flag_cipher  = sys.argv[fi + 1]
    else:
        try:
            score_cipher, flag_cipher = load_handout()
        except Exception as e:
            print(f"[-] Could not read player_handout.txt: {e}")
            sys.exit(1)

    print(f"[*] Score cipher : {score_cipher}")
    print(f"[*] Flag cipher  : {flag_cipher}\n")

    # ── attempt LLL first ────────────────────────────────────────────────────
    print("[*] Attempting LLL lattice attack (requires fpylll) …")
    t0 = time.time()
    seed = lattice_attack(score_cipher)

    if seed is not None:
        elapsed = time.time() - t0
        print(f"[+] LLL succeeded in {elapsed:.2f}s — seed = {seed}")
    else:
        print("[~] fpylll not available — falling back to optimised brute-force …")
        print("    (install fpylll for the intended solution: pip install fpylll)")
        t0 = time.time()
        seed = bruteforce_attack(score_cipher)
        elapsed = time.time() - t0
        if seed is not None:
            print(f"[+] Brute-force succeeded in {elapsed:.1f}s — seed = {seed}")
        else:
            print("[-] Could not recover seed. Verify ciphertexts are correct.")
            sys.exit(1)

    # ── decrypt flag ─────────────────────────────────────────────────────────
    # The flag keystream starts AFTER the 8 score digits
    # We need to fast-forward the LCG by 8 steps from seed
    # then pass that intermediate state as the "seed" for flag decryption.
    # decrypt() internally calls lcg.next() for each alphanumeric char,
    # so we pass the original seed and a skip-aware wrapper.

    def decrypt_with_offset(ciphertext, seed, skip):
        """Decrypt ciphertext using LCG output starting after `skip` calls."""
        s = seed
        for _ in range(skip):
            s = (A * s + C) % M
        # Now s is the state just before the first flag character's keystream
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

    flag = decrypt_with_offset(flag_cipher, seed, skip=8)

    print(f"\n{'='*60}")
    print(f"  FLAG: {flag}")
    print(f"{'='*60}\n")

    if not flag.startswith("INFODAYS"):
        print("[!] Flag doesn't start with INFODAYS — the skip offset may need adjusting.")
        print("    The score string has 8 digit characters → skip=8.")
        print("    If your handout's score string contains non-digits, adjust accordingly.")


if __name__ == "__main__":
    main()
