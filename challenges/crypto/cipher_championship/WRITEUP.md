# cipher_championship — Writeup

**Category:** Cryptography · **Difficulty:** Insane (3 flags)

Three classical crypto attacks, one per round. Every round is
solvable with stdlib Python — no `pycryptodome` needed on the player
side, no SageMath, no z3. The point is to *recognise* the textbook
weakness in each scheme.

---

## 1. Round 1 — Half-time (Easy, repeating-key XOR)

`public/round1.txt` gives a hex ciphertext plus a hint: the plaintext
opens with the literal string `Flag: `, and the key is "somewhere
between 3 and 8 bytes."

That hint is everything. When you XOR a ciphertext byte with the
corresponding *known* plaintext byte, you get the key byte at that
position — that's the crib-drag. Since `"Flag: "` is 6 characters and
the key is ≤ 8 bytes, one XOR pass over the first 6 ciphertext bytes
leaks most of the key outright.

```python
import re
from pathlib import Path

CRIB = b"Flag: "
txt = Path("public/round1.txt").read_text()
ct = bytes.fromhex(re.search(r"ciphertext_hex = ([0-9a-f]+)", txt).group(1))

for klen in range(3, 9):
    key = bytes(ct[i] ^ CRIB[i] for i in range(min(klen, len(CRIB))))
    if len(key) < klen:
        continue
    pt = bytes(c ^ key[i % klen] for i, c in enumerate(ct))
    if pt.startswith(CRIB):
        print(klen, pt.decode())
```

For `klen=5` the plaintext decodes cleanly:

```
Flag: INFODAYS{SaamNoLimits_xor_broken_at_halftime_a7f2c409}
```

**Why it's easy:** XOR is its own inverse, and a known crib longer
than the key length is a complete break. The only "work" is trying
each key length — 6 guesses, at most.

---

## 2. Round 2 — The Away Goal (Medium, RSA e=3 cube root)

`public/round2.txt` is a textbook RSA public key: a 2048-bit `n`, a
public exponent `e = 3`, and a ciphertext `c`. The hint nudges the
player: "the message is short, e is tiny, work out what `m^e` looks
like when `m^e < n`."

If `m^3 < n`, then `c = m^3 mod n = m^3` — the modulus never actually
fires. Recovery is just `m = c^(1/3)` over the integers. Python has
no stdlib integer cube root, so we Newton-iterate:

```python
def iroot(n, k):
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y

import re
from pathlib import Path
txt = Path("public/round2.txt").read_text()
grab = lambda key: int(re.search(rf"{key} = (\d+)", txt).group(1))
n, e, c = grab("n"), grab("e"), grab("c")

m = iroot(c, 3)
assert m**3 == c
pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(pt.decode())
```

Result:

```
INFODAYS{SaamNoLimits_cube_root_away_goal_a7f2c409}
```

**Why it's medium:** the attack itself is one line (`iroot(c, 3)`),
but the player has to recognise that `e=3` plus a short plaintext is
the textbook Håstad / "small-exponent" red flag. Standard RSA with
padding (OAEP, PKCS#1 v1.5) is immune — textbook RSA isn't.

---

## 3. Round 3 — Lifting the Trophy (Hard, Wiener's attack)

`public/round3.txt` has a 1024-bit `n`, a suspiciously *huge* `e`
(almost the full size of `n`), and a ciphertext `c`. The hint calls
out the relevant observation: "notice how big `e` is relative to
`n`."

A large `e` implies a small `d` (they're inverses mod `phi`). When
`d < n^(1/4) / 3`, Wiener's 1990 attack recovers `d` from the
continued-fraction expansion of `e/n`: one of the convergents `k/d`
has denominator exactly equal to the private exponent.

The verification step is the key to knowing *which* convergent is
right: for each candidate `(k, d)` we compute `phi = (e*d - 1) / k`,
then check whether `x^2 - (n - phi + 1)*x + n = 0` has integer roots
(those roots would be `p` and `q`). If yes, we've found the right
convergent.

```python
from math import isqrt

def wiener(e, n):
    a, b = e, n
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b

    h_prev, h_cur = 0, 1
    k_prev, k_cur = 1, 0
    for ai in cf:
        h_prev, h_cur = h_cur, ai * h_cur + h_prev
        k_prev, k_cur = k_cur, ai * k_cur + k_prev
        k, d = h_cur, k_cur
        if k == 0 or d == 1 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s*s - 4*n
        if disc < 0:
            continue
        r = isqrt(disc)
        if r*r == disc and (s + r) % 2 == 0:
            return d
    return None

import re
from pathlib import Path
txt = Path("public/round3.txt").read_text()
grab = lambda key: int(re.search(rf"{key} = (\d+)", txt).group(1))
n, e, c = grab("n"), grab("e"), grab("c")

d = wiener(e, n)
m = pow(c, d, n)
print(m.to_bytes((m.bit_length() + 7) // 8, "big").decode())
```

Result:

```
INFODAYS{SaamNoLimits_wiener_raised_the_trophy_a7f2c409}
```

**Why it's hard:** the player has to *recognise* that a huge `e` is
the diagnostic for a small `d`, then either implement Wiener from
scratch or know the right library call. The continued-fraction
machinery isn't hard, but it's not something you stumble into — you
have to know the attack exists. This is the classic "ready reference"
crypto skill: spotting the textbook weakness in 30 seconds instead of
30 minutes.

---

## 4. Full solve run

```bash
$ python3 solver/solve_r1.py
[+] recovered key  : b'N\x10\xb9\xea\x90'  (len=5)
[+] plaintext      : Flag: INFODAYS{SaamNoLimits_xor_broken_at_halftime_a7f2c409}

$ python3 solver/solve_r2.py
[+] plaintext: INFODAYS{SaamNoLimits_cube_root_away_goal_a7f2c409}

$ python3 solver/solve_r3.py
[+] recovered d    : 959121650421189014070806076147160115740224942302236814224285  (200 bits)
[+] plaintext      : INFODAYS{SaamNoLimits_wiener_raised_the_trophy_a7f2c409}
```

All three flags captured. Championship won.

---

## 5. Why Insane

- **Three unrelated attack surfaces in one challenge.** XOR crib,
  small-exponent RSA, and Wiener's attack have essentially nothing
  in common beyond the word "crypto" — a player strong in one may be
  weak in another.
- **Each round is its own ecosystem.** There's no shared key, no
  side-channel between rounds, no multi-stage reduction. You can't
  shortcut round 3 by breaking round 1.
- **Pure stdlib solvers.** No SageMath, no pycryptodome on the player
  side — if you know the math, you can write it in Python by hand.
  The bar is *knowledge*, not tooling.
- **Dynamic flags.** Every `gen.py` run randomises the XOR key, RSA
  primes, Wiener exponent, and flag hex suffix. Nothing worth
  memorising across attempts.

## 6. Related techniques

- Crib-drag XOR: picoCTF "basic-mod", CryptoHack "XOR / Starter",
  classic Vigenère analysis.
- Small-exponent RSA: Håstad broadcast attack, Franklin-Reiter related
  message attack, Coppersmith short-pad attack.
- Wiener's attack: CryptoHack "Wiener's Revenge", FLARE-On past
  challenges, every serious intro-cryptanalysis course.

## 7. References

- M. J. Wiener, *Cryptanalysis of Short RSA Secret Exponents*, IEEE
  Transactions on Information Theory, 1990.
- J. Håstad, *Solving Simultaneous Modular Equations of Low Degree*,
  SIAM Journal on Computing, 1988.
- Dan Boneh, *Twenty Years of Attacks on the RSA Cryptosystem*,
  Notices of the AMS, 1999 — survey covering both e=3 and small-d
  attacks.
