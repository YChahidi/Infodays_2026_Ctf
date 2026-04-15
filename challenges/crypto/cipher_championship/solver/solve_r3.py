#!/usr/bin/env python3
"""
Round 3 solver — RSA with a small private exponent (Wiener's attack).

When d < n^(1/4) / 3, the fraction e/n has a continued-fraction
convergent k/d whose denominator is exactly the private exponent.
For each convergent we test whether (e*d - 1) is divisible by k
(giving a candidate phi = (e*d - 1) / k) and whether the implied
quadratic x^2 - ((n - phi) + 1)*x + n = 0 has integer roots — those
roots are p and q. On success we have d directly and decrypt c^d mod n.
"""

import re
import sys
from math import isqrt
from pathlib import Path


def cf_expand(a: int, b: int):
    """Yield the continued-fraction coefficients of a/b."""
    while b:
        q, r = divmod(a, b)
        yield q
        a, b = b, r


def convergents(cf):
    """Yield (h, k) convergents given a list of CF coefficients."""
    h_prev, h_cur = 0, 1
    k_prev, k_cur = 1, 0
    for a in cf:
        h_prev, h_cur = h_cur, a * h_cur + h_prev
        k_prev, k_cur = k_cur, a * k_cur + k_prev
        yield h_cur, k_cur


def wiener(e: int, n: int) -> int | None:
    cf = list(cf_expand(e, n))
    for k, d in convergents(cf):
        if k == 0 or d == 1:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # x^2 - s*x + n = 0  where s = n - phi + 1
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = isqrt(disc)
        if r * r != disc:
            continue
        if (s + r) % 2 == 0:
            return d
    return None


def parse(txt: str) -> tuple[int, int, int]:
    def grab(key: str) -> int:
        m = re.search(rf"{key}\s*=\s*([0-9]+)", txt)
        if not m:
            raise SystemExit(f"[-] {key} not found in round3.txt")
        return int(m.group(1))

    return grab("n"), grab("e"), grab("c")


def main() -> int:
    here = Path(__file__).resolve().parent
    txt = (here.parent / "public" / "round3.txt").read_text()
    n, e, c = parse(txt)

    d = wiener(e, n)
    if d is None:
        print("[-] Wiener's attack failed — d is outside the bound", file=sys.stderr)
        return 1
    print(f"[+] recovered d    : {d}  ({d.bit_length()} bits)")

    m = pow(c, d, n)
    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print(f"[+] plaintext      : {pt.decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
