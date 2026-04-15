#!/usr/bin/env python3
"""
Round 2 solver — textbook RSA with e=3 and no padding.

The message is short enough that m^3 < n, so the modular reduction
never fires: c == m^3. Take the integer cube root of c and convert
the result back to bytes.
"""

import re
import sys
from pathlib import Path


def iroot(n: int, k: int) -> int:
    """Integer k-th root via Newton's method. Returns floor(n**(1/k))."""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def parse(txt: str) -> tuple[int, int, int]:
    def grab(key: str) -> int:
        m = re.search(rf"{key}\s*=\s*([0-9]+)", txt)
        if not m:
            raise SystemExit(f"[-] {key} not found in round2.txt")
        return int(m.group(1))

    return grab("n"), grab("e"), grab("c")


def main() -> int:
    here = Path(__file__).resolve().parent
    txt = (here.parent / "public" / "round2.txt").read_text()
    n, e, c = parse(txt)
    assert e == 3, f"expected e=3, got e={e}"

    m = iroot(c, 3)
    if m ** 3 != c:
        print("[-] cube root is not exact — m^3 wrapped n after all", file=sys.stderr)
        return 1

    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print(f"[+] plaintext: {pt.decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
