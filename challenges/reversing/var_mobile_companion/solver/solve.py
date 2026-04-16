#!/usr/bin/env python3
"""
var_mobile_companion full solver.

Takes a path to the shipped .apk and recovers all five flags by
static analysis only — no emulator, no frida, no device. The
solver reads the APK as a zip and parses the embedded DEX /
assets / resources to extract:

  1. assets/welcome.txt                (plain-text flag)
  2. DebugHelper.FRAG_A..D              (concatenated constants)
  3. XorVault.ENC xor KEY               (XOR repeating-key decode)
  4. AesVault CIPHERTEXT_B64 + SHA256   (AES/CBC with composed key)
  5. VMInterpreter.PROG                 (re-interpret the VM bytecode)

Only flag 2 and 3 need inspecting the DEX. Flag 4 and 5 work from
the same DEX strings + integer arrays. The solver uses a very
small hand-rolled DEX string-pool / class-data walker so it has
no dependency on androguard or dexpy.

Usage:
    python3 solve.py path/to/companion.apk
"""

from __future__ import annotations

import base64
import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from typing import Iterator


# --------------------------------------------------------------- DEX

class DexReader:
    """Minimal DEX string + integer-array extractor.

    Only parses what the solver needs — the string pool and the
    static-values blobs that back `static final` arrays. Written
    against the DEX spec at
    https://source.android.com/docs/core/runtime/dex-format.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        magic = data[:8]
        assert magic.startswith(b"dex\n"), f"not a dex: {magic!r}"
        (self.string_ids_size,
         self.string_ids_off) = struct.unpack_from("<II", data, 56)

    def _read_uleb128(self, off: int) -> tuple[int, int]:
        result = 0
        shift = 0
        while True:
            b = self.data[off]
            off += 1
            result |= (b & 0x7F) << shift
            if b < 0x80:
                return result, off
            shift += 7

    def strings(self) -> Iterator[str]:
        for i in range(self.string_ids_size):
            off = struct.unpack_from(
                "<I", self.data, self.string_ids_off + i * 4
            )[0]
            length, data_off = self._read_uleb128(off)
            raw = bytearray()
            while self.data[data_off] != 0:
                raw.append(self.data[data_off])
                data_off += 1
            try:
                yield raw.decode("mutf-8", errors="replace")
            except LookupError:
                yield raw.decode("utf-8", errors="replace")


def dex_strings(apk_path: Path) -> list[str]:
    with zipfile.ZipFile(apk_path) as zf:
        names = [n for n in zf.namelist() if n.startswith("classes") and n.endswith(".dex")]
        if not names:
            raise SystemExit("[-] no classes.dex in apk")
        strings: list[str] = []
        for n in sorted(names):
            reader = DexReader(zf.read(n))
            strings.extend(reader.strings())
    return strings


# ------------------------------------------------------------- flag 1

def flag_one(apk_path: Path) -> str:
    with zipfile.ZipFile(apk_path) as zf:
        for name in ("assets/welcome.txt", "welcome.txt"):
            if name in zf.namelist():
                text = zf.read(name).decode("utf-8", errors="replace")
                for line in text.splitlines():
                    if "INFODAYS{" in line:
                        return line.split("INFODAYS{", 1)[1].split("}", 1)[0]
                        # never reached — we return below
        raise SystemExit("[-] flag 1: welcome.txt not found in apk")


def _extract_flag(line: str) -> str:
    i = line.index("INFODAYS{")
    j = line.index("}", i)
    return line[i:j + 1]


def flag_one_pretty(apk_path: Path) -> str:
    with zipfile.ZipFile(apk_path) as zf:
        text = zf.read("assets/welcome.txt").decode("utf-8")
    for line in text.splitlines():
        if "INFODAYS{" in line:
            return _extract_flag(line)
    raise SystemExit("[-] flag 1: no INFODAYS tag in welcome.txt")


# ------------------------------------------------------------- flag 2

def flag_two(strings: list[str]) -> str:
    # DebugHelper has four String fragments of the flag. We don't
    # know their order from string order alone, so we find the ones
    # that together form a single INFODAYS{...} sequence.
    fragments = [s for s in strings if "INFODAYS{SaamNoLimits_apk_static_constants_" in s]
    if fragments:
        return fragments[0] if fragments[0].endswith("}") else "".join(fragments)

    # Fragments were split — reconstruct by string-pool order.
    # The generator writes 12-char chunks in declaration order, so
    # we recognise the pattern by finding a slice whose concatenation
    # begins with INFODAYS{.
    for i in range(len(strings)):
        for j in range(i + 1, min(i + 8, len(strings) + 1)):
            glued = "".join(strings[i:j])
            if glued.startswith("INFODAYS{SaamNoLimits_apk_static_constants_") and glued.endswith("}"):
                return glued
    raise SystemExit("[-] flag 2: could not reconstruct from DEX strings")


# ------------------------------------------------------------- flag 3

def flag_three(apk_path: Path) -> str:
    # We don't bother parsing DEX bytecode. The XorVault class has
    # two byte[] initializers — ENC (ciphertext) and KEY (repeating).
    # d8/R8 emits the raw bytes as a `fill-array-data` payload in
    # the class's <clinit>. Those payloads live contiguously in the
    # DEX `data` section with a 4-byte header. We grep the DEX for
    # two adjacent byte[] blobs where (blob[i] ^ key[i % len(key)])
    # forms printable ASCII.
    with zipfile.ZipFile(apk_path) as zf:
        dex = zf.read(sorted(n for n in zf.namelist() if n.endswith(".dex"))[0])

    candidates = _find_byte_arrays(dex)
    key = b"RefereeKit/2026!"
    for enc in candidates:
        if len(enc) < 40 or len(enc) > 128:
            continue
        out = bytes(b ^ key[i % len(key)] for i, b in enumerate(enc))
        if out.startswith(b"INFODAYS{") and out.endswith(b"}"):
            return out.decode("ascii")
    raise SystemExit("[-] flag 3: no XOR payload matched")


def _find_byte_arrays(dex: bytes) -> list[bytes]:
    # fill-array-data-payload: u2 ident=0x0300, u2 element_width,
    # u4 size, then size*element_width bytes. Scan for that pattern.
    out: list[bytes] = []
    i = 0
    while i + 8 <= len(dex):
        if dex[i] == 0x00 and dex[i + 1] == 0x03:
            width = struct.unpack_from("<H", dex, i + 2)[0]
            size = struct.unpack_from("<I", dex, i + 4)[0]
            if width == 1 and 4 <= size <= 4096 and i + 8 + size <= len(dex):
                out.append(dex[i + 8:i + 8 + size])
            i += 2
        else:
            i += 1
    return out


# ------------------------------------------------------------- flag 4

def flag_four(strings: list[str]) -> str:
    # All four ingredients live in the DEX string pool: CIPHERTEXT_B64,
    # PKG, VER, SALT. We don't have to know which strings are which
    # field — we just identify them by format.
    pkg = _find_one(strings, lambda s: s == "com.infodays.referee.companion")
    ver = _find_one(strings, lambda s: s == "1.0.0")
    salt = _find_one(strings, lambda s: s == "infodays2026_var_referee_salt")
    cipher_b64 = _find_one(
        strings,
        lambda s: len(s) > 20
        and all(c.isalnum() or c in "+/=" for c in s)
        and len(s) % 4 == 0,
    )

    key_material = f"{pkg}|{ver}|{salt}".encode()
    key = hashlib.sha256(key_material).digest()[:16]
    iv = hashlib.sha256(("iv:" + salt).encode()).digest()[:16]
    ct = base64.b64decode(cipher_b64)

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def _find_one(strings: list[str], pred) -> str:
    matches = [s for s in strings if pred(s)]
    if not matches:
        raise SystemExit(f"[-] could not find string matching {pred}")
    return matches[0]


# ------------------------------------------------------------- flag 5

OP_HALT = 0
OP_LOAD_IMM = 1
OP_XOR_IMM = 2
OP_ADD_IMM = 3
OP_SUB_IMM = 4
OP_ROTL = 5
OP_STORE = 6


def flag_five(apk_path: Path) -> str:
    # VMInterpreter.PROG is a `static final int[]`. d8 encodes these
    # as a `fill-array-data-payload` with element_width=4. We scan
    # the DEX for such payloads, try each as a VM program, and take
    # whichever run emits a valid INFODAYS{...} string.
    with zipfile.ZipFile(apk_path) as zf:
        dex = zf.read(sorted(n for n in zf.namelist() if n.endswith(".dex"))[0])

    for prog in _find_int_arrays(dex):
        result = _run_vm(prog)
        if result.startswith("INFODAYS{") and result.endswith("}"):
            return result
    raise SystemExit("[-] flag 5: no VM program produced a flag")


def _find_int_arrays(dex: bytes) -> list[list[int]]:
    out: list[list[int]] = []
    i = 0
    while i + 8 <= len(dex):
        if dex[i] == 0x00 and dex[i + 1] == 0x03:
            width = struct.unpack_from("<H", dex, i + 2)[0]
            size = struct.unpack_from("<I", dex, i + 4)[0]
            if width == 4 and 10 <= size <= 4096 and i + 8 + size * 4 <= len(dex):
                out.append(list(struct.unpack_from(f"<{size}i", dex, i + 8)))
            i += 2
        else:
            i += 1
    return out


def _run_vm(prog: list[int]) -> str:
    R = [0] * 8
    out = bytearray()
    pc = 0
    while pc + 1 < len(prog):
        op = prog[pc]
        arg = prog[pc + 1]
        pc += 2
        reg = (arg >> 8) & 0xFF
        imm = arg & 0xFF
        if op == OP_HALT:
            break
        elif op == OP_LOAD_IMM:
            R[reg] = imm
        elif op == OP_XOR_IMM:
            R[reg] ^= imm
        elif op == OP_ADD_IMM:
            R[reg] = (R[reg] + imm) & 0xFF
        elif op == OP_SUB_IMM:
            R[reg] = (R[reg] - imm) & 0xFF
        elif op == OP_ROTL:
            s = imm & 7
            v = R[reg] & 0xFF
            R[reg] = ((v << s) | (v >> (8 - s))) & 0xFF
        elif op == OP_STORE:
            out.append(R[arg & 0xFF] & 0xFF)
        else:
            return ""
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return ""


# ----------------------------------------------------------------- main

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: solve.py <apk>", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1])
    if not apk.exists():
        raise SystemExit(f"[-] no such apk: {apk}")

    print(f"[*] target apk: {apk}")
    strings = dex_strings(apk)
    print(f"[+] dex string-pool entries: {len(strings)}")

    print("[*] stage 1 — strings dump (assets/welcome.txt)")
    f1 = flag_one_pretty(apk)
    print(f"[+] flag 1 (easy):      {f1}")

    print("[*] stage 2 — static constants in DebugHelper")
    f2 = flag_two(strings)
    print(f"[+] flag 2 (medium):    {f2}")

    print("[*] stage 3 — xor-decode in XorVault")
    f3 = flag_three(apk)
    print(f"[+] flag 3 (hard):      {f3}")

    print("[*] stage 4 — AES with composed key in AesVault")
    f4 = flag_four(strings)
    print(f"[+] flag 4 (very hard): {f4}")

    print("[*] stage 5 — custom bytecode VM in VMInterpreter")
    f5 = flag_five(apk)
    print(f"[+] flag 5 (insane):    {f5}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
