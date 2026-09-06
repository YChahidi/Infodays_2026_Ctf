#!/usr/bin/env python3
"""
GENERAL MBAPPE — spice smuggler.

The 32-byte permutation (`spice.bin`) is hidden in the trailing
bytes of the webp image shipped to players.  Most image viewers
stop at the RIFF container boundary, so the trailer is silently
ignored — but `xxd` / `strings` / any hex editor will reveal it.

Magic framing (little-endian):

    4 bytes   "MBSP"      (Mbappe SPice)
    1 byte    version     (0x01)
    1 byte    length      (0x20)
    N bytes   payload     (the PERM bytes)
    4 bytes   "MBEP"      (Mbappe End of Payload)

Usage:
    python3 stego.py embed   <base_image>  <spice.bin>  <out_image>
    python3 stego.py extract <image>       <out_spice.bin>
"""
import argparse
import os
import sys

MAGIC_START = b"MBSP"
MAGIC_END   = b"MBEP"
VERSION     = 0x01


def pack_payload(payload: bytes) -> bytes:
    if len(payload) != 32:
        raise ValueError(f"expected 32-byte payload, got {len(payload)}")
    return MAGIC_START + bytes([VERSION, len(payload)]) + payload + MAGIC_END


def embed(base: str, spice: str, out: str):
    with open(base, "rb") as f:
        image = f.read()
    with open(spice, "rb") as f:
        payload = f.read()

    # If the input already has a trailer, strip it so regen is idempotent.
    idx = image.rfind(MAGIC_START)
    if idx != -1 and image.endswith(MAGIC_END):
        image = image[:idx]

    wrapped = pack_payload(payload)
    with open(out, "wb") as f:
        f.write(image + wrapped)
    print(f"[+] embedded {len(payload)} bytes into {out} "
          f"({len(image)} image + {len(wrapped)} trailer = {len(image)+len(wrapped)} total)")


def extract(image_path: str, out_path: str):
    with open(image_path, "rb") as f:
        data = f.read()
    idx = data.rfind(MAGIC_START)
    if idx == -1 or not data.endswith(MAGIC_END):
        print("[!] no MBSP trailer found — wrong image?", file=sys.stderr)
        sys.exit(2)
    version = data[idx + 4]
    length  = data[idx + 5]
    start   = idx + 6
    payload = data[start:start + length]
    if len(payload) != length:
        print(f"[!] truncated payload (version {version}, want {length}, got {len(payload)})",
              file=sys.stderr)
        sys.exit(2)
    with open(out_path, "wb") as f:
        f.write(payload)
    print(f"[+] extracted {length} bytes of spice (version {version}) -> {out_path}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp_e = sub.add_parser("embed")
    sp_e.add_argument("base")
    sp_e.add_argument("spice")
    sp_e.add_argument("out")

    sp_x = sub.add_parser("extract")
    sp_x.add_argument("image")
    sp_x.add_argument("out")

    args = ap.parse_args()
    if args.cmd == "embed":
        embed(args.base, args.spice, args.out)
    else:
        extract(args.image, args.out)


if __name__ == "__main__":
    main()
