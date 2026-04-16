#!/usr/bin/env python3
"""
Round 1 solver — pure XOR check.

Ghidra/radare2 reveals two static byte arrays R1_KEY and R1_TGT, and a
loop `inp[i] ^ R1_KEY[i] == R1_TGT[i]`. Recovering the passphrase is
just `inp[i] = R1_KEY[i] ^ R1_TGT[i]`.

The hex blobs below are extracted from the shipped binary via Ghidra
(or `objdump -s -j .rodata dist/tournament`). Your build will have the
same layout but possibly different byte values; re-dump and update if
needed.
"""

R1_KEY = bytes.fromhex("8e69b9cb66304008f6cf133f0cf4")
R1_TGT = bytes.fromhex("fa00d2a2394421639790715e6e8d")

pwd = bytes(k ^ t for k, t in zip(R1_KEY, R1_TGT))
print("Round 1 passphrase:", pwd.decode())
