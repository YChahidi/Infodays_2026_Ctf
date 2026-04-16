#!/usr/bin/env python3
"""
Round 2 solver — custom stack VM.

Disassembling the VM reveals a 10-opcode stack machine. The embedded
program (VM_PROG) runs one check per input byte:

    LOAD_INP i         # push inp[i]
    PUSH K_add[i]      # push add-key
    ADD                # inp[i] + K_add[i]  (mod 256)
    PUSH K_xor[i]      # push xor-key
    XOR                # ^ K_xor[i]
    PUSH T[i]          # push expected target
    CMP_NE             # 1 if mismatch, 0 if match
    OR                 # fold into accumulator

At HALT, the accumulator must be 0 (all checks matched). So for each
byte: `inp[i] = ((T[i] ^ K_xor[i]) - K_add[i]) mod 256`.

The program is in .rodata as VM_PROG — dump it with Ghidra or objdump.
"""

PROG = bytes.fromhex(
    "01000300017305019f04017a0708030101420501290401980708030201640501"
    "ba0401630708030301c60501430401790708030401b30501a70401bf07080305"
    "01560501450401f007080306019d0501fa0401f60708030701fa05015404013c"
    "07080308010605014f0401240708030901b20501560401470708030a01820501"
    "8604016f0708030b0104050165040116070809"
)

# Walk the bytecode, pull K_add / K_xor / T for each i.
K_add, K_xor, T = [], [], []
pc = 2  # skip the PUSH 0 accumulator seed
while pc < len(PROG) - 1:
    assert PROG[pc] == 0x03        # LOAD_INP idx
    pc += 2
    assert PROG[pc] == 0x01        # PUSH K_add
    K_add.append(PROG[pc + 1]); pc += 2
    assert PROG[pc] == 0x05; pc += 1
    assert PROG[pc] == 0x01        # PUSH K_xor
    K_xor.append(PROG[pc + 1]); pc += 2
    assert PROG[pc] == 0x04; pc += 1
    assert PROG[pc] == 0x01        # PUSH T
    T.append(PROG[pc + 1]); pc += 2
    assert PROG[pc] == 0x07; pc += 1
    assert PROG[pc] == 0x08; pc += 1

pwd = bytes(((t ^ x) - a) & 0xff for a, x, t in zip(K_add, K_xor, T))
print("Round 2 passphrase:", pwd.decode())
