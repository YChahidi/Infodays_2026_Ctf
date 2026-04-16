#!/usr/bin/env python3
"""
Round 3 solver — 16-variable linear constraint system.

Disassembling check_round3 reveals a loop:

    for i in 0..15:
        s = C[i][0]*inp[i] + C[i][1]*inp[(i+1)%16] + C[i][2]*inp[(i+7)%16]
        assert s == T[i]

16 linear equations in 16 unknowns. Z3 solves it in one shot. The
printable-ASCII constraint keeps the solution unique.

Coefficients and targets are extracted from .rodata (Ghidra's data
view, or `objdump -s -j .rodata dist/tournament`).
"""

from z3 import Int, Solver, And, sat

C = [
    (99, 151, 20),  (148, 66, 80),   (166, 18, 174),  (66, 153, 79),
    (100, 133, 150),(195, 32, 109),  (44, 116, 125),  (140, 84, 155),
    (33, 174, 176), (95, 116, 186),  (136, 57, 43),   (97, 70, 118),
    (81, 21, 166),  (63, 129, 49),   (68, 76, 53),    (85, 25, 25),
]
T = [28239, 31408, 38102, 31695, 42878, 39136, 30219, 41095,
     42307, 43588, 25766, 31867, 27829, 27378, 22920, 15685]

x = [Int(f"x{i}") for i in range(16)]
s = Solver()
for xi in x:
    s.add(And(xi >= 0x20, xi <= 0x7e))  # printable ASCII
for i in range(16):
    c0, c1, c2 = C[i]
    s.add(c0 * x[i] + c1 * x[(i + 1) % 16] + c2 * x[(i + 7) % 16] == T[i])

assert s.check() == sat, "no solution"
m = s.model()
pwd = bytes(m[x[i]].as_long() for i in range(16))
print("Round 3 passphrase:", pwd.decode())
