# tournament_bracket — Writeup

**Category:** Reverse Engineering · **Difficulty:** Insane (3 flags)

One stripped Linux x86-64 ELF, three gated stages. Each round hides one
flag, each round uses a different technique. Flags are XOR-encrypted in
`.rodata` with the round passphrase as the key — `strings` leaks
nothing, you must actually solve.

---

## 0. Initial recon

```bash
file dist/tournament
# ELF 64-bit LSB pie executable, x86-64, stripped

./dist/tournament
# ================================================
#  Infodays 2026 - Tournament Bracket
#  Three rounds. Three flags. One binary.
# ================================================
# [Round 1: Group Stage] Passphrase:

strings dist/tournament | grep -i infodays
#  Infodays 2026 - Tournament Bracket       <-- only the title, no flags
```

Load in Ghidra or radare2. The entry point chains three functions:
`check_round1`, `run_vm` (via `check_round2`), and `check_round3`. Each
is gated by an `fgets` + `strcspn` input read. On success, the code
calls a decoder:

```c
static void print_decoded(const unsigned char *enc, int n,
                          const unsigned char *key, int klen) {
    for (int i = 0; i < n; i++)
        putchar(enc[i] ^ key[i % klen]);
    putchar('\n');
}
```

So each flag is stored XOR-encrypted in `.rodata` (`FLAG1_ENC`,
`FLAG2_ENC`, `FLAG3_ENC`) and the key is the user input — meaning if
your passphrase is wrong, the "flag" comes out as garbage. You have to
solve each round to get each flag.

---

## 1. Round 1 — Group Stage (Easy)

Decompiled `check_round1`:

```c
int check_round1(const char *inp) {
    if (strlen(inp) < 14) return 0;
    for (int i = 0; i < 14; i++)
        if ((inp[i] ^ R1_KEY[i]) != R1_TGT[i]) return 0;
    return 1;
}
```

Two 14-byte arrays `R1_KEY` and `R1_TGT` in `.rodata`. The check is
`inp[i] ^ R1_KEY[i] == R1_TGT[i]`, so:

```
inp[i] = R1_KEY[i] ^ R1_TGT[i]
```

Dump the arrays from the binary:

```
R1_KEY = 8e 69 b9 cb 66 30 40 08 f6 cf 13 3f 0c f4
R1_TGT = fa 00 d2 a2 39 44 21 63 97 90 71 5e 6e 8d
```

Python one-liner:

```python
k = bytes.fromhex("8e69b9cb66304008f6cf133f0cf4")
t = bytes.fromhex("fa00d2a2394421639790715e6e8d")
print(bytes(a ^ b for a, b in zip(k, t)).decode())
# tiki_taka_baby
```

Feed `tiki_taka_baby`, flag 1 decrypts:

```
[+] Flag 1: INFODAYS{SaamNoLimits_group_stage_survived_a7f2c409}
```

---

## 2. Round 2 — Knockout (Medium)

`check_round2` calls `run_vm`. Decompile `run_vm` and you see a
dispatch loop:

```c
while (pc < VM_PROG_LEN) {
    unsigned char op = VM_PROG[pc++];
    switch (op) {
    case 0x01: st[sp++] = VM_PROG[pc++]; break;        // PUSH imm8
    case 0x03: st[sp++] = inp[VM_PROG[pc++]]; break;   // LOAD_INP idx
    case 0x04: /* XOR  */ ... break;
    case 0x05: /* ADD  */ ... break;
    case 0x07: /* CMP_NE */ ... break;
    case 0x08: /* OR   */ ... break;
    case 0x09: return st[sp-1] == 0;                   // HALT
    }
}
```

Opcode table:

| Opcode | Mnemonic    | Effect |
|--------|-------------|--------|
| 0x01   | `PUSH imm8` | push next byte |
| 0x03   | `LOAD_INP idx` | push `inp[idx]` |
| 0x04   | `XOR`       | pop a,b; push `a ^ b` |
| 0x05   | `ADD`       | pop a,b; push `(a+b) & 0xff` |
| 0x07   | `CMP_NE`    | pop a,b; push `1 if a!=b else 0` |
| 0x08   | `OR`        | pop a,b; push `a | b` |
| 0x09   | `HALT`      | return pass iff top-of-stack == 0 |

Dump `VM_PROG` from `.rodata`. The structure is:

```
01 00                       ; PUSH 0          (accumulator seed)

; per-byte check (repeats 12 times)
03 i                        ; LOAD_INP i
01 K_add[i]                 ; PUSH K_add[i]
05                          ; ADD
01 K_xor[i]                 ; PUSH K_xor[i]
04                          ; XOR
01 T[i]                     ; PUSH T[i]
07                          ; CMP_NE
08                          ; OR (fold into accumulator)

09                          ; HALT (acc must be 0)
```

Each check computes `((inp[i] + K_add[i]) ^ K_xor[i]) == T[i]`, and
ORs the mismatch bit into a running accumulator. On `HALT`, accumulator
must be 0, i.e. every byte matched.

Invert per byte:

```
inp[i] = ((T[i] ^ K_xor[i]) - K_add[i]) mod 256
```

Parser + inverter (see `solver/solve_r2.py`):

```python
PROG = bytes.fromhex("01000300017305019f04017a0708...")
K_add, K_xor, T = [], [], []
pc = 2
while pc < len(PROG) - 1:
    pc += 2                       # LOAD_INP i
    K_add.append(PROG[pc + 1]); pc += 2
    pc += 1                       # ADD
    K_xor.append(PROG[pc + 1]); pc += 2
    pc += 1                       # XOR
    T.append(PROG[pc + 1]); pc += 2
    pc += 2                       # CMP_NE; OR

pwd = bytes(((t ^ x) - a) & 0xff for a, x, t in zip(K_add, K_xor, T))
print(pwd.decode())
# route_one_go
```

Feed `route_one_go`, flag 2 decrypts:

```
[+] Flag 2: INFODAYS{SaamNoLimits_knockout_blow_landed_a7f2c409}
```

---

## 3. Round 3 — Final (Hard)

`check_round3`:

```c
int check_round3(const char *inp) {
    if (strlen(inp) < 16) return 0;
    for (int i = 0; i < 16; i++) {
        unsigned int s = 0;
        s += R3_COEF[i][0] * inp[i];
        s += R3_COEF[i][1] * inp[(i+1) % 16];
        s += R3_COEF[i][2] * inp[(i+7) % 16];
        if (s != R3_TGT[i]) return 0;
    }
    return 1;
}
```

A 16-equation linear system in 16 unknowns. Each equation uses three
input bytes (`inp[i]`, `inp[(i+1) % 16]`, `inp[(i+7) % 16]`) and a
16×3 coefficient table. Constraint each variable to printable ASCII
(`0x20..0x7e`) to pin a unique solution and throw it at Z3:

```python
from z3 import Int, Solver, And, sat

C = [(99,151,20), (148,66,80), (166,18,174), (66,153,79),
     (100,133,150), (195,32,109), (44,116,125), (140,84,155),
     (33,174,176), (95,116,186), (136,57,43), (97,70,118),
     (81,21,166), (63,129,49), (68,76,53), (85,25,25)]
T = [28239,31408,38102,31695,42878,39136,30219,41095,
     42307,43588,25766,31867,27829,27378,22920,15685]

x = [Int(f"x{i}") for i in range(16)]
s = Solver()
for xi in x:
    s.add(And(xi >= 0x20, xi <= 0x7e))
for i in range(16):
    c0, c1, c2 = C[i]
    s.add(c0*x[i] + c1*x[(i+1)%16] + c2*x[(i+7)%16] == T[i])

s.check()
m = s.model()
print(bytes(m[x[i]].as_long() for i in range(16)).decode())
# penalty_shootout
```

Feed `penalty_shootout`, flag 3 decrypts:

```
[+] Flag 3: INFODAYS{SaamNoLimits_raised_the_trophy_a7f2c409}

[*] You raised the trophy. Well played.
```

---

## 4. Full autonomous run

```bash
$ printf 'tiki_taka_baby\nroute_one_go\npenalty_shootout\n' | ./dist/tournament
[+] Flag 1: INFODAYS{SaamNoLimits_group_stage_survived_a7f2c409}
[+] Flag 2: INFODAYS{SaamNoLimits_knockout_blow_landed_a7f2c409}
[+] Flag 3: INFODAYS{SaamNoLimits_raised_the_trophy_a7f2c409}
```

All three flags captured. Raised the trophy.

---

## 5. Why Insane

- **Three independent techniques stacked in one binary.** A player who
  can do round 1 might bounce off round 2; a player comfortable with VMs
  might not know Z3.
- **No flag leaks via `strings`.** Every flag is XOR-protected against
  its own passphrase, so you cannot shortcut to a flag without solving
  the round that protects it.
- **Stripped binary.** All symbol names are gone — players must name
  functions manually in Ghidra and recognise patterns (stack VM
  dispatch loop, linear system) from shape alone.
- **Custom VM is not a known ISA.** No existing disassembler will help;
  you must read the switch statement and build your own opcode table.
- **Round 3 is solver-first, not manual.** Hand-solving a 16×16 linear
  system is technically possible but painful — the intended skill is
  recognising "this is an SMT problem" and reaching for Z3.

## 6. Related techniques

- Custom VM reversing: HTB "Rflag", Google CTF "Cfnhub", picoCTF
  "keygenme" series.
- Linear constraint flag checks: FLARE-On past challenges, TAMUctf.
- XOR-over-`.rodata` flag protection: a staple of picoCTF and
  Flare-On warm-up tiers.
