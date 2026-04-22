# general_mbappe — author writeup

## tl;dr

1.  Read the ISA off the recipe by matching cook.c's parser.
2.  Realise every `LADDER TMP, 0x??, FAIL` byte is a slice of the
    in-memory shuffled buffer taken at index `(5*i) % 32`.
3.  Undo the stride-5 index permutation and then the 4-byte block
    shuffle `[0,1,2,3] → [2,1,3,0]`.
4.  The recovered 32 bytes are the kitchen pass.  Flag:
    `infodays{SaamNoLimits_<pass>}`.

## Walkthrough

### Mapping the ISA

`cook.c` is ~200 lines and unobfuscated.  `main` reads the recipe,
prompts the player for a pass, stores it at `mem[0x00..0x1F]` (and
a verbatim backup at `mem[0x80..0x9F]` for the success print), then
runs the VM.  The dispatch table in `execute()` gives us the opcode
semantics:

| Mnemonic        | Meaning                                    |
|-----------------|--------------------------------------------|
| `AES256 <imm>`  | `putchar(imm)` — cosmetic char print        |
| `BOIL r, imm`   | `r = imm`                                   |
| `QUICKMAFFS r, op, imm` | `r = r ADD/SUB/XOR imm`              |
| `GOODBYE r`     | `r = mem[CARBO]; CARBO++`                   |
| `WINDOW  r`     | `mem[CARBO] = r; CARBO++`                   |
| `LADDER r, imm, label` | `if r != imm goto label`             |
| `HALT imm`      | `exit(imm)`                                 |

Eight registers named after ingredients.  `CARBO` is the implicit
pointer; `GOODBYE`/`WINDOW` auto-increment it.

### Recipe decomposition

`dist/recipe.asm` has three obvious blocks.

**Stage 1 — key load.**  `BOIL CARBO, 0x40` followed by 32
`BOIL TMP, 0x??` / `WINDOW TMP` pairs.  This puts a 32-byte
"verification key" into `mem[0x40..0x5F]`.  This is a red herring:
the subsequent LADDERs compare against immediates, never against
`mem[0x40+i]`.

**Stage 2 — 4-byte block shuffle.**  Eight repetitions of:

```
BOIL    CARBO, 0xNN
GOODBYE VEGETABLE      ; in[0]
GOODBYE FRUIT          ; in[1]
GOODBYE MEAT           ; in[2]
GOODBYE DAIRY          ; in[3]
BOIL    CARBO, 0xNN
WINDOW  MEAT           ; out[0] = in[2]
WINDOW  FRUIT          ; out[1] = in[1]
WINDOW  DAIRY          ; out[2] = in[3]
WINDOW  VEGETABLE      ; out[3] = in[0]
```

Forward permutation: `out = [in[2], in[1], in[3], in[0]]`, i.e. the
permutation vector `PERM = [2, 1, 3, 0]`.  Its inverse is
`[3, 1, 0, 2]`: `in[0] = out[3]`, `in[1] = out[1]`,
`in[2] = out[0]`, `in[3] = out[2]`.

**Stage 3 — stride-5 verification.**  32 triplets of the form:

```
BOIL    CARBO, 0xII
GOODBYE TMP
LADDER  TMP, 0xKK, FAIL
```

Reading the indices in order gives `0x00, 0x05, 0x0a, 0x0f, 0x14,
0x19, 0x1e, 0x03, 0x08, ...` — the sequence `(5 * i) mod 32` for
`i = 0..31`.  Since `gcd(5, 32) = 1` this is a full permutation of
`[0, 32)`.

### Two inversions

Call the bytes pulled off the 32 LADDER immediates `K[0..31]`.  The
recipe guarantees `shuffled[(5*i) mod 32] == K[i]`, so:

```python
shuffled = bytearray(32)
for i in range(32):
    shuffled[(5*i) % 32] = K[i]
```

Now undo the 4-byte block shuffle:

```python
plain = bytearray(32)
for off in range(0, 32, 4):
    b = shuffled[off:off+4]
    plain[off+0] = b[3]
    plain[off+1] = b[1]
    plain[off+2] = b[0]
    plain[off+3] = b[2]
```

`plain.decode()` is the kitchen pass.

### End-to-end check

```bash
$ python3 solver/solve.py dist/recipe.asm
[+] kitchen pass: GeN3r4L_MB4PP3_c00k5_4_cU570m_VM
[+] flag:         infodays{SaamNoLimits_GeN3r4L_MB4PP3_c00k5_4_cU570m_VM}

$ printf 'GeN3r4L_MB4PP3_c00k5_4_cU570m_VM\n' | ./dist/cook dist/recipe.asm
...
Le general sourit.  Access granted, capitaine.
infodays{SaamNoLimits_GeN3r4L_MB4PP3_c00k5_4_cU570m_VM}
```

### Why this is Hard (not Insane)

A player who just picks up `cook.c` learns the ISA in five minutes.
The pivot is noticing the stride-5 pattern in the LADDER indices —
without it you try to read the pass "in order" from the immediates
and it doesn't form English.  Once you spot the stride, both
inversions are trivial.  The 32 key-load instructions at `0x40` are
there to keep players staring at "BOIL TMP / WINDOW TMP" wondering
if they mean something, when they never get read back.
