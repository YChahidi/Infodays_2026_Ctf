# KDB v2 — writeup (INSANE)

`INFODAYS{SaamNoLimits_qkd_sifting_leak_<hex>}`

## TL;DR

Three stacked primitives:

1. **Public transcript with no anchor** — recovered basis has a global
   X↔Z flip ambiguity.  The server publishes a 16-bit
   SHA-256 fingerprint of the shared key so the attacker can pick the
   right flip after reconstruction.
2. **10% noisy sifting bits** — a naive Z3 SAT solve returns UNSAT.
   Switch to `z3.Optimize` with soft constraints (one per
   non-ambiguous frame) and maximise satisfied count.  This is
   MaxSAT; Z3 handles it directly via `add_soft`.
3. **AES-GCM transport with fingerprint-seeded nonce** — tag check
   fails if even one key bit is wrong.  No room for trial-and-error:
   the MaxSAT solution + the right flip MUST match or the session
   refuses you.

Once the dust settles the leak is the same as the original Clutch
idea: non-ambiguous frames (measured bits `"11"`) pin the bases'
equality relation; ambiguous frames with one `m=1` side pin an
individual basis; everything else is noise to be voted out.

## TL;DR (old)

Every non-ambiguous frame in the transcript has measured bits `"11"`,
which collapses the sifting component into a clean equality relation
between two secret basis values:

- sifting = `"00,11"`  ⇒  `basis[a] == basis[b]`
- sifting = `"11,11"`  ⇒  `basis[a] != basis[b]`

Ambiguous frames where *exactly* one side has `m=1` directly expose
the basis value of that side via the `(s_X, s_Z)` component.
Together with the published `kickoff_basis` (= `basis[0]`), the basis
pool is uniquely determined — a Z3 query in a handful of lines finds
it.  Apply the key derivation table, AES-ECB encrypt the magic
command, receive the flag.

## 1. The leak

Look at `compute_sifting_string` in `handout/protocol.py`:

```python
s_X = (m_a if basis[a] == 0 else 0) ^ (m_b if basis[b] == 0 else 0)
s_Z = (m_a if basis[a] == 1 else 0) ^ (m_b if basis[b] == 1 else 0)
```

And the ambiguous filter:

```python
ambiguous = (m_a != 1 or m_b != 1)
```

So every non-ambiguous frame has `m_a = m_b = 1`, which means

- `s_X = (1 if basis[a]==0 else 0) XOR (1 if basis[b]==0 else 0)`
- `s_Z = (1 if basis[a]==1 else 0) XOR (1 if basis[b]==1 else 0)`

Enumerating the four possible `(basis[a], basis[b])` combos:

| `basis[a]` | `basis[b]` | `s_X s_Z` |
|------------|------------|-----------|
| 0 (X)      | 0 (X)      | `00`      |
| 1 (Z)      | 1 (Z)      | `00`      |
| 0 (X)      | 1 (Z)      | `11`      |
| 1 (Z)      | 0 (X)      | `11`      |

So sifting bits = `"00"` iff the two bases agree, `"11"` iff they
disagree.

## 2. Why the key depends on *individual* basis values

`KEY_DERIVATION` in `protocol.py`:

```python
KEY_DERIVATION = {
    "00,11|XX": "0",
    "00,11|ZZ": "1",
    "11,11|XZ": "1",
    "11,11|ZX": "0",
}
```

The sifting bits tell you "same or different", but the actual key bit
depends on which individual basis each index has — flipping *every*
basis bit (X→Z, Z→X) complements every key bit.  So without
additional information you'd get either the real key or its
bitwise complement.

The server kindly publishes `kickoff_basis = basis[0]` to resolve
that ambiguity.

## 3. Ambiguous frames aren't all useless

A frame with `m_a = 1, m_b = 0`:

```
s_X = (1 if basis[a]==0 else 0) XOR 0 = 1 iff basis[a]==0
s_Z = (1 if basis[a]==1 else 0) XOR 0 = 1 iff basis[a]==1
```

→ `(s_X, s_Z) = (1, 0)` ⇒ `basis[a] = 0`, and `(0, 1)` ⇒ `basis[a] =
1`.  So these frames directly pin `basis[a]`.  Mirror case for `m_a =
0, m_b = 1`.  Only frames with both `m=0` leak nothing — skip them.

## 4. Solving with Z3

```python
bv = [Bool(f"b_{i}") for i in range(n)]
solver.add(bv[0] == (kickoff_basis == 1))

for (a, b, m_a, m_b), sift, amb in zip(frames, sifts, amb_mask):
    sX, sZ = int(sift[0]), int(sift[1])
    if not amb:
        solver.add(bv[a] == bv[b]) if sX == 0 else solver.add(bv[a] != bv[b])
    elif m_a == 1 and m_b == 0:
        if sX == 1 and sZ == 0: solver.add(bv[a] == False)
        elif sX == 0 and sZ == 1: solver.add(bv[a] == True)
    elif m_a == 0 and m_b == 1:
        if sX == 1 and sZ == 0: solver.add(bv[b] == False)
        elif sX == 0 and sZ == 1: solver.add(bv[b] == True)

solver.check()
model = solver.model()
basis = [int(bool(model[bv[i]])) for i in range(n)]
```

Then rebuild `shared_key` with `KEY_DERIVATION` exactly as the server
does, AES-256-ECB encrypt `b"OPEN THE GATE"` using
`SHA-256(shared_key)`, hex-encode, and send `{"command": "<hex>"}`.

## 5. Why this is a realistic crypto fail

The protocol is faithful to a real idea (QKD post-processing sift +
filter), but the designer forgot that the "ambiguous frame" filter is
*data-dependent* — it turns all surviving frames into a bit-parity
oracle against the basis pool.  When a public filter is a function of
secret state, the post-filter transcript leaks the secret.  The
classical cryptographic version of the same bug shows up in
password-reset flows that only email users "who exist", in
rate-limiters that respond faster to rejected inputs, and in
QKD-inspired proposals whose error-correction step decides what to
publish based on the bits being corrected.

## Running the solver

```
$ python3 solver/solve.py 127.0.0.1:9001
[*] banner: {"info": "=== Kevin De Bruyne — Pass Signal Protocol ==="}
[*] transcript: 256 frames, 189 ambiguous, kickoff_basis=0
[*] recovered shared_key (67 bits): 101111010111100111010001111011101000011111110100...
FLAG: INFODAYS{SaamNoLimits_qkd_sifting_leak_341f87f1}
```
