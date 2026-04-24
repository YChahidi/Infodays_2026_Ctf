# NEYMAR — Author Writeup (staff only)

> Do not ship this file inside the player bundle. It names the
> underlying cryptanalytic bug directly.

## Intended solve in 5 steps

1. **Parse FFP1 framing.** Every message is `b"FFP1"` + 2-byte BE
   length + JSON payload.
2. **Clear the PoW gate.** Server sends `{"op":"pow","challenge":H,"bits":B}`;
   find `nonce` with `leading_zero_bits(sha256(b"ffp1-pow:"+challenge+nonce)) >= bits`.
3. **Read the handshake** — `{"op":"handshake", registered_plays, tactics, chalkboard_codes, vetoed_tactics}`.
4. **Recover the lane assignment** (see §2 below) with z3 equality /
   inequality constraints on a 1-bit-per-pair variable.
5. **Rebuild the match cipher**, derive `sha256(match_cipher)` as the
   AES-256-ECB key, encrypt `"PASS TO NEYMAR"` padded to 16 B, send
   `{"op":"play","cipher_hex":...}`, receive
   `{"op":"flag","msg":"...INFODAYS{...}"}`.

## 1. The protocol (unchanged from the quantum-flavored source)

For each of `N = 1024` pair indices, Scout picks `(lane_choice, bit)`
at random. Dispatcher picks a lane at random; when his lane matches
Scout's he recovers Scout's bit, otherwise his outcome is random. The
set of basis-match indices is published as `registered_plays`.

Scout pairs the registered plays into disjoint two-element tuples —
`tactics`. For each tactic Dispatcher publishes a string

    "<X_xor>,<measured_bits>"

where `X_xor` is the XOR of result bits at indices measured in lane X,
and `measured_bits` is the concatenation of both results.

`error_correction` flags every tactic with `measured_bits != "11"` as
`vetoed`. Only the remainder contributes a bit to the `match_cipher`
via

    key_bit = KEY_DERIVATION[code][ BOB_MR_DERIVATION[(lane[a], lane[b])] ]

## 2. The leak

Case-split `sifting_bits` under the assumption `measured_bits == "11"`:

| lane[a] | lane[b] | X_xor | Z_xor | sifting_bits |
|---------|---------|-------|-------|--------------|
|    X    |    X    | 1⊕1=0 |   0   |     `00`     |
|    Z    |    Z    |   0   | 1⊕1=0 |     `00`     |
|    X    |    Z    |   1   |   1   |     `11`     |
|    Z    |    X    |   1   |   1   |     `11`     |

So every surviving tactic leaks one bit of information about lane
equality:

- `"00,11"` ⇒ `lane[a] == lane[b]`
- `"11,11"` ⇒ `lane[a] != lane[b]`

Feed those as equality / inequality constraints into z3 over a
1-bit-per-index variable. The model is unique up to a global `X↔Z`
flip, and `BOB_MR_DERIVATION` is invariant under that flip, so the
derived `match_cipher` is unambiguous.

## 3. Full exploit

Runnable in `solver/solve.py` — mines PoW, parses FFP1, solves z3,
and pulls the flag. Finishes in ~1 s end-to-end on a laptop.

## 4. Why the three hardening layers matter for CTF students

| Layer | What it blocks |
|-------|----------------|
| Renamed public fields + command text | Google / ChatGPT pattern-match on the HackTheBox "Clutch" writeup returns nothing. A student that asks "what does `registered_plays` + `tactics` + `chalkboard_codes` mean?" gets no hits. |
| FFP1 framing | "Just paste JSON into netcat" doesn't produce output. Players must read the server's first frame byte by byte and infer the format — a natural RE task that LLMs are mediocre at without direct source access. |
| 18-bit PoW | A student running one solver once spends ~0.5 s. A naïve AI-scripted approach that spams reconnects to probe responses spends hours. |

None of the three change the underlying cryptanalysis. A student who
understands the bug can still build a clean solver — as the reference
implementation here shows.

## 5. Suggested hints to release (if stuck)

1. *"The first message after handshake looks like binary garbage
   followed by JSON. Look at the magic bytes."* — unlocks FFP1 parsing.
2. *"Why do all surviving tactics end in `,11`?"* — unlocks the leak.
3. *"Treat each `lane_choice` as a 1-bit unknown."* — unlocks z3.
