# var_override

**Category:** Cryptography
**Difficulty:** Extreme (single flag, source-code disclosure)
**Type:** Static file attachment (no container, no port)

## Player brief

> The Infodays 2026 VAR booth signs every overrule before it is
> pushed to the scoreboard — secp256k1 ECDSA, SHA-256 digest, one
> signature per decision. The audit panel leaked the full source
> of the signing service, along with the public key, 15 intercepted
> decision signatures, and an AES-GCM'd flag blob whose key is
> derived from the signer's private key.
>
> Recover the private key from the signatures and the source, then
> decrypt `flag.enc`.
>
> **Attached:**
> - `signer.py` — the full source of the VAR signing service
> - `public_key.txt` — signer public key (Qx, Qy) on secp256k1
> - `signatures.txt` — 15 signed VAR decisions, one per line
> - `flag.enc` — AES-GCM(flag) · key = SHA256(priv.to_bytes(32,'big'))
>
> **Flag format:** `INFODAYS{SaamNoLimits_<phrase>_<hex>}`

## What makes it Extreme

- The bug is **subtle and source-visible**: the signer draws nonces
  at the wrong bit width, justified with a plausible-sounding
  legacy audit-log cover story in the comments. You have to spot
  it as a crypto bug, not an engineering one.
- Exploiting it is **not code review — it's lattice cryptanalysis**.
  You derive an affine relation per signature, stack them into a
  Boneh–Venkatesan lattice, and run LLL. The result is one vector
  whose coordinates encode the private key.
- **Pure lattice, no oracle.** There is no signing service to hit,
  no chosen-message query, no side-channel. You get a fixed dump
  and have to do the math.
- **Chained primitives.** Recovering `d` is only step one: the flag
  lives inside an AES-GCM blob keyed by SHA-256 of `d`. You have to
  reconstitute the key from the recovered integer and decrypt.

## Solve pipeline

1. Read `signer.py` carefully. Notice the "232-bit nonces for VAR1
   audit log compatibility" comment — that's a 24-bit MSB leak on
   every nonce, which is the Hidden Number Problem in disguise.
2. Parse `signatures.txt`, hash each decision to get `z_i`, and
   compute `A_i = z_i · s_i^{-1} mod n`, `T_i = r_i · s_i^{-1} mod n`.
3. Build the Boneh–Venkatesan lattice (see `solver/solve.py` or
   `WRITEUP.md` for the exact basis).
4. LLL-reduce. Pick out the row whose last entry is `±K·n`. The
   column-`m` entry of that row, divided by `K`, is the private key.
5. Compute `key = SHA256(d.to_bytes(32, 'big'))` and decrypt
   `flag.enc` (AES-GCM, layout: `nonce[12] || tag[16] || ct`).

## Deployment

Pure static attachment. No container, no port, no runtime.

1. Build once: `python3 gen.py` (writes `public/` bundle + `flag.txt`)
2. Upload the four files from `public/` as attachments on CTFd
3. Paste the flag from `flag.txt`

### Regenerating the bundle

```bash
# Fresh random private key + hex suffix
python3 gen.py

# Deterministic build hex (private key is still freshly random)
python3 gen.py --hex a7f2c409
```

## Files

| Path | Purpose |
|------|---------|
| `public/signer.py` | Buggy ECDSA signer — the player-facing source |
| `public/public_key.txt` | Signer's secp256k1 public key (Qx, Qy) |
| `public/signatures.txt` | 15 intercepted `decision \| r \| s` triples |
| `public/flag.enc` | AES-GCM(flag), key derived from recovered `d` |
| `gen.py` | Build-time generator |
| `solver/solve.py` | Full attack: HNP lattice + pure-Python LLL + AES unwrap |
| `flag.txt` | The flag for the current build |
| `WRITEUP.md` | Full author solution with lattice derivation |

## Requirements

- Python 3.10+
- `pycryptodome` (AES-GCM)
- `sympy` (LLL via `DomainMatrix.lll`) — already a transitive
  dependency of most scientific Python stacks. Players are free to
  swap in `fpylll` or SageMath if they prefer.

## Current flag (build `a7f2c409`)

See `flag.txt`. Rotates if you rerun `gen.py` without `--hex`.
