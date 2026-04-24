"""
KDB "Pass Signal Protocol" — v2 (INSANE).

Changes from v1 (published writeup style):
    * No public anchor.  The recovered basis is ambiguous up to a global
      X<->Z flip; the server publishes only a 16-bit prefix of
      SHA-256(shared_key) so the attacker has to pick the correct
      flip.  That's fine — but combined with...
    * 10% noise injected into sifting strings.  Each frame independently
      has a ~10% chance of having its sifting-bit byte randomly flipped
      at publication time.  A naive Z3 solve ends UNSAT; players need a
      MaxSAT / weighted solve and to track which constraints they have
      to drop.
    * Commands travel under AES-GCM, not ECB.  Any single-bit error in
      the recovered key flips the GCM tag and the server rejects the
      frame.  Random guessing doesn't work.

Per index i in [0, N_BASIS):
    basis[i]  ∈ {0, 1}  — secret (X / Z)
Per frame (a, b, m_a, m_b):
    sifting_string = "{s_X}{s_Z},{m_a}{m_b}"   (possibly noisy)

Non-ambiguous frames end in ",11" and leak basis (a)==basis(b) iff
sifting bits are "00".  Noisy frames will flip this — so players must
find a basis assignment that satisfies the *maximum* number of frame
constraints.  Ambiguous frames with exactly one m=1 still pin
individual basis values, which anchors the connected components.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

N_BASIS  = 64
N_FRAMES = 384            # bump frame count to tolerate noise
NOISE_PROBABILITY = 0.10  # ~10% of sifting strings carry flipped bits
FINGERPRINT_BITS  = 16    # public prefix of SHA-256(shared_key)

KEY_DERIVATION: dict[str, str] = {
    "00,11|XX": "0",
    "00,11|ZZ": "1",
    "11,11|XZ": "1",
    "11,11|ZX": "0",
}


def _basis_char(b: int) -> str:
    return "X" if b == 0 else "Z"


@dataclass
class Session:
    basis: list[int] = field(default_factory=list)
    frames: list[tuple[int, int, int, int]] = field(default_factory=list)
    sifting_strings: list[str] = field(default_factory=list)
    ambiguous_mask: list[bool] = field(default_factory=list)
    shared_key: str = ""
    key_fingerprint: str = ""   # hex prefix of sha256(shared_key)


def _sift_clean(basis: list[int], a: int, b: int, m_a: int, m_b: int) -> str:
    ba, bb = basis[a], basis[b]
    s_X = (m_a if ba == 0 else 0) ^ (m_b if bb == 0 else 0)
    s_Z = (m_a if ba == 1 else 0) ^ (m_b if bb == 1 else 0)
    return f"{s_X}{s_Z},{m_a}{m_b}"


def _add_noise(sift: str, rng: secrets.SystemRandom) -> str:
    """Flip one or both sifting bits with the configured probability."""
    if rng.random() >= NOISE_PROBABILITY:
        return sift
    sb, mb = sift.split(",")
    flip_bits = rng.choice(["00", "01", "10", "11"])
    while flip_bits == "00":
        flip_bits = rng.choice(["01", "10", "11"])
    new = []
    for b, f in zip(sb, flip_bits):
        new.append("1" if (int(b) ^ int(f)) else "0")
    return "".join(new) + "," + mb


def generate_session(rng: secrets.SystemRandom | None = None) -> Session:
    rng = rng or secrets.SystemRandom()
    s = Session()
    s.basis = [rng.randrange(2) for _ in range(N_BASIS)]

    for _ in range(N_FRAMES):
        a = rng.randrange(N_BASIS)
        b = rng.randrange(N_BASIS - 1)
        if b >= a:
            b += 1
        m_a = rng.randrange(2)
        m_b = rng.randrange(2)
        s.frames.append((a, b, m_a, m_b))

        clean = _sift_clean(s.basis, a, b, m_a, m_b)
        noisy = _add_noise(clean, rng)
        s.sifting_strings.append(noisy)
        s.ambiguous_mask.append(not (m_a == 1 and m_b == 1))

    # Shared key derivation always uses the TRUE basis and *clean* sifting
    # so noise doesn't screw up Haaland/KDB's internal secret computation.
    clean_sifts = [_sift_clean(s.basis, a, b, m_a, m_b) for (a, b, m_a, m_b) in s.frames]
    s.shared_key = derive_shared_key(s.basis, s.frames, clean_sifts, s.ambiguous_mask)

    fp_bytes = hashlib.sha256(s.shared_key.encode()).digest()
    s.key_fingerprint = fp_bytes[: (FINGERPRINT_BITS + 7) // 8].hex()[: FINGERPRINT_BITS // 4]
    return s


def derive_shared_key(
    basis: list[int],
    frames: list[tuple[int, int, int, int]],
    sifting_strings: list[str],
    ambiguous_mask: list[bool],
) -> str:
    out = []
    for frame, sift, amb in zip(frames, sifting_strings, ambiguous_mask):
        if amb:
            continue
        a, b, _, _ = frame
        orient = _basis_char(basis[a]) + _basis_char(basis[b])
        out.append(KEY_DERIVATION[f"{sift}|{orient}"])
    return "".join(out)


def aes_key_from_shared(shared_key: str) -> bytes:
    return hashlib.sha256(shared_key.encode()).digest()
