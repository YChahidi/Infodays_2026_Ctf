"""
Lookup tables for the Frame-based QKD protocol used by the PSG secure
channel. Constants are drawn from the frame reconciliation rules in
"Frame-Based Coherent One-Way Quantum Key Distribution" (Symmetry 2020).

BOB_MR_DERIVATION is symmetric under a global basis flip, which is
exactly why the protocol still produces a consistent key when Alice and
Bob only compare basis *orientations* per frame rather than individual
basis values.
"""

BOB_MR_DERIVATION = {
    ("X", "X"): 0,
    ("X", "Z"): 1,
    ("Z", "X"): 1,
    ("Z", "Z"): 0,
}

# Only sifting strings whose measured_bits == "11" contribute key material;
# the rest are flagged ambiguous during error correction and discarded.
KEY_DERIVATION = {
    "00,11": {0: "0", 1: "1"},
    "11,11": {0: "1", 1: "0"},
}
