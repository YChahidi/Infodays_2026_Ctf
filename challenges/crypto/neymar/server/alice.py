"""
Alice side of the Frame-based QKD handshake.

Alice prepares N entangled pair halves in a random basis with a random
bit value, then collaborates with Bob after measurement to reconcile
frames and derive the shared key.
"""

from random import SystemRandom

from helpers import BOB_MR_DERIVATION, KEY_DERIVATION


class Alice:
    def __init__(self, pairs):
        self.pairs = pairs
        rand = SystemRandom()
        self.preparation_basis = [rand.choice(["X", "Z"]) for _ in range(pairs)]
        self.preparation_results = [rand.randrange(2) for _ in range(pairs)]

    def prepare(self):
        return list(zip(self.preparation_basis, self.preparation_results))

    def compute_frames(self, double_matchings):
        rand = SystemRandom()
        pool = list(double_matchings)
        rand.shuffle(pool)

        frames = []
        for i in range(0, len(pool) - 1, 2):
            frames.append((pool[i], pool[i + 1]))

        usable_frames = frames
        auxiliary_frames = []
        return frames, usable_frames, auxiliary_frames

    def error_correction(self, usable_frames, auxiliary_frames, bob_sifting_strings):
        ambiguous_frames = []
        for frame in usable_frames:
            _, measured_bits = bob_sifting_strings[frame].split(",")
            if measured_bits != "11":
                ambiguous_frames.append(frame)

        alice_sifting_strings = dict(bob_sifting_strings)
        return alice_sifting_strings, ambiguous_frames

    def generate_shared_key(self, frames, usable_frames, ambiguous_frames,
                            alice_sifting_strings, bob_sifting_strings):
        shared_secret = ""
        for frame in frames:
            if frame in ambiguous_frames:
                continue
            basis_orientation = (self.preparation_basis[frame[0]],
                                 self.preparation_basis[frame[1]])
            measurement_result = BOB_MR_DERIVATION[basis_orientation]
            shared_secret += KEY_DERIVATION[bob_sifting_strings[frame]][measurement_result]
        return shared_secret
