"""
Bob side of the Frame-based QKD handshake.

Bob chooses a random measurement basis per pair. When his basis matches
Alice's preparation basis he recovers Alice's bit perfectly (this pair
enters the public double_matchings list); otherwise his outcome is
independent random noise.
"""

from random import SystemRandom

from helpers import BOB_MR_DERIVATION, KEY_DERIVATION


class Bob:
    def __init__(self, depolarizing_probability):
        self.depolarizing_probability = depolarizing_probability
        self.measurement_basis = {}
        self.measurement_results = {}

    def measure(self, pairs):
        rand = SystemRandom()
        double_matchings = []
        for i, (alice_basis, alice_result) in enumerate(pairs):
            basis = rand.choice(["X", "Z"])
            if basis == alice_basis:
                result = alice_result
                double_matchings.append(i)
            else:
                result = rand.randrange(2)
            self.measurement_basis[i] = basis
            self.measurement_results[i] = str(result)
        return double_matchings

    def _sifting_bits(self, frame):
        acc = {"X": 0, "Z": 0}
        for pair in frame:
            acc[self.measurement_basis[pair]] ^= int(self.measurement_results[pair][0])
        return f"{acc['X']}{acc['Z']}"

    def _measured_bits(self, frame):
        return "".join(self.measurement_results[pair][0] for pair in frame)

    def compute_sifting_strings(self, frames):
        sifting_strings = {}
        for frame in frames:
            sifting_strings[frame] = f"{self._sifting_bits(frame)},{self._measured_bits(frame)}"
        return sifting_strings

    def generate_shared_key(self, frames, ambiguous_frames, sifting_strings):
        shared_secret = ""
        for frame in frames:
            if frame in ambiguous_frames:
                continue
            basis_orientation = (self.measurement_basis[frame[0]],
                                 self.measurement_basis[frame[1]])
            measurement_result = BOB_MR_DERIVATION[basis_orientation]
            shared_secret += KEY_DERIVATION[sifting_strings[frame]][measurement_result]
        return shared_secret
