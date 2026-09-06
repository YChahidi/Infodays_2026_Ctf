#!/usr/bin/env python3

TARGET = 0xCAFEBABEDEADBEEF

def rol(v, r):
    v &= 0xFFFFFFFF
    return ((v << r) | (v >> (32 - r))) & 0xFFFFFFFF


def gen_expected():
    seed = 0xC0FFEE
    out = []
    for i in range(16):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((((seed >> 16) ^ (i * 0x5A)) + 0x33) & 0xFF)
    return out


EXPECTED = gen_expected()


def vm_step(byte, state, i):
    x = byte
    x ^= state
    x = (x * 7 + (state ^ 0x3D)) & 0xFFFFFFFF
    x = rol(x, i % 5)
    x ^= (i * 11)
    return x & 0xFFFFFFFF


def solve():
    print("[*] relaxed forward search...")

    states = [([], 0xA5, 0, 0)]  # (path, state, checksum, mismatch_score)

    for i in range(16):
        new_states = []

        for path, state, checksum, score in states:

            for b in range(256):
                x = vm_step(b, state, i)

                # soft constraint (NOT hard prune)
                new_score = score
                if (x & 0xFF) != EXPECTED[i]:
                    new_score += 1

                new_checksum = checksum
                new_checksum ^= (x * 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
                new_checksum = (new_checksum + ((x << 13) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
                new_checksum ^= ((i << 29) & 0xFFFFFFFFFFFFFFFF)

                new_states.append((path + [b], x, new_checksum, new_score))

        # keep only best candidates (beam search)
        new_states.sort(key=lambda x: x[3])
        states = new_states[:5000]   # beam width

        print(f"[+] step {i} -> states: {len(states)}")

    print("[*] final selection...")

    for path, state, checksum, score in states:
        if checksum == TARGET:
            print("[+] mismatch score:", score)
            return bytes(path)

    return None


if __name__ == "__main__":
    res = solve()

    if res:
        print("\n[+] FOUND:", res)
        print("[+] HEX:", res.hex())
    else:
        print("\n[-] no solution found")
