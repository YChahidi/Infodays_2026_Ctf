#!/usr/bin/env python3

a = 1103515245
c = 12345
m = 2**31

SCORE_PLAIN  = "3107202612345678"
SCORE_CIPHER = "8355587028004226"
FLAG_CIPHER  = "XZOIEMTY{HIL_X9FC3J3_JTS_QU2DY_2365}"


# ---------------- LCG STEP ---------------- #
def step(x):
    return (a * x + c) % m


def step3(x):
    for _ in range(3):
        x = step(x)
    return x


# ---------------- TEST SEED ---------------- #
def test_seed(seed):
    x = seed

    # verify score consistency
    for i, ch in enumerate(SCORE_CIPHER):
        x = step3(x)
        ks = x & 0xFFFF

        if ch.isdigit():
            expected = (int(SCORE_PLAIN[i]) + ks) % 10
            if expected != int(ch):
                return None

    return seed


# ---------------- SEARCH (BUT EARLY PRUNED) ---------------- #
print("[*] searching seed...")

START = 1_000_000_000
END   = 1_500_000_000

for seed in range(START, END):
    result = test_seed(seed)
    if result is not None:
        print("[+] seed found:", result)
        break


# ---------------- DECRYPT ---------------- #
def decrypt(cipher, seed):
    x = seed
    out = []

    for ch in cipher:
        x = step3(x)
        ks = x & 0xFFFF

        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base - ks) % 26 + base))

        elif ch.isdigit():
            out.append(str((int(ch) - ks) % 10))

        else:
            out.append(ch)

    return "".join(out)


print("[*] decrypting...")

# reuse found seed
seed = None
for s in range(1_000_000_000, 1_500_000_000):
    if test_seed(s):
        seed = s
        break

if seed:
    print("[+] FLAG:", decrypt(FLAG_CIPHER, seed))
else:
    print("[-] failed")
