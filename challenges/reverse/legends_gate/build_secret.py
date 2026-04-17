seed = 0xC0FFEE
seed ^= 3
seed = (seed << 5) | (seed >> 27)

def vm(v, i, seed):
    k = (seed ^ (i * 0x27) ^ (i >> 2)) & 0xFF
    return v ^ k

PASS = "L45_L3y3nd45!"

enc_pass = [vm(ord(c), i, seed) for i, c in enumerate(PASS)]

with open("legend_secret.h", "w") as f:
    f.write("#pragma once\n#include <stdint.h>\n\n")
    f.write(f"#define PASS_LEN {len(enc_pass)}\n\n")

    f.write("static const uint8_t enc_pass[PASS_LEN] = {")
    f.write(",".join(str(x) for x in enc_pass))
    f.write("};\n")
