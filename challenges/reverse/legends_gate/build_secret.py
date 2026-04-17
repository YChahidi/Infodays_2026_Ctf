PASS = "L45_L3y3nd45!"
FLAG = "INFODAYS{VM_FINAL_STABLE_2026}"

def vm(v, i, seed):
    k = (seed ^ (i * 0x27) ^ (i >> 2)) & 0xFF
    return v ^ k

def gen(text, seed):
    return [vm(ord(c), i, seed) for i, c in enumerate(text)]

seed = 0xC0FFEE
seed ^= 3
seed = (seed << 5) | (seed >> 27)

enc_pass = gen(PASS, seed)
enc_flag = gen(FLAG, seed)

with open("legend_secret.h", "w") as f:
    f.write("#pragma once\n#include <stdint.h>\n\n")
    f.write(f"#define PASS_LEN {len(enc_pass)}\n")
    f.write(f"#define FLAG_LEN {len(enc_flag)}\n\n")

    f.write("static const uint8_t enc_pass[] = {" +
            ",".join(map(str, enc_pass)) + "};\n\n")

    f.write("static const uint8_t enc_flag[] = {" +
            ",".join(map(str, enc_flag)) + "};\n")
