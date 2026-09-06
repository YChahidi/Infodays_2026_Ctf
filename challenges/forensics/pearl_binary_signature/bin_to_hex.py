# The bits extracted from your grid
bits = "1010001001011111110100111100100000110111001100110111010001011000110110010100000111010100001010101011011001011010110110101"

# 1. Take enough bits for 11 hex characters (11 * 4 = 44 bits)
flag_bits = bits[:44]

# 2. Convert to hex
hex_flag = ""
for i in range(0, len(flag_bits), 4):
    hex_char = hex(int(flag_bits[i:i+4], 2))[2:]
    hex_flag += hex_char

print(f"The first 11 hex characters are: {hex_flag}")
