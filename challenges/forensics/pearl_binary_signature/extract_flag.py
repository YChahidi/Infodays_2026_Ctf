from PIL import Image

# 1. Load the challenge image
img = Image.open("agadir_tifo_challenge.png").convert("RGB")
pixels = img.load()

bits = ""

# 2. Extract LSB from the first 121 pixels (11x11 grid)
for y in range(11):
    for x in range(11):
        r, g, b = pixels[x, y]
        # Extract the last bit using the bitwise AND operator
        bit = r & 1
        bits += str(bit)

# 3. Print the result as a 121-bit string
print(f"Extracted Bits (121):\n{bits}\n")

# 4. Print as an 11x11 grid to visually verify the 'Tifo'
print("Visual 11x11 Grid:")
for i in range(0, 121, 11):
    print(bits[i:i+11])
