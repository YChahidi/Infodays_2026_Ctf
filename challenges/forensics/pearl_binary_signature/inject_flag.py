from PIL import Image

# Your 121 bits from the uppercase AGADIR hash
bits = "101000100101111111010011110010000011011100110011011101000101100011011001010000011101010000101010101101100101101011011010110100000"

img = Image.open("stadium.png").convert("RGB")
pixels = img.load()

# We hide the bits in the first 121 pixels of the top-left corner
idx = 0
for y in range(11):  # 11 rows
    for x in range(11): # 11 columns
        if idx < len(bits):
            r, g, b = pixels[x, y]
            # Change only the last bit of the Red channel
            new_r = (r & ~1) | int(bits[idx])
            pixels[x, y] = (new_r, g, b)
            idx += 1

img.save("agadir_tifo_challenge.png")
print("Challenge file 'agadir_tifo_challenge.png' created successfully!")
