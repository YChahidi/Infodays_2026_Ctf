📝 Description
The Ultras in Agadir have outdone themselves. They've created an 11x11 'Starting XI Squared' mosaic that hides a cryptographic secret. To unlock the flag, find the name of the host city. nc 127.0.0.1 1234

Hint: The city is the Pearl of the South. The hash is as loud as the fans.

🕵️ Solution
Decode the Hints: * "Pearl of the South" refers to the city of AGADIR.

"Loud" indicates the string should be in ALL CAPS.

"11x11 Starting XI Squared" refers to 121 bits of data hidden in the image.

Generate the Hash:

The student must calculate the SHA-256 hash of the string AGADIR.

SHA-256("AGADIR"): a25fd3c837337458d941d42ab655da0d09f174e06cdef52283499704b71f6092  -  (echo -n "AGADIR" |sha256sum
)

Extract Steganographic Data:

Using a tool like StegSolve or a Python script, the student extracts the Least Significant Bits (LSB) from the image agadir_tifo_challenge.png.

Python script for extraction :

└─$ cat extract_flag.py 
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

The first 121 bits extracted from the image will match the first 121 bits of the SHA-256 hash binary representation.

Network Exploitation:

Once the match is confirmed, the student connects to the provided listener: nc 127.0.0.1 1234.

By sending the Hex format of the hash , the server provides the flag.

Flag: INFODAYS{4G4D1R_ST3G4N0GR4PHY_M4ST3R_2030}
