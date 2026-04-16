#!/usr/bin/env python3
import os
import subprocess
from PIL import Image

PASSWORD = "Agadir2030"
FLAG = "INFODAYS{2_L4Y3R_ST3G4N0GR4PHY_M4ST3R_2026}"

print("Creating 2-layer stego challenge...")

# Create hidden image with LSB flag
hidden_img = Image.new('RGB', (400, 300), color='lightblue')
pixels = hidden_img.load()

flag_bits = ''.join(format(ord(c), '08b') for c in FLAG) + '00000000'

idx = 0
for y in range(hidden_img.height):
    for x in range(hidden_img.width):
        if idx < len(flag_bits):
            r, g, b = pixels[x, y]
            b = (b & 0xFE) | int(flag_bits[idx])
            pixels[x, y] = (r, g, b)
            idx += 1

hidden_img.save("hidden_flag.png")
print("  Created hidden_flag.png")

# Create base image
base_img = Image.new('RGB', (1024, 768), color='darkgreen')
base_img.save("stadium_base.jpg")

# Embed with steghide
subprocess.run(["steghide", "embed", "-cf", "stadium_base.jpg", "-ef", "hidden_flag.png", "-p", PASSWORD])

# Rename
os.rename("stadium_base.jpg", f"stadium_vip_{PASSWORD}.jpg")

# Cleanup
os.remove("hidden_flag.png")

print(f"Challenge created: stadium_vip_{PASSWORD}.jpg")
print(f"Flag: {FLAG}")
