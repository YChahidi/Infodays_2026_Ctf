#!/usr/bin/env python3
import subprocess
import re
import glob
import os
from PIL import Image

def extract_steghide(image, password):
    # Remove existing file if it exists
    if os.path.exists('extracted.png'):
        os.remove('extracted.png')
    
    # Use yes pipe to automatically answer 'y' to overwrite prompt
    cmd = f'echo y | steghide extract -sf {image} -p {password} -xf extracted.png'
    subprocess.run(cmd, shell=True, capture_output=True)
    
    return 'extracted.png' if os.path.exists('extracted.png') else None

def extract_lsb(png_path):
    img = Image.open(png_path)
    pixels = img.load()
    bits = ""
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            bits += str(b & 1)
    text = ""
    for i in range(0, len(bits), 8):
        if i + 8 <= len(bits):
            char = chr(int(bits[i:i+8], 2))
            if char == '\x00':
                break
            text += char
    return text

images = glob.glob("stadium_*.jpg")
if not images:
    print("No image found")
    exit(1)

image = images[0]
match = re.search(r'Agadir(\d+)', image)
password = f"Agadir{match.group(1)}" if match else "Agadir2030"

print(f"Image: {image}")
print(f"Password: {password}")

extracted = extract_steghide(image, password)
if extracted:
    print(f"Extracted: {extracted}")
    flag = extract_lsb(extracted)
    flag_match = re.search(r'INFODAYS\{[^}]+\}', flag)
    if flag_match:
        print(f"FLAG: {flag_match.group(0)}")
    os.remove('extracted.png')
