# VIP Invitation - 2 Layer Hard Mode

## Description
You received a stadium image with password hint in filename.

## Solution

### Layer 1 - Steghide
Password is in filename: Agadir2030

steghide extract -sf stadium_vip_Agadir2030.jpg -p Agadir2030

This extracts: extracted.png

### Layer 2 - LSB Steganography
The PNG has flag hidden in blue channel LSB.

Use Python with PIL to extract LSB from blue channel, then convert bits to text.

## Flag
INFODAYS{2_L4Y3R_ST3G4N0GR4PHY_M4ST3R_2026}
