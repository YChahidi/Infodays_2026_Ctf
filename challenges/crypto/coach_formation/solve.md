# 🚩 Coach Formation - Ultra Hard Mode

## 📝 Description
The coach's tactical notebook was intercepted. Three encrypted messages were found.

## 🔍 Vulnerability
The encryption uses an LCG (Linear Congruential Generator) with standard glibc parameters:
- a = 1103515245
- c = 12345
- m = 2^31

## 🛠️ Solution Steps

1. **Extract keystream** from known plaintext-ciphertext pair (Message 1)
2. **Find seed residue** modulo 26 from first keystream value
3. **Brute force seed** searching only residues (0 to 2^31 in steps of 26)
4. **Decrypt flag** using recovered seed

## 🏁 Flag
`INFODAYS{L1NH4RT_M0R41N_LLL_4TT4CK_2026}`
