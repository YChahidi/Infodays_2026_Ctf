#!/usr/bin/env python3

score_pt = "3107202612345678"
score_ct = "4259446290123456"
flag_ct = "GLDMBYWQ{DGLYJ_ZMQQ_JAE_APWNRM}"

# Compute keystream mod 10 for digits
ks_mod10 = [(int(score_ct[i]) - int(score_pt[i])) % 10 for i in range(len(score_pt))]
print(f"Keystream (mod 10): {ks_mod10}")

# Compute keystream mod 26 for letters (using known flag prefix)
flag_prefix = "INFODAYS"
flag_prefix_len = len(flag_prefix)

ks_mod26 = []
for i in range(flag_prefix_len):
    pt = ord(flag_prefix[i]) - ord('A')
    ct = ord(flag_ct[i]) - ord('A')
    ks_mod26.append((ct - pt) % 26)

print(f"Keystream (mod 26) from flag prefix: {ks_mod26}")

# Notice the pattern - after a few steps, keystream becomes constant
# For digits, after position 8, ks_mod10 = 8
# So we can assume the keystream stabilizes

# Decrypt the flag using the stabilized keystream
# We need to find the correct ks_mod26 for each position
# Since the flag is "INFODAYS{...}", we can use that to find the pattern

# Try to deduce the keystream pattern
# The keystream might be the same for all positions after a while
# Let's try to decrypt assuming ks is constant after a point

# First, let's get the full keystream by solving the LCG
# But simpler: since we have both digit and letter ks, we can find the actual ks values

# The keystream is (x ^ (y >> 8)) & 0xFFFF
# For digits, we only know ks % 10
# For letters, we only know ks % 26
# We need to find ks that satisfy both for consistent positions

# Let's just brute force the possible ks values for the first position
for ks_test in range(0, 0x10000):
    if ks_test % 10 == ks_mod10[0] and ks_test % 26 == ks_mod26[0]:
        print(f"Possible ks for position 0: {ks_test}")

# Given the complexity, let's just try to decrypt with the assumption that ks is the same for all positions
# Use the ks from the first position to decrypt everything
ks_assumed = None
for ks_test in range(0, 0x10000):
    if ks_test % 10 == ks_mod10[0]:
        ks_assumed = ks_test
        break

if ks_assumed:
    print(f"\n[*] Trying to decrypt with ks = {ks_assumed}")
    
    # Decrypt flag with constant ks
    flag = []
    for ch in flag_ct:
        if ch.isalpha():
            base = ord('A')
            dec = chr((ord(ch) - base - ks_assumed) % 26 + base)
            flag.append(dec)
        else:
            flag.append(ch)
    
    print(f"[+] Result: {''.join(flag)}")
    
    # Check if it looks like a flag
    if "INFODAYS" in ''.join(flag) or "INFODAYS" in ''.join(flag).upper():
        print("[+] Success! This looks like the flag")
    else:
        print("[-] Not the correct flag, trying alternative...")
        
        # Try with ks from flag prefix
        for ks_test in range(0, 0x10000):
            if ks_test % 26 == ks_mod26[0]:
                flag = []
                for ch in flag_ct:
                    if ch.isalpha():
                        base = ord('A')
                        dec = chr((ord(ch) - base - ks_test) % 26 + base)
                        flag.append(dec)
                    else:
                        flag.append(ch)
                
                result = ''.join(flag)
                if "INFODAYS" in result:
                    print(f"[+] FLAG FOUND: {result}")
                    break
