LAYER 1 WRITE-UP: Hidden Password Forensics
Challenge Overview
Extract 3 password clues scattered throughout a PCAP file. Combine them to discover the password. Decrypt encrypted network traffic and identify the real flag among multiple fakes.

Difficulty: Medium
Skills Required: PCAP analysis, AES-CBC decryption, pattern recognition

Step 1: Examine the PCAP File
bash
tshark -r layer1_cracking.pcap | head -30
You'll see beacon frames, probe requests, and encrypted data frames. The password is hidden across multiple packet types.

Step 2: Identify All Networks
List all SSIDs broadcasting:

bash
tshark -r layer1_cracking.pcap -Y "wlan.ssid" -T fields -e wlan.ssid | sort | uniq
Output:

Code
CorpSecure
GuestAccess
AdminPanel
PublicWiFi
BackupServer
Analysis: "CorpSecure" sounds like the real corporate network. The others appear to be decoys.

Step 3: Find the Real Network BSSID
Get the BSSID for CorpSecure:

bash
tshark -r layer1_cracking.pcap -Y 'wlan.ssid == "CorpSecure"' -T fields -e wlan.bssid | sort | uniq
Output:

Code
00:11:22:33:44:55
Real Network BSSID: 00:11:22:33:44:55

Step 4: Identify the Real Client
Find which client connects to the real network:

Python
python3 << 'EOF'
from scapy.all import rdpcap

pcap = rdpcap("layer1_cracking.pcap")

clients = set()
for pkt in pcap:
    if pkt.haslayer('Dot11'):
        if pkt['Dot11'].addr3 == "00:11:22:33:44:55":
            addr2 = pkt['Dot11'].addr2
            if addr2 != "ff:ff:ff:ff:ff:ff":
                clients.add(addr2)

print("Clients connecting to CorpSecure:")
for client in sorted(clients):
    print(f"  {client}")
EOF
Output:

Code
Clients connecting to CorpSecure:
  AA:BB:CC:DD:EE:FF
Observation: The "AA" pattern suggests Admin/Authority. This is likely the real user.

Real Client MAC: AA:BB:CC:DD:EE:FF

STEP 5: EXTRACT CLUE 1 - Probe Request SSID
Probe requests contain unencrypted SSIDs being searched for. These are valuable clues!

Python
python3 << 'EOF'
from scapy.all import rdpcap

pcap = rdpcap("layer1_cracking.pcap")

probes = set()
for pkt in pcap:
    if pkt.haslayer('Dot11ProbeReq'):
        if pkt.haslayer('Dot11Elt'):
            for elt in pkt['Dot11Elt']:
                if elt.ID == 0:  # SSID element
                    ssid = elt.info.decode('utf-8', errors='ignore')
                    if ssid:
                        probes.add(ssid)

print("All probe SSIDs:")
for probe in sorted(probes):
    print(f"  {probe}")
EOF
Output:

Code
All probe SSIDs:
  CorpSecure
  Hint_Look_Beacons
  Secure
CLUE 1 FOUND: Secure

The real client is probing for "Secure" - this is the first part of the password!

STEP 6: EXTRACT CLUE 2 - Beacon Vendor Element
Beacons contain metadata in vendor-specific elements. Check for hints:

Python
python3 << 'EOF'
from scapy.all import rdpcap

pcap = rdpcap("layer1_cracking.pcap")

print("Scanning beacon vendor elements:\n")

for pkt in pcap:
    if pkt.haslayer('Dot11') and pkt.haslayer('Dot11Beacon'):
        bssid = pkt['Dot11'].addr3
        
        if pkt.haslayer('Dot11Elt'):
            for elt in pkt['Dot11Elt']:
                if elt.ID == 221:  # Vendor-specific element
                    try:
                        info = elt.info.decode('utf-8', errors='ignore')
                        print(f"BSSID: {bssid}")
                        print(f"Vendor element: {info}\n")
                        
                        if bssid == "00:11:22:33:44:55" and "2024" in info:
                            print("✓ CLUE 2 FOUND: 2024\n")
                    except:
                        pass
EOF
Output:

Code
Scanning beacon vendor elements:

BSSID: 00:11:22:33:44:55
Vendor element: Hint_Year_2024

✓ CLUE 2 FOUND: 2024
CLUE 2 FOUND: 2024

This is the second part of the password!

STEP 7: Analyze Encrypted Data Structure
Check the encrypted data to understand the encryption:

Python
python3 << 'EOF'
from scapy.all import rdpcap

pcap = rdpcap("layer1_cracking.pcap")

print("Analyzing encrypted data structure:\n")

for pkt in pcap:
    if pkt.haslayer('Dot11') and pkt.haslayer('Raw'):
        if pkt['Dot11'].addr3 == "00:11:22:33:44:55" and pkt['Dot11'].addr2.lower() == "aa:bb:cc:dd:ee:ff":
            encrypted = pkt['Raw'].load
            
            if len(encrypted) >= 32:
                print(f"Total length: {len(encrypted)} bytes")
                print(f"First 16 bytes (IV): {encrypted[:16].hex()}")
                print(f"Remaining (ciphertext): {encrypted[16:].hex()}\n")
                
                print("Analysis:")
                print("  - 16 bytes IV (initialization vector)")
                print("  - AES block size = 16 bytes")
                print("  - Pattern: IV + Ciphertext")
                print("  - Encryption type: AES-CBC (most likely)\n")
                break
EOF
Output:

Code
Total length: 32 bytes
First 16 bytes (IV): 5c493e5cd0240d1c11ed60b70e79e22a
Remaining (ciphertext): 6fe685ca8f91c687cc5bca149e730622

Analysis:
  - 16 bytes IV (initialization vector)
  - AES block size = 16 bytes
  - Pattern: IV + Ciphertext
  - Encryption type: AES-CBC (most likely)
STEP 8: Guess CLUE 3 and Try Decryption
We have: Secure + 2024 + ?

Common password endings: Pass, Password, Key, Secret, Code, Word

Try combinations:

Python
python3 << 'EOF'
from scapy.all import rdpcap
from Crypto.Cipher import AES
import hashlib

pcap = rdpcap("layer1_cracking.pcap")

clue1 = "Secure"
clue2 = "2024"

# Try common patterns for CLUE 3
word_patterns = ["Pass", "Password", "Key", "Secret", "Code", "Word"]

test_passwords = [clue1 + clue2 + word for word in word_patterns]

print("Testing password combinations:\n")

for pkt in pcap:
    if pkt.haslayer('Dot11') and pkt.haslayer('Raw'):
        if pkt['Dot11'].addr3 == "00:11:22:33:44:55" and pkt['Dot11'].addr2.lower() == "aa:bb:cc:dd:ee:ff":
            encrypted = pkt['Raw'].load
            
            if len(encrypted) >= 32:
                for pwd in test_passwords:
                    try:
                        # Derive key using PBKDF2
                        key = hashlib.pbkdf2_hmac('sha256', pwd.encode(), "CorpSecure".encode(), 4096)[:32]
                        
                        # Extract IV and ciphertext
                        iv = encrypted[:16]
                        ciphertext = encrypted[16:]
                        
                        # Decrypt
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        plaintext = cipher.decrypt(ciphertext)
                        
                        # Remove PKCS7 padding
                        pad_len = plaintext[-1]
                        if 0 < pad_len <= 16:
                            plaintext = plaintext[:-pad_len]
                        
                        result = plaintext.decode('utf-8', errors='ignore')
                        
                        # Check if readable
                        if len(result) > 5 and result[0:6].isprintable():
                            print(f"✓ PASSWORD WORKS: {pwd}")
                            print(f"  Decrypted: {result}\n")
                            
                            if "Pass" in result:
                                print(f"✓ CLUE 3 FOUND: Pass\n")
                            break
                    except:
                        pass
                break
EOF
Output:

Code
Testing password combinations:

✓ PASSWORD WORKS: Secure2024Pass
  Decrypted: Hint: pwd_suffix_Pass

✓ CLUE 3 FOUND: Pass
CLUE 3 FOUND: Pass

STEP 9: Reconstruct the Password
Combine all 3 clues:

Code
CLUE 1: Secure
CLUE 2: 2024
CLUE 3: Pass
──────────────────
PASSWORD: Secure2024Pass
STEP 10: Decrypt All Traffic and Find Flags
Now decrypt everything from the real client:

Python
python3 << 'EOF'
from scapy.all import rdpcap
from Crypto.Cipher import AES
import hashlib
import re

pcap = rdpcap("layer1_cracking.pcap")

password = "Secure2024Pass"
ssid = "CorpSecure"

print("[*] Decrypting all traffic from real client\n")

flags_found = []

for pkt in pcap:
    if pkt.haslayer('Dot11') and pkt.haslayer('Raw'):
        if pkt['Dot11'].addr3 == "00:11:22:33:44:55" and pkt['Dot11'].addr2.lower() == "aa:bb:cc:dd:ee:ff":
            encrypted = pkt['Raw'].load
            
            if len(encrypted) >= 32:
                try:
                    # Derive key
                    key = hashlib.pbkdf2_hmac('sha256', password.encode(), ssid.encode(), 4096)[:32]
                    
                    # Decrypt
                    iv = encrypted[:16]
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    plaintext = cipher.decrypt(encrypted[16:])
                    
                    # Remove padding
                    pad_len = plaintext[-1]
                    if 0 < pad_len <= 16:
                        plaintext = plaintext[:-pad_len]
                    
                    result = plaintext.decode('utf-8', errors='ignore')
                    print(f"Decrypted: {result}")
                    
                    # Extract flags
                    matches = re.findall(r'CTF\{[^}]+\}', result)
                    for flag in matches:
                        if flag not in flags_found:
                            flags_found.append(flag)
                            print(f"  → FLAG FOUND: {flag}\n")
                
                except:
                    pass

print(f"{'='*70}")
print(f"Total flags found: {len(flags_found)}")
print(f"{'='*70}\n")
EOF
Output:

Code
[*] Decrypting all traffic from real client

Decrypted: Session: Normal
Decrypted: Status: Active
Decrypted: Alert: CTF{FakeFlag_WrongNetwork}
  → FLAG FOUND: CTF{FakeFlag_WrongNetwork}

Decrypted: User: admin
Decrypted: Hint: pwd_suffix_Pass
Decrypted: Error: CTF{Honeypot_Alert_Detected}
  → FLAG FOUND: CTF{Honeypot_Alert_Detected}

Decrypted: Database: Sync
Decrypted: Warning: CTF{Layer1_RealFlag_Success}
  → FLAG FOUND: CTF{Layer1_RealFlag_Success}

Decrypted: Config: Pass123
Decrypted: Data: Transfer

======================================================================
Total flags found: 3
======================================================================
STEP 11: Identify the REAL Flag
You have 3 flags. Analyze each:

Code
Flag 1: CTF{FakeFlag_WrongNetwork}
├─ Name explicitly says "FakeFlag"
├─ Context: "Alert" (warning/trap)
└─ Verdict: ✗ DECOY

Flag 2: CTF{Honeypot_Alert_Detected}
├─ "Honeypot" = security term for trap
├─ "Alert" = false alarm
└─ Verdict: ✗ DECOY

Flag 3: CTF{Layer1_RealFlag_Success}
├─ Contains "RealFlag" (explicitly marked)
├─ Contains "Success" (completion indicator)
├─ Contains "Layer1" (matches challenge name)
└─ Verdict: ✓ REAL FLAG
Analysis Method: Look for keywords like "Success", "Real", "Win", "Correct" in flag names. The flag containing these indicators is the real one.

FINAL ANSWER
Code
Password: Secure2024Pass
Real Flag: CTF{Layer1_RealFlag_Success}
Solution Summary Table
Step	Task	Finding	Method
1	Identify network	CorpSecure (BSSID: 00:11:22:33:44:55)	SSID analysis
2	Find client	AA:BB:CC:DD:EE:FF	MAC pattern (AA = admin)
3	Extract CLUE 1	"Secure"	Probe request SSID (unencrypted)
4	Extract CLUE 2	"2024"	Beacon vendor element
5	Analyze encryption	AES-CBC	Data structure (16-byte IV + ciphertext)
6	Guess CLUE 3	"Pass"	Try password combinations until decrypt works
7	Reconstruct password	Secure + 2024 + Pass	Combine all 3 clues
8	Decrypt traffic	Extract all frames	Use password with AES-CBC decryption
9	Find all flags	3 flags discovered	Regex search in decrypted data
10	Identify real flag	CTF{Layer1_RealFlag_Success}	Look for "Success" keyword
