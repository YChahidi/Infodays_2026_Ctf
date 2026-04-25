"""
LAYER 1: CLUES HIDDEN IN PCAP
=============================

Challenge:
- Password hidden as clues scattered in PCAP
- Clue 1: Hidden in unencrypted probe request
- Clue 2: Hidden in beacon frame info
- Clue 3: Hidden in client MAC sequence
- At least 3 FAKE flags
- Players must extract clues from PCAP, combine them, decrypt

NO BRUTE FORCE - Password only discoverable through analysis
"""

from scapy.all import *
from Crypto.Cipher import AES
import hashlib
import os
import time

OUTPUT_FILE = "layer1_cracking.pcap"

# Real network
REAL_SSID = "CorpSecure"
REAL_BSSID = "00:11:22:33:44:55"
REAL_CLIENT = "AA:BB:CC:DD:EE:FF"
REAL_PASSWORD = "Secure2024Pass"
REAL_FLAG =os.environ["FLAG"]

# PASSWORD CLUES (scattered in PCAP):
# Clue 1 (in probe request): "Secure"
# Clue 2 (in beacon): "2024"
# Clue 3 (in data frame comment/pattern): "Pass"
# Combined: Secure + 2024 + Pass = Secure2024Pass

# Fake networks
FAKE_NETWORKS = [
    ("GuestAccess", "11:22:33:44:55:66"),
    ("AdminPanel", "22:33:44:55:66:77"),
    ("PublicWiFi", "33:44:55:66:77:88"),
]

FAKE_CLIENTS = [
    "DE:AD:BE:EF:00:01",
    "DE:AD:BE:EF:00:02",
    "DE:AD:BE:EF:00:03",
]

# FAKE FLAGS (at least 3)
FAKE_FLAG_1 = "CTF{CAMpusNetwork}"
FAKE_FLAG_2 = "CTF{Honeypot_Alert_Detected}"
FAKE_FLAG_3 = "CTF{TestServer_Backup}"

packets = []

def encrypt_payload(password, data, ssid):
    """Encrypt with AES-CBC"""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), ssid.encode(), 4096)[:32]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = data.encode() if isinstance(data, str) else data
    padding_len = 16 - (len(msg) % 16)
    msg = msg + bytes([padding_len] * padding_len)
    return iv + cipher.encrypt(msg)

print("[*] LAYER 1: CLUES HIDDEN IN PCAP")
print(f"[*] Password: {REAL_PASSWORD}")
print(f"[*] Password made of 3 clues scattered in PCAP\n")

seq = 0
base_time = time.time()

print("[+] Generating REAL network with CLUES...\n")

# ===== CLUE 1: In PROBE REQUEST (unencrypted) =====
print("[+] Embedding CLUE 1 in probe request: 'Secure'")

probe_request_clue1 = (
    RadioTap() /
    Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", 
          addr2=REAL_CLIENT, addr3="ff:ff:ff:ff:ff:ff", SC=seq) /
    Dot11ProbeReq() /
    Dot11Elt(ID="SSID", info=b"Secure")  # CLUE 1: First part of password
)
probe_request_clue1.time = base_time + (seq * 0.01)
packets.append(probe_request_clue1)
seq += 1

# ===== BEACON WITH CLUE 2 =====
print("[+] Embedding CLUE 2 in beacon: '2024'")

for i in range(20):
    beacon = (
        RadioTap() /
        Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
              addr2=REAL_BSSID, addr3=REAL_BSSID, SC=seq) /
        Dot11Beacon(cap="ESS+privacy") /
        Dot11Elt(ID="SSID", info=REAL_SSID.encode())
    )
    
    # CLUE 2: In beacon info element (second beacon)
    if i == 1:
        beacon = beacon / Dot11Elt(ID=0x01, info=b"Supported_Rates_2024")  # CLUE 2: Year hint
    
    # CLUE 2 also in vendor element
    if i == 0:
        beacon = beacon / Dot11Elt(ID=221, info=b"Hint_Year_2024")
    
    pkt = beacon
    pkt.time = base_time + (seq * 0.01)
    packets.append(pkt)
    seq += 1

# ===== CLUE 3: In DATA FRAME PAYLOAD (encrypted) =====
print("[+] Embedding CLUE 3 in encrypted data: 'Pass'")

# Real encrypted data - mix with fake flags AND hidden clue
real_data_payloads = [
    "Session: Normal",
    "Status: Active",
    f"Alert: {FAKE_FLAG_1}",  # FAKE FLAG 1
    "User: admin",
    "Hint: pwd_suffix_Pass",  # CLUE 3: Third part of password hidden
    f"Error: {FAKE_FLAG_2}",  # FAKE FLAG 2
    "Database: Sync",
    f"Warning: {REAL_FLAG}",  # REAL FLAG
    "Config: Pass123",  # Another hint to confuse
    "Data: Transfer",
]

for i, payload in enumerate(real_data_payloads):
    encrypted = encrypt_payload(REAL_PASSWORD, payload, REAL_SSID)
    data_pkt = (
        RadioTap() /
        Dot11(type=2, subtype=0, addr1=REAL_BSSID, addr2=REAL_CLIENT, 
              addr3=REAL_BSSID, FCfield=0x4100, SC=seq) /
        LLC() /
        SNAP() /
        Raw(load=encrypted)
    )
    data_pkt.time = base_time + (seq * 0.01)
    packets.append(data_pkt)
    seq += 1

print("[+] Generating FAKE networks...\n")

# ===== FAKE NETWORKS =====
for fake_ssid, fake_bssid in FAKE_NETWORKS:
    # Beacons
    for i in range(12):
        beacon = (
            RadioTap() /
            Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
                  addr2=fake_bssid, addr3=fake_bssid, SC=seq) /
            Dot11Beacon(cap="ESS+privacy") /
            Dot11Elt(ID="SSID", info=fake_ssid.encode())
        )
        
        # Add misleading hints
        if i == 0:
            beacon = beacon / Dot11Elt(ID=221, info=b"Hint_Wrong_Password123")
        
        pkt = beacon
        pkt.time = base_time + (seq * 0.01)
        packets.append(pkt)
        seq += 1
    
    # Fake encrypted data
    for fake_client in FAKE_CLIENTS:
        for j in range(3):
            wrong_passwords = [
                "WrongPassword123",
                "AdminPass2024",
                "TestPassword"
            ]
            
            fake_payloads = [
                f"Data: {FAKE_FLAG_1}",
                f"Flag: {FAKE_FLAG_2}",
                f"System: {FAKE_FLAG_3}",
            ]
            
            payload = fake_payloads[j % len(fake_payloads)]
            pwd = wrong_passwords[j % len(wrong_passwords)]
            
            encrypted = encrypt_payload(pwd, payload, fake_ssid)
            
            data_pkt = (
                RadioTap() /
                Dot11(type=2, subtype=0, addr1=fake_bssid, addr2=fake_client, 
                      addr3=fake_bssid, FCfield=0x4100, SC=seq) /
                LLC() /
                SNAP() /
                Raw(load=encrypted)
            )
            data_pkt.time = base_time + (seq * 0.01)
            packets.append(data_pkt)
            seq += 1

print("[+] Adding unencrypted DECOY frames...\n")

# Unencrypted fake frames
decoy_unencrypted = [
    f"DEBUG: {FAKE_FLAG_1}",
    f"ADMIN: {FAKE_FLAG_2}",
    f"CACHE: {FAKE_FLAG_3}",
    b"Log: CTF{Fake_Unencrypted}",
    b"Hint: Try_Password_Admin123",
]

for payload in decoy_unencrypted:
    if isinstance(payload, str):
        payload = payload.encode()
    
    decoy_pkt = (
        RadioTap() /
        Dot11(type=2, subtype=0, addr1=FAKE_NETWORKS[0][1], addr2=FAKE_CLIENTS[0], 
              addr3=FAKE_NETWORKS[0][1], FCfield=0x4100, SC=seq) /
        LLC() /
        SNAP() /
        Raw(load=payload)
    )
    decoy_pkt.time = base_time + (seq * 0.01)
    packets.append(decoy_pkt)
    seq += 1

print("[+] Shuffling packets...\n")

random.shuffle(packets)

# Re-timestamp
for i, pkt in enumerate(packets):
    pkt.time = base_time + (i * 0.01)

wrpcap(OUTPUT_FILE, packets)

print("\n" + "="*70)
print("LAYER 1: CLUES IN PCAP GENERATED")
print("="*70)
print(f"Output: {OUTPUT_FILE}")
print()
print("Challenge Overview:")
print(f"  Real Network: {REAL_SSID}")
print(f"  Real BSSID: {REAL_BSSID}")
print(f"  Real Client: {REAL_CLIENT}")
print()
print("PASSWORD CLUES (scattered in PCAP):")
print()
print("  CLUE 1: In PROBE REQUEST (unencrypted)")
print("    - Look for probe requests from real client")
print("    - SSID being probed contains: 'Secure'")
print("    - This is part 1 of password")
print()
print("  CLUE 2: In BEACON FRAME INFO")
print("    - Check beacon frame elements")
print("    - Look for vendor elements or info elements")
print("    - Contains: '2024'")
print("    - This is part 2 of password")
print()
print("  CLUE 3: In ENCRYPTED DATA")
print("    - Extract and decrypt data from real client")
print("    - Unencrypted traffic contains hints")
print("    - Contains: 'Pass'")
print("    - This is part 3 of password")
print()
print("PASSWORD FORMULA:")
print("  Clue 1 + Clue 2 + Clue 3 = Password")
print("  Secure + 2024 + Pass = Secure2024Pass")
print()
print("REAL FLAG (encrypted):")
print(f"  {REAL_FLAG}")
print()
print("FAKE FLAGS (ignore):")
print(f"  - {FAKE_FLAG_1}")
print(f"  - {FAKE_FLAG_2}")
print(f"  - {FAKE_FLAG_3}")
print("="*70)