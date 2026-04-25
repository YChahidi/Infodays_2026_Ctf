"""
LAYER 2: FORENSIC ANALYSIS - 10 DIGIT NUMERIC BRUTE FORCE
========================================================

Challenge:
- 6 networks with encrypted traffic
- Only 1 is REAL (contains REAL flag string)
- 2 networks contain FAKE flag strings (misleads)
- Each has a 10-digit PIN that follows a PATTERN
- CLUES hidden in beacon fields (channel, beacon interval)
- Players must find clues, brute force, and identify REAL vs FAKE flags
- Real network is DeviceSync (network_5)
"""
import os
from scapy.all import *
from Crypto.Cipher import AES
import hashlib
import os
import time

LAYER2_DIR = "layer2_captures"
REAL_FLAG_STRING = os.environ["FLAG"]  # hada gha whats between {..... } , ya3ni infodays{REAL_FLAG_STRING}
FAKE_FLAG_1 = "ExternalThreatAlert"  # Decoy 1
FAKE_FLAG_2 = "SystemCompromised"    # Decoy 2

# Network definitions WITH HIDDEN CLUES AND FAKE FLAGS
NETWORKS = [
    {
        "name": "network_1",
        "ssid": "CorpNet_A",
        "bssid": "00:11:22:33:44:55",
        "psk": "2026042401",
        "is_real": False,
        "is_fake_flag": True,  # Contains FAKE flag
        "flag_string": FAKE_FLAG_1,
        "pattern": "Date-based",
        "channel": 6,
        "beacon_interval": 100,
    },
    {
        "name": "network_2",
        "ssid": "CorpNet_B",
        "bssid": "00:11:22:33:44:66",
        "psk": "1111111111",
        "is_real": False,
        "is_fake_flag": False,
        "flag_string": None,
        "pattern": "Repeating",
        "channel": 1,
        "beacon_interval": 111,
    },
    {
        "name": "network_3",
        "ssid": "GuestNet",
        "bssid": "00:11:22:33:44:77",
        "psk": "5555555555",
        "is_real": False,
        "is_fake_flag": True,  # Contains FAKE flag
        "flag_string": FAKE_FLAG_2,
        "pattern": "Repeating",
        "channel": 11,
        "beacon_interval": 555,
    },
    {
        "name": "network_4",
        "ssid": "AdminNet",
        "bssid": "00:11:22:33:44:88",
        "psk": "9876543210",
        "is_real": False,
        "is_fake_flag": False,
        "flag_string": None,
        "pattern": "Reverse Sequential",
        "channel": 9,
        "beacon_interval": 987,
    },
    {
        "name": "network_5",
        "ssid": "DeviceSync",
        "bssid": "00:11:22:33:44:99",
        "psk": "8888888888",  # ALL 8s
        "is_real": True,
        "is_fake_flag": False,
        "flag_string": REAL_FLAG_STRING,  # REAL FLAG
        "pattern": "Repeating",
        "channel": 8,
        "beacon_interval": 888,
    },
    {
        "name": "network_6",
        "ssid": "BackupAP",
        "bssid": "00:11:22:33:44:AA",
        "psk": "0000000000",
        "is_real": False,
        "is_fake_flag": False,
        "flag_string": None,
        "pattern": "All Zeros",
        "channel": 13,
        "beacon_interval": 100,
    },
]

def encrypt_payload(password, data, ssid):
    """Encrypt with AES-CBC"""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), ssid.encode(), 4096)[:32]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = data.encode() if isinstance(data, str) else data
    padding_len = 16 - (len(msg) % 16)
    msg = msg + bytes([padding_len] * padding_len)
    return iv + cipher.encrypt(msg)

def create_beacon(ssid, bssid, channel, beacon_interval, seq=0):
    """Create beacon frame WITH HIDDEN CLUES IN BEACON FIELDS"""
    beacon = (
        RadioTap(channel=(2407 + channel * 5, 0x00a0)) /
        Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
              addr2=bssid, addr3=bssid, SC=seq) /
        Dot11Beacon(beacon_interval=beacon_interval, cap="ESS+privacy") /
        Dot11Elt(ID="SSID", info=ssid.encode()) /
        Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96") /
        Dot11Elt(ID="DSset", info=bytes([channel]))  # Channel info
    )
    
    return beacon

def create_data_frame(ap, client, payload, seq=0):
    """Create data frame"""
    return (
        RadioTap() /
        Dot11(type=2, subtype=0, addr1=ap, addr2=client, addr3=ap, 
              FCfield=0x4100, SC=seq) /
        LLC() /
        SNAP() /
        Raw(load=payload)
    )

if not os.path.exists(LAYER2_DIR):
    os.makedirs(LAYER2_DIR)

print("[*] LAYER 2: 10-Digit Numeric Brute Force Challenge")
print("[*] Generating challenge files with hidden beacon clues...\n")

for idx, network in enumerate(NETWORKS, 1):
    packets = []
    is_real = network["is_real"]
    is_fake = network["is_fake_flag"]
    
    print(f"[{idx}/{len(NETWORKS)}] {network['name']}")
    print(f"      SSID: {network['ssid']}")
    print(f"      PIN: {network['psk']}")
    print(f"      Pattern: {network['pattern']}")
    print(f"      Channel: {network['channel']} (hidden clue)")
    print(f"      Beacon Interval: {network['beacon_interval']}ms (hidden clue)")
    
    if is_real:
        print(f"      ★ REAL NETWORK ★")
        print(f"      Contains: {REAL_FLAG_STRING}")
    elif is_fake:
        print(f"      [FAKE FLAG DECOY]")
        print(f"      Contains: {network['flag_string']}")
    else:
        print(f"      [DECOY] - No flag")
    
    seq = 0
    base_time = time.time()
    
    # === BEACONS WITH HIDDEN CLUES IN FIELDS ===
    for i in range(20):
        beacon_pkt = create_beacon(
            network["ssid"], 
            network["bssid"],
            network["channel"],
            network["beacon_interval"],
            seq
        )
        beacon_pkt.time = base_time + (seq * 0.1)
        packets.append(beacon_pkt)
        seq += 1
    
    # === DATA FRAMES ===
    clients = [
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66",
        "DE:AD:BE:EF:CA:FE"
    ]
    
    if is_real or is_fake:
        # REAL or FAKE network - contains flag string
        traffic_payloads = [
            "SessionID: 0x12345678",
            "UserID: admin",
            "Action: DataExport",
            "Timestamp: 2026-04-24T14:23:51Z",
            "LogLevel: CRITICAL",
            f"SecurityAlert: {network['flag_string']}",
            "Status: LOGGED",
            "EventID: 9001",
            "Source: InternalServer",
            "Destination: SecureVault",
            "Priority: HIGH",
            "Response: Required",
        ]
    else:
        # DECOY networks - normal traffic (no flags)
        traffic_payloads = [
            "SessionID: 0xAABBCCDD",
            "UserID: guest",
            "Data: NormalTraffic",
            "Status: OK",
            "Connection: Established",
            "Timestamp: 2026-04-24T14:20:00Z",
            "Message: KeepAlive",
            "Heartbeat: Active",
        ]
    
    # Create encrypted frames
    for i in range(40):
        client = clients[i % len(clients)]
        payload_text = traffic_payloads[i % len(traffic_payloads)]
        
        # Encrypt with PIN
        encrypted = encrypt_payload(network["psk"], payload_text, network["ssid"])
        
        # AP -> Client
        data_pkt1 = create_data_frame(network["bssid"], client, encrypted, seq)
        data_pkt1.time = base_time + (seq * 0.1)
        packets.append(data_pkt1)
        seq += 1
        
        # Client -> AP
        data_pkt2 = create_data_frame(client, network["bssid"], encrypted, seq)
        data_pkt2.time = base_time + (seq * 0.1)
        packets.append(data_pkt2)
        seq += 1
    
    # Save PCAP
    output_file = f"{LAYER2_DIR}/{network['name']}.pcap"
    wrpcap(output_file, packets)
    print(f"      ✓ Created {output_file}\n")

print("\n" + "="*70)
print("LAYER 2: 10-DIGIT NUMERIC BRUTE FORCE - CHALLENGE GENERATED")
print("="*70)
print(f"\nChallenge Summary:")
print(f"  Total networks: {len(NETWORKS)}")
print(f"  Real networks: 1 (DeviceSync)")
print(f"  Networks with flags: 3 (1 real + 2 fake decoys)")
print(f"  Decoy networks: {len(NETWORKS) - 3}")
print(f"\nFlags Found:")
for net in NETWORKS:
    if net["is_fake_flag"] or net["is_real"]:
        status = "★ REAL" if net["is_real"] else "✗ FAKE"
        print(f"  {net['ssid']:15} → {net['flag_string']:30} {status}")
print(f"\nHidden Clues (in beacon fields):")
print(f"  Channel number = hint")
print(f"  Beacon interval = hint")
print(f"\nClue Map:")
for net in NETWORKS:
    if net["is_real"]:
        status = "★ REAL"
    elif net["is_fake_flag"]:
        status = "✗ FAKE FLAG"
    else:
        status = "DECOY"
    print(f"  {net['ssid']:15} Ch:{net['channel']} Interval:{net['beacon_interval']:4} → PIN: {net['psk']} {status}")
print(f"\nStrategy:")
print(f"  1. Extract SSID from each PCAP")
print(f"  2. Check beacon channel and interval")
print(f"  3. Analyze patterns in beacon details")
print(f"  4. Generate PIN patterns based on hints")
print(f"  5. Brute force each network")
print(f"  6. Identify which networks decrypt successfully")
print(f"  7. Extract flags (3 will decrypt)")
print(f"  8. Determine which flag is REAL vs FAKE")
print(f"  9. Real flag from network with strongest indicators")
print("="*70)