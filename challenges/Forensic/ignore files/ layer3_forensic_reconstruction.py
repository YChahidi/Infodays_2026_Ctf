from scapy.all import *
import random
import time

# =========================================================
# ADVANCED FORENSIC WIFI CTF GENERATOR
# =========================================================
# FINAL FLAG:
# CTF{CorpNet_48291}
#
# Players must:
# 1. Identify suspicious AP
# 2. Extract string part from real SSID (CorpNet)
# 3. Track the legitimate client
# 4. Ignore fake clues
# 5. Reconstruct numeric fragments: 48 + 29 + 1
# =========================================================

OUTPUT_FILE = "layer3_cracking.pcap"

TARGET = {
    "ssid": "CorpNet_Internal",
    "bssid": "00:14:22:01:23:45",
    "channel": 6,
}

REAL_CLIENT = "AA:BB:CC:11:22:33"

STRING_PART = "CorpNet"
FLAG_PART_1 = "48"
FLAG_PART_2 = "29"
FLAG_PART_3 = "1"

DECOY_NETWORKS = [
    ("CorpNet_Guest", "00:14:22:01:23:46", 1),
    ("CorpNet_Admin", "00:14:22:01:23:47", 11),
    ("CorpNet_5G", "00:14:22:01:23:48", 3),
    ("AdminPanel", "00:14:22:01:23:49", 9),
    ("Printer_AP", "00:14:22:01:23:50", 7),
    ("FreeAirportWiFi", "00:14:22:01:23:51", 4),
]

DECOY_CLIENTS = [
    "DE:AD:BE:EF:00:01",
    "DE:AD:BE:EF:00:02",
    "DE:AD:BE:EF:00:03",
    "DE:AD:BE:EF:00:04",
]

packets = []


def beacon(ssid, bssid, channel):
    return (
        RadioTap() /
        Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid
        ) /
        Dot11Beacon(cap="ESS+privacy") /
        Dot11Elt(ID="SSID", info=ssid.encode()) /
        Dot11Elt(ID="DSset", info=bytes([channel]))
    )



def probe_request(client):
    return (
        RadioTap() /
        Dot11(
            type=0,
            subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=client,
            addr3="ff:ff:ff:ff:ff:ff"
        ) /
        Dot11ProbeReq() /
        Dot11Elt(ID="SSID", info=b"")
    )



def normal_data(client, ap):
    noise = [
        b"TLS Application Data",
        b"POST /internal/api/upload",
        b"Database Sync Request",
        b"Encrypted Backup Transfer",
        b"Authentication Session Active",
    ]

    return (
        RadioTap() /
        Dot11(
            type=2,
            subtype=0,
            addr1=ap,
            addr2=client,
            addr3=ap
        ) /
        LLC() /
        SNAP() /
        Raw(load=random.choice(noise))
    )



def fake_flag_packet(client, ap):
    fake_values = ["12345", "88888", "54321", "77777", "11111"]

    payload = f"""
DEBUG LOG
FLAG_PART={random.choice(fake_values)}
Temporary credentials cached
Ignore debug session
""".encode()

    return (
        RadioTap() /
        Dot11(
            type=2,
            subtype=0,
            addr1=ap,
            addr2=client,
            addr3=ap
        ) /
        LLC() /
        SNAP() /
        Raw(load=payload)
    )



def hidden_hint_packet(client, ap):
    payload = b"""
IR Memo

Repeated values are not always truth.
Trust the client that completes the exchange.
Ignore isolated debug artifacts.
"""

    return (
        RadioTap() /
        Dot11(
            type=2,
            subtype=0,
            addr1=ap,
            addr2=client,
            addr3=ap
        ) /
        LLC() /
        SNAP() /
        Raw(load=payload)
    )



def real_flag_part_1(client, ap):
    payload = f"""
SECURITY INCIDENT REPORT
Host: internal-db-02
Session-ID: XJ-{FLAG_PART_1}
Priority: HIGH
""".encode()

    return (
        RadioTap() /
        Dot11(type=2, subtype=0, addr1=ap, addr2=client, addr3=ap) /
        LLC() / SNAP() / Raw(load=payload)
    )



def real_flag_part_2(client, ap):
    payload = f"""
AUTH MODULE
Validation Success
AuthToken: {FLAG_PART_2}
Integrity Verified
""".encode()

    return (
        RadioTap() /
        Dot11(type=2, subtype=0, addr1=ap, addr2=client, addr3=ap) /
        LLC() / SNAP() / Raw(load=payload)
    )



def real_flag_part_3(client, ap):
    payload = f"""
INCIDENT REF
Case confirmed
Reference-ID: {FLAG_PART_3}
SOC escalation complete
""".encode()

    return (
        RadioTap() /
        Dot11(type=2, subtype=0, addr1=ap, addr2=client, addr3=ap) /
        LLC() / SNAP() / Raw(load=payload)
    )



def fake_eapol(ap, client):
    return (
        RadioTap() /
        Dot11(type=2, subtype=8, addr1=ap, addr2=client, addr3=ap) /
        LLC() /
        SNAP() /
        EAPOL(version=2, type=3) /
        Raw(load=bytes(random.getrandbits(8) for _ in range(80)))
    )



def full_handshake(ap, client):
    return [
        fake_eapol(ap, client),
        RadioTap() / Dot11(type=2, subtype=8, addr1=client, addr2=ap, addr3=ap) / LLC() / SNAP() / EAPOL(version=2, type=3) / Raw(load=b"msg2_nonce_response"),
        fake_eapol(ap, client),
        RadioTap() / Dot11(type=2, subtype=8, addr1=client, addr2=ap, addr3=ap) / LLC() / SNAP() / EAPOL(version=2, type=3) / Raw(load=b"msg4_install_ack"),
    ]


for _ in range(100):
    packets.append(beacon(TARGET["ssid"], TARGET["bssid"], TARGET["channel"]))

for ssid, bssid, ch in DECOY_NETWORKS:
    for _ in range(50):
        packets.append(beacon(ssid, bssid, ch))

for client in DECOY_CLIENTS:
    for _ in range(20):
        packets.append(probe_request(client))
        fake_ap = random.choice(DECOY_NETWORKS)[1]
        packets.append(normal_data(client, fake_ap))
        packets.append(fake_flag_packet(client, fake_ap))
        packets.append(fake_eapol(fake_ap, client))

for _ in range(30):
    packets.append(probe_request(REAL_CLIENT))
    packets.append(normal_data(REAL_CLIENT, TARGET["bssid"]))

packets.extend(full_handshake(TARGET["bssid"], REAL_CLIENT))
packets.append(hidden_hint_packet(REAL_CLIENT, TARGET["bssid"]))
packets.append(real_flag_part_1(REAL_CLIENT, TARGET["bssid"]))
packets.append(real_flag_part_2(REAL_CLIENT, TARGET["bssid"]))
packets.append(real_flag_part_3(REAL_CLIENT, TARGET["bssid"]))

random.shuffle(packets)
base = time.time()

for i, pkt in enumerate(packets):
    pkt.time = base + (i * 0.03)

wrpcap(OUTPUT_FILE, packets)

print("=" * 70)
print("ADVANCED FORENSIC WIFI CTF GENERATED")
print("=" * 70)
print(f"File: {OUTPUT_FILE}")
print("FINAL FLAG: CTF{CorpNet_48291}")
print("=" * 70)