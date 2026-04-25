from scapy.all import *
from Crypto.Cipher import AES
import hashlib
import os
import random
import time

OUTPUT_FILE = "layer1_hard_forensic.pcap"

# =========================================================
# REAL TARGET
# =========================================================

REAL_NETWORK = {
    "ssid": "DeviceSync",
    "bssid": "00:11:22:33:44:55",
    "client": "AA:BB:CC:DD:EE:FF",
    "password": "Alpha2026Sync!",
    "flag": "infodays{Ghostly_L3akENc}"
}

# =========================================================
# FAKE NETWORKS
# =========================================================

FAKE_NETWORKS = [
    {
        "ssid": "CorpGuest",
        "bssid": "11:22:33:44:55:66",
        "password": "Guest123",
        "flag": "infodays{guest_network_breach}"
    },
    {
        "ssid": "Printer_AP",
        "bssid": "22:33:44:55:66:77",
        "password": "Printer2026",
        "flag": "infodays{printer_backup_flag}"
    },
    {
        "ssid": "AdminPanel",
        "bssid": "33:44:55:66:77:88",
        "password": "AdminRoot",
        "flag": "infodays{admin_fake_root}"
    },
    {
        "ssid": "BackupAP",
        "bssid": "44:55:66:77:88:99",
        "password": "BackupPass",
        "flag": "infodays{backup_server_leak}"
    },
    {
        "ssid": "LegacyIoT",
        "bssid": "55:66:77:88:99:AA",
        "password": "iot_device",
        "flag": "infodays{iot_honeypot}"
    }
]

packets = []
seq = 0
base_time = time.time()


# =========================================================
# HELPERS
# =========================================================


def next_seq():
    global seq
    seq += 1
    return seq & 0xFFF



def derive_key(password, ssid):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        ssid.encode(),
        5000
    )[:32]



def encrypt_payload(password, ssid, plaintext):
    key = derive_key(password, ssid)

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    data = plaintext.encode()
    pad = 16 - (len(data) % 16)
    data += bytes([pad] * pad)

    encrypted = cipher.encrypt(data)
    return iv + encrypted



def create_beacon(ssid, bssid, channel, clue=None):
    pkt = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
            SC=next_seq()
        )
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )

    if clue:
        pkt = pkt / Dot11Elt(ID=221, info=clue.encode())

    return pkt



def create_data(src, dst, bssid, payload):
    return (
        RadioTap()
        / Dot11(
            type=2,
            subtype=0,
            addr1=dst,
            addr2=src,
            addr3=bssid,
            FCfield=0x4100,
            SC=next_seq()
        )
        / LLC()
        / SNAP()
        / Raw(load=payload)
    )


# =========================================================
# REAL NETWORK
# =========================================================

print("[*] Generating REAL network...")

real_clues = [
    "VendorTag=Alpha",
    "BuildVersion=2026",
    "Service=Sync!"
]

for i in range(40):
    clue = real_clues[i % len(real_clues)] if i < 6 else None
    packets.append(
        create_beacon(
            REAL_NETWORK["ssid"],
            REAL_NETWORK["bssid"],
            11,
            clue
        )
    )

# make real flag subtle and rare
real_payloads = [
    "Session established",
    "Sync complete",
    "User authenticated",
    "Database replication started",
    "Node sync healthy",
    "Transfer complete",
    "Backup verification success",
    "Checksum validation passed",
    "Session closed"
]

# real flag appears ONLY ONCE
real_flag_index = random.randint(250, 650)

for i in range(700):
    if i == real_flag_index:
        plain = REAL_NETWORK["flag"]
    else:
        plain = random.choice(real_payloads)

    encrypted = encrypt_payload(
        REAL_NETWORK["password"],
        REAL_NETWORK["ssid"],
        plain
    )

    packets.append(
        create_data(
            REAL_NETWORK["client"],
            REAL_NETWORK["bssid"],
            REAL_NETWORK["bssid"],
            encrypted
        )
    )


# =========================================================
# FAKE NETWORKS
# =========================================================

print("[*] Generating FAKE networks...")

for idx, net in enumerate(FAKE_NETWORKS, start=1):
    for _ in range(80):
        packets.append(
            create_beacon(
                net["ssid"],
                net["bssid"],
                idx + 1,
                "QuickHint=password123"
            )
        )

    for _ in range(250):
        # fake flags should be loud and frequent
        fake_plain = random.choice([
            net["flag"],
            net["flag"],
            net["flag"],
            f"backup flag: {net['flag']}",
            f"temporary token => {net['flag']}",
            "CRITICAL ALERT",
            "ROOT ACCESS GRANTED",
            "ADMIN TOKEN FOUND",
            "Database compromised",
            "Emergency backup triggered"
        ])

        encrypted = encrypt_payload(
            net["password"],
            net["ssid"],
            fake_plain
        )

        packets.append(
            create_data(
                "DE:AD:BE:EF:00:01",
                net["bssid"],
                net["bssid"],
                encrypted
            )
        )


# =========================================================
# FINALIZE
# =========================================================

print("[*] Finalizing PCAP...")

random.shuffle(packets)

for i, pkt in enumerate(packets):
    pkt.time = base_time + (i * 0.01)

wrpcap(OUTPUT_FILE, packets)

print("\n" + "=" * 70)
print("HARD LAYER 1 GENERATED")
print("=" * 70)
print(f"Output File : {OUTPUT_FILE}")
print()
print("CREATOR ONLY")
print(f"REAL SSID    : {REAL_NETWORK['ssid']}")
print(f"PASSWORD     : {REAL_NETWORK['password']}")
print(f"REAL FLAG    : {REAL_NETWORK['flag']}")
print("=" * 70)
