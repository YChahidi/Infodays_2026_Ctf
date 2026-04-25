from scapy.all import *
from Crypto.Cipher import AES
import hashlib
import os
import time
import random

"""
LAYER 2 — HARD VERSION (METHOD 2: METADATA RECONSTRUCTION)
==========================================================

Password is NOT hidden in plaintext.

Players must reconstruct password using:

REAL example:
Beacon interval = 829
Channel = 4
Vendor hint = 17-36

Password logic:
48 + 29 + 17 + 36 + 40
= 4829173640

This removes obvious CLUE strings and creates real forensic work.

Goal:
- 6 encrypted Wi-Fi captures
- Only 1 contains REAL flag
- 2 contain FAKE flags
- Others are decoys
- Requires metadata analysis + controlled brute-force
"""

LAYER2_DIR = "layer2_captures"

REAL_FLAG_STRING = "infodays{crypt0sync_3x4ctly}"

FAKE_FLAG_1 = "ExternalThreatAlert"
FAKE_FLAG_2 = "SystemCompromised"


NETWORKS = [
    {
        "name": "network_1",
        "ssid": "CorpNet_A",
        "bssid": "61:38:04:27:59:AA",
        "psk": "6138042759",
        "is_real": False,
        "is_fake_flag": True,
        "flag_string": FAKE_FLAG_1,
        "channel": 6,
        "beacon_interval": 138,
        "vendor_hint": "04-27",
    },

    {
        "name": "network_2",
        "ssid": "CorpNet_B",
        "bssid": "94:71:20:58:36:BB",
        "psk": "9471205836",
        "is_real": False,
        "is_fake_flag": False,
        "flag_string": None,
        "channel": 9,
        "beacon_interval": 471,
        "vendor_hint": "20-58",
    },

    {
        "name": "network_3",
        "ssid": "GuestNet",
        "bssid": "35:07:14:62:29:CC",
        "psk": "3507146229",
        "is_real": False,
        "is_fake_flag": True,
        "flag_string": FAKE_FLAG_2,
        "channel": 3,
        "beacon_interval": 507,
        "vendor_hint": "14-62",
    },

    {
        "name": "network_4",
        "ssid": "AdminNet",
        "bssid": "72:16:98:35:50:DD",
        "psk": "7216983550",
        "is_real": False,
        "is_fake_flag": False,
        "flag_string": None,
        "channel": 7,
        "beacon_interval": 216,
        "vendor_hint": "98-35",
    },

    {
        "name": "network_5",
        "ssid": "DeviceSync",
        "bssid": "48:29:17:36:40:99",
        "psk": "4829173640",
        "is_real": True,
        "is_fake_flag": False,
        "flag_string": REAL_FLAG_STRING,
        "channel": 4,
        "beacon_interval": 829,
        "vendor_hint": "17-36",
    },

    {
        "name": "network_6",
        "ssid": "BackupAP",
        "bssid": "86:42:03:71:59:EE",
        "psk": "8642037159",
        "is_real": False,
        "is_fake_flag": False,
        "flag_string": None,
        "channel": 8,
        "beacon_interval": 642,
        "vendor_hint": "03-71",
    },
]


def encrypt_payload(password, data, ssid):
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        ssid.encode(),
        4096
    )[:32]

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg = data.encode() if isinstance(data, str) else data

    pad_len = 16 - (len(msg) % 16)
    msg += bytes([pad_len] * pad_len)

    return iv + cipher.encrypt(msg)


def create_beacon(ssid, bssid, channel, interval, seq):
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
            SC=seq
        )
        / Dot11Beacon(
            beacon_interval=interval,
            cap="ESS+privacy"
        )
        / Dot11Elt(
            ID="SSID",
            info=ssid.encode()
        )
        / Dot11Elt(
            ID="DSset",
            info=bytes([channel])
        )
    )


def create_data_frame(ap, client, payload, seq):
    return (
        RadioTap()
        / Dot11(
            type=2,
            subtype=0,
            addr1=ap,
            addr2=client,
            addr3=ap,
            FCfield=0x4100,
            SC=seq
        )
        / LLC()
        / SNAP()
        / Raw(load=payload)
    )


if not os.path.exists(LAYER2_DIR):
    os.makedirs(LAYER2_DIR)


print("=" * 70)
print("LAYER 2 — HARD VERSION GENERATOR")
print("=" * 70)
print()


for idx, network in enumerate(NETWORKS, 1):
    print(f"[{idx}/6] Building {network['ssid']}")

    packets = []
    seq = 0
    base_time = time.time()

    clients = [
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66",
        "DE:AD:BE:EF:CA:FE",
        "66:55:44:33:22:11",
        "10:20:30:40:50:60",
        "FE:ED:FA:CE:BE:EF",
    ]

    # =========================================
    # Beacon frames
    # =========================================

    for _ in range(80):
        pkt = create_beacon(
            network["ssid"],
            network["bssid"],
            network["channel"],
            network["beacon_interval"],
            seq
        )

        pkt.time = base_time + (seq * 0.05)
        packets.append(pkt)
        seq += 1

    # =========================================
    # Payload selection
    # =========================================

    if network["is_real"] or network["is_fake_flag"]:
        payloads = [
            "Session: Established",
            "User: admin",
            "Status: Authenticated",
            "Action: InternalSync",
            "Priority: Critical",
            f"SecurityAlert: {network['flag_string']}",
            "Destination: Vault",
            "Response: Required",
            "Event: SyncRequest",
            "Timestamp: 2026-04-24T14:55:00Z",
        ]
    else:
        payloads = [
            "Session: Normal",
            "User: guest",
            "Status: OK",
            "Connection: Alive",
            "Heartbeat: Active",
            "Traffic: Standard",
            "Message: KeepAlive",
            "Sync: Background",
        ]

    # =========================================
    # Encrypted traffic
    # =========================================

    for _ in range(250):
        client = random.choice(clients)
        payload_text = random.choice(payloads)

        encrypted = encrypt_payload(
            network["psk"],
            payload_text,
            network["ssid"]
        )

        # packet corruption for realism
        if random.randint(1, 8) == 1:
            encrypted = encrypted[:24] + os.urandom(12)

        pkt1 = create_data_frame(
            network["bssid"],
            client,
            encrypted,
            seq
        )
        pkt1.time = base_time + (seq * 0.05)
        packets.append(pkt1)
        seq += 1

        pkt2 = create_data_frame(
            client,
            network["bssid"],
            encrypted,
            seq
        )
        pkt2.time = base_time + (seq * 0.05)
        packets.append(pkt2)
        seq += 1

    # =========================================
    # Save
    # =========================================

    output = f"{LAYER2_DIR}/{network['name']}.pcap"
    wrpcap(output, packets)

    print(f"    saved -> {output}")

    if network["is_real"]:
        print("    ★ REAL FLAG NETWORK")
    elif network["is_fake_flag"]:
        print("    ✗ FAKE FLAG NETWORK")

    print()


print("=" * 70)
print("GENERATION COMPLETE")
print("=" * 70)
print()

print("CREATOR ONLY")
print("REAL NETWORK")
print("SSID      : DeviceSync")
print("BSSID     : 48:29:17:36:40:99")
print("CHANNEL   : 4")
print("BEACON    : 829")
print("REAL PIN  : 4829173640")
print(f"REAL FLAG : {REAL_FLAG_STRING}")
print()

print("Expected solve path:")
print("1. Enumerate all PCAPs")
print("2. Extract SSID")
print("3. Extract BSSID")
print("4. Extract beacon interval")
print("5. Notice password logic from metadata")
print("6. Reconstruct candidate PIN")
print("7. Decrypt traffic")
print("8. Hit fake flags first")
print("9. Separate fake vs real")
print("10. Recover final real flag")
print()

print("=" * 70)