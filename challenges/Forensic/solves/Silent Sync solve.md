Layer 2 — Wi-Fi Traffic Decryption (Hard) Writeup
Challenge Summary

You are given 6 wireless capture files:

network_1.pcap
network_2.pcap
network_3.pcap
network_4.pcap
network_5.pcap
network_6.pcap

Each capture contains:

beacon frames
encrypted Wi-Fi traffic
fake operational traffic
fake flags
decoy networks

Only one network contains the real flag.

The challenge is designed so players:

hit fake flags first
think they solved it
realize there are decoys
perform deeper forensic analysis
reconstruct the real password
decrypt the correct network
Goal

Recover:

infodays{real_flag}
Core Concept

This is not WPA cracking.

This is:

Forensics + Metadata Reconstruction + AES Decryption

Traffic is encrypted using:

AES-CBC
PBKDF2-HMAC-SHA256

The password must be reconstructed from metadata.

Step 1 — Enumerate Networks

List all files:

ls layer2_captures/

Output:

network_1.pcap
network_2.pcap
network_3.pcap
network_4.pcap
network_5.pcap
network_6.pcap
Step 2 — Find Beacon Information

Extract SSID and beacon interval:

tshark -r network_5.pcap \
-Y "wlan.fc.type_subtype == 8" \
-T fields \
-e wlan.ssid \
-e wlan.fixed.beacon

Output:

DeviceSync    829
DeviceSync    829
DeviceSync    829

Important clues:

SSID = DeviceSync
Beacon Interval = 829

This is the suspicious network.

Step 3 — Extract BSSID

Now recover the AP MAC:

tshark -r network_5.pcap \
-Y "wlan.fc.type_subtype == 8" \
-T fields \
-e wlan.bssid

Output:

48:29:17:36:40:99

Important clue:

48 29 17 36 40

Ignore:

99

That last byte is noise.

Step 4 — Reconstruct the PIN

The password is derived from metadata:

48 + 29 + 17 + 36 + 40
=
4829173640

Therefore:

REAL PIN = 4829173640

This is intentional.

Players must notice the pattern.

Step 5 — Extract Raw Encrypted Payload

Get encrypted traffic:

tshark -r network_5.pcap \
-Y "wlan.fc.type == 2" \
-T fields \
-e data.data > raw_hex.txt

This extracts the encrypted payloads in hex.

Step 6 — Create Decryption Script

Create:

nano decrypt.py

Paste:

from Crypto.Cipher import AES
import hashlib

SSID = "DeviceSync"
PASSWORD = "4829173640"


def derive_key(password, ssid):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        ssid.encode(),
        4096
    )[:32]


key = derive_key(PASSWORD, SSID)

with open("raw_hex.txt") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        try:
            raw = bytes.fromhex(line)

            iv = raw[:16]
            ciphertext = raw[16:]

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)

            pad = decrypted[-1]
            plaintext = decrypted[:-pad].decode(
                errors="ignore"
            )

            if "SecurityAlert" in plaintext:
                print(plaintext)

        except:
            pass
Step 7 — Run Decryption
python3 decrypt.py

Example output:

SecurityAlert: ExternalThreatAlert
SecurityAlert: SystemCompromised
SecurityAlert: infodays{ftestreal}
Step 8 — Ignore Fake Flags

These are fake:

ExternalThreatAlert
SystemCompromised

These are bait.

Only valid final flag format matters:

infodays{...}

The real one is:

infodays{ftestreal}
Final Flag
infodays{ftestreal}
Why This Challenge Is Hard

Because most players:

stop at first fake flag
do not inspect beacon metadata
miss the BSSID reconstruction trick
forget PBKDF2 uses SSID as salt
decrypt wrong traffic
assume first success is final

This forces proper forensic methodology.

Intended Player Journey
1. Enumerate PCAPs
2. See multiple possible targets
3. Hit fake flags first
4. Submit wrong answers
5. Re-investigate deeper
6. Notice beacon + BSSID pattern
7. Reconstruct real PIN
8. Decrypt real traffic
9. Recover final flag