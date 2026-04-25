STEP 1 — Open PCAP

Use:

wireshark layer1_hard_forensic.pcap

OR terminal:

tshark -r layer1_hard_forensic.pcap
STEP 2 — Enumerate Networks

Find all SSIDs:

tshark -r layer1_hard_forensic.pcap \
-Y "wlan.fc.type_subtype == 8" \
-T fields \
-e wlan.ssid

Expected output:

CorpGuest
Printer_AP
AdminPanel
BackupAP
LegacyIoT
DeviceSync

At first, fake networks look more attractive.

This is intentional.

STEP 3 — Extract Beacon Clues

Check vendor-specific elements:

tshark -r layer1_hard_forensic.pcap \
-Y "wlan.fc.type_subtype == 8" \
-V | grep VendorTag

You may see:

VendorTag=Alpha

Then:

tshark -r layer1_hard_forensic.pcap \
-Y "wlan.fc.type_subtype == 8" \
-V | grep BuildVersion

Output:

BuildVersion=2026

Then:

tshark -r layer1_hard_forensic.pcap \
-Y "wlan.fc.type == 2" \
-V | grep Service

Output:

Service=Sync!

Now reconstruct:

Alpha + 2026 + Sync!

Final password:

Alpha2026Sync!
STEP 4 — Extract Raw Encrypted Hex

We need encrypted payloads from the real network only.

Use:

tshark -r layer1_hard_forensic.pcap \
-Y "wlan.ta == 00:11:22:33:44:55 && data.data" \
-T fields \
-e data.data > hex.txt

This saves encrypted payloads.

STEP 5 — Decrypt Script

Create:

nano decrypt.py

Paste:

from Crypto.Cipher import AES
import hashlib

password = "Alpha2026Sync!"
ssid = "DeviceSync"


def derive_key(password, ssid):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        ssid.encode(),
        5000
    )[:32]


def decrypt(hex_data):
    raw = bytes.fromhex(hex_data)

    iv = raw[:16]
    ciphertext = raw[16:]

    key = derive_key(password, ssid)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(ciphertext)

    pad = plain[-1]
    plain = plain[:-pad]

    try:
        text = plain.decode()

        # print only useful lines
        if "FLAG" in text or "TOKEN" in text:
            print(text)

    except:
        pass


with open("hex.txt", "r") as f:
    ciphertexts = [line.strip() for line in f if line.strip()]

for item in ciphertexts:
    decrypt(item)
STEP 6 — Run Decryption

Install dependency:

pip install pycryptodome

Then:

python decrypt.py

Expected final output:

FINAL ARCHIVE TOKEN => infodays{real_static_testing_flag}

This is the REAL flag.