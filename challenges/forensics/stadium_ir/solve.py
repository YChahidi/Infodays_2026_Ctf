#!/usr/bin/env python3
"""Solver for the stadium_ir blue team challenge.

Chain (executed over SSH as analyst):

  1. SSH in with known creds from the briefing.
  2. Enumerate /etc/cron.d (including dotfiles). A hidden
     `.sysupdate` entry reveals the attacker's stager path.
  3. Read the stager (`/opt/stadium/.cache/daemon.sh`). Its header
     comment contains F1, and it declares both the XOR key and
     the staged payload path.
  4. Read the staged payload (base64 wrapped around an XOR'd blob),
     decode it with the key → recover F2.
"""
from __future__ import annotations

import base64
import re
import sys

import paramiko

HOST = "localhost"
PORT = 2222
USER = "analyst"
PASS = "analyst123"

FLAG_RE = re.compile(r"INFODAYS\{[^}]+\}")


def run(client: paramiko.SSHClient, cmd: str) -> str:
    _, stdout, _ = client.exec_command(cmd)
    return stdout.read().decode("utf-8", errors="replace")


def main() -> int:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=10)

    print("[*] /etc/cron.d listing (including dotfiles):")
    print(run(c, "ls -la /etc/cron.d/").rstrip())

    cron = run(c, "cat /etc/cron.d/.sysupdate")
    print("\n[*] hidden cron content:")
    print(cron.rstrip())

    script_m = re.search(r"(/\S+\.sh)", cron)
    if not script_m:
        print("[!] could not locate attacker script in cron entry")
        return 1
    script = script_m.group(1)
    print(f"\n[*] stager script = {script}")

    daemon = run(c, f"cat {script}")
    print("\n[*] stager contents:")
    print(daemon.rstrip())

    f1 = FLAG_RE.search(daemon)
    key_m = re.search(r'KEY="([^"]+)"', daemon)
    payload_m = re.search(r'PAYLOAD="([^"]+)"', daemon)
    if not (f1 and key_m and payload_m):
        print("[!] missing flag/key/payload reference in daemon.sh")
        return 1

    print(f"\n[+] F1 = {f1.group(0)}")

    key = key_m.group(1).encode()
    payload_path = payload_m.group(1)
    raw = run(c, f"cat {payload_path}").strip()

    try:
        xored = base64.b64decode(raw)
    except Exception as exc:
        print(f"[!] base64 decode failed: {exc}")
        return 1

    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(xored))
    print("\n[*] decoded staged blob:")
    try:
        print(plain.decode().rstrip())
    except UnicodeDecodeError:
        print(plain)

    f2 = FLAG_RE.search(plain.decode(errors="replace"))
    if not f2:
        print("[!] F2 not found in decoded blob")
        return 1
    print(f"\n[+] F2 = {f2.group(0)}")

    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
