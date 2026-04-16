#!/usr/bin/env python3
"""Aït Baha Nuclear — Flask HMI (reads the PLC via Modbus)."""
from __future__ import annotations

import hashlib
import os
import re

from flask import Flask, render_template_string
from pymodbus.client import ModbusTcpClient

FLAG2 = os.environ.get("FLAG2", "INFODAYS{SaamNoLimits_placeholder_2}")
FLAG3 = os.environ.get("FLAG3", "INFODAYS{SaamNoLimits_placeholder_3}")
OPERATOR_CODE = b"RABAT_SAFE_42!!"

MB_HOST = os.environ.get("MB_HOST", "127.0.0.1")
MB_PORT = int(os.environ.get("MB_PORT", "5020"))

app = Flask(__name__)


def _open():
    c = ModbusTcpClient(MB_HOST, port=MB_PORT)
    c.connect()
    return c


def read_hr(addr: int, count: int = 1):
    try:
        c = _open()
        r = c.read_holding_registers(addr, count=count)
        c.close()
        if r is None or (hasattr(r, "isError") and r.isError()):
            return None
        return r.registers
    except Exception:
        return None


BASE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Aït Baha Nuclear — HMI</title>
<style>
body{font-family:'Courier New',monospace;background:#0a1929;color:#d0e8ff;padding:2em;max-width:900px;margin:auto;}
h1{color:#ffaa00;border-bottom:2px solid #ffaa00;padding-bottom:0.3em;}
h2{color:#66ccff;}
.panel{background:#112233;padding:1em 1.5em;margin:1em 0;border-left:4px solid #00ffaa;}
.bad{border-left-color:#ff4444;color:#ffbbbb;}
.good{border-left-color:#ffff00;color:#ffff88;}
nav{margin:1.5em 0;}
nav a{color:#66ccff;margin-right:1.5em;text-decoration:none;}
nav a:hover{color:#ffaa00;}
pre{background:#000;padding:0.8em;color:#ffff00;border:1px dashed #ffaa00;}
code{color:#aaffaa;}
small{color:#668899;}
</style></head><body>{{body|safe}}</body></html>
"""


def page(body: str) -> str:
    return render_template_string(BASE, body=body)


@app.route("/")
def index():
    r = read_hr(0, 4) or [0, 0, 0, 0]
    temp = r[0] / 10.0
    body = f"""
<h1>⚛ AÏT BAHA NUCLEAR — Control Room HMI</h1>
<div class="panel">
<b>Reactor Status (live from PLC unit 1):</b><br><br>
Core Temperature : <b>{temp:.1f}</b> °C<br>
Coolant Flow     : <b>{r[1]}</b> L/s<br>
Neutron Flux     : <b>{r[2]}</b><br>
Control Rod      : <b>{r[3]}</b> %<br>
</div>
<nav>
<a href="/calibration">[Calibration Panel]</a>
<a href="/emergency">[Emergency SCRAM]</a>
<a href="/help">[Engineer Help]</a>
</nav>
<hr>
<small>Legacy PLC backend: <code>modbus-tcp://{MB_HOST}:{MB_PORT}</code> &nbsp;—&nbsp; no authentication (vendor default)</small>
"""
    return page(body)


@app.route("/calibration")
def calibration():
    r = read_hr(0, 4) or [0, 0, 0, 0]
    temp = r[0] / 10.0
    flow = r[1]
    rod = r[3]
    ok = (temp <= 25.0) and (flow == 0) and (rod == 100)
    if ok:
        body = f"""
<h1>CALIBRATION MODE ENGAGED</h1>
<div class="panel good">
<b>Plant is in calibration envelope.</b><br>
Token printed from calibration controller:
<pre>{FLAG2}</pre>
</div>
<a href="/">&larr; back to control room</a>
"""
    else:
        body = f"""
<h1>Calibration Panel — LOCKED</h1>
<div class="panel bad">
Entering calibration requires the plant to be in a safe parked state:
<ul>
<li>Core temperature &le; 25.0 °C</li>
<li>Coolant flow = 0 L/s</li>
<li>Control rod fully inserted (100 %)</li>
</ul>
Current readings from PLC unit 1:
<ul>
<li>temp = {temp:.1f} °C</li>
<li>flow = {flow} L/s</li>
<li>rod  = {rod} %</li>
</ul>
</div>
<a href="/">&larr; back to control room</a>
"""
    return page(body)


@app.route("/emergency")
def emergency():
    r = read_hr(4, 2) or [0, 0]
    scram, magic = r[0], r[1]
    expected = int(hashlib.sha256(OPERATOR_CODE).hexdigest()[:4], 16)
    if scram == 1 and magic == expected:
        body = f"""
<h1>SCRAM INTERLOCK BYPASSED</h1>
<div class="panel good">
<b>Emergency shutdown signature accepted.</b><br>
Reactor tripped to safe state. Audit token follows:
<pre>{FLAG3}</pre>
</div>
<a href="/">&larr; back to control room</a>
"""
    else:
        body = f"""
<h1>SCRAM Interlock — ACTIVE</h1>
<div class="panel bad">
Emergency shutdown refused. Required preconditions:
<ul>
<li>HR 4 (scram_flag) must equal 1</li>
<li>HR 5 (operator_magic) must equal the interlock checksum</li>
</ul>
Current:
<ul>
<li>scram = {scram}</li>
<li>magic = {magic}</li>
</ul>
See <a href="/help">[Engineer Help]</a> for the checksum algorithm.
</div>
<a href="/">&larr; back to control room</a>
"""
    return page(body)


@app.route("/help")
def help_page():
    body = """
<h1>ENGINEER HELP — Legacy HMI</h1>
<pre>
PLC backend : modbus-tcp://&lt;host&gt;:5020   (unit id 1, no auth)

HOLDING REGISTERS (function code 3 / 6 / 16):
  HR  0 : core_temp       (x10, e.g. 3400 = 340.0 C)
  HR  1 : coolant_flow    (L/s)
  HR  2 : neutron_flux
  HR  3 : rod_position    (%)
  HR  4 : scram_flag      (0/1, writable)
  HR  5 : operator_magic  (writable, SCRAM interlock)
  HR  6 : maintenance_mode
  HR  7 : tick            (1 Hz)
  HR 50+: reserved for plant diagnostics

INPUT REGISTERS (function code 4):
  IR  0..3 : redundant sensor mirror
  IR 100+  : operator authentication code (read-only, ASCII)

SCRAM INTERLOCK (evaluated by /emergency):
  allow_scram := (HR4 == 1) AND (HR5 == interlock_checksum)

  interlock_checksum =
      int( sha256(operator_code_ascii).hexdigest()[:4], 16 )

  i.e. read the operator code bytes from IR 100.. (16 regs),
  strip trailing nulls, SHA-256 them, take the first 4 hex
  characters and interpret them as a 16-bit integer, then
  write that integer into HR 5.

LEGACY NOTE: this PLC ships with no authentication. DO NOT
expose port 5020 to the public network. (We know, we know.)
</pre>
<a href="/">&larr; back to control room</a>
"""
    return page(body)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8012, debug=False)
