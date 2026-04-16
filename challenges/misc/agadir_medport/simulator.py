#!/usr/bin/env python3
"""Agadir MedPort — MQTT SCADA telemetry simulator.

Publishes crane, gate, and weather telemetry on the `agadir/#` tree
and handles two command surfaces:

  agadir/quay/crane1/cmd     (anonymous-publishable) — diagnostic
                               override is vulnerable to CTF exploit F2
  agadir/admin/vault         (opsadmin only)        — unlock command
                               returns F3

Also publishes:
  - `$CTF/agadir/diag/backup`   — hidden topic carrying F1. MQTT
                                    wildcard `#` does NOT match
                                    topics starting with `$`, so
                                    naive `mosquitto_sub -t '#'` misses
                                    it — players must know the quirk.
  - `agadir/ops/briefing`       — retained, base64-encoded ops
                                    briefing containing opsadmin creds.
"""
from __future__ import annotations

import base64
import json
import os
import random
import threading
import time

import paho.mqtt.client as mqtt

FLAG1 = os.environ.get("FLAG1", "INFODAYS{SaamNoLimits_placeholder_f1}")
FLAG2 = os.environ.get("FLAG2", "INFODAYS{SaamNoLimits_placeholder_f2}")
FLAG3 = os.environ.get("FLAG3", "INFODAYS{SaamNoLimits_placeholder_f3}")

OPS_USER = "opsadmin"
OPS_PASS = os.environ.get("OPS_PASS", "AgadirPlaceholder")
SIM_USER = "simulator"
SIM_PASS = os.environ.get("SIM_PASS", "simplaceholder")

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883


def on_connect(client, _userdata, _flags, rc, _props=None):
    print(f"[sim] connected rc={rc}", flush=True)

    briefing = (
        "Agadir MedPort — ops briefing (INTERNAL)\n"
        f"Ops user: {OPS_USER}\n"
        f"Ops pass: {OPS_PASS}\n"
        "Scope: rotate after Infodays 2026 event.\n"
        "TODO: never expose this topic to anonymous clients.\n"
    )
    client.publish(
        "agadir/ops/briefing",
        base64.b64encode(briefing.encode()).decode(),
        retain=True,
        qos=1,
    )
    client.publish("agadir/sys/heartbeat", "online", retain=True, qos=1)

    client.subscribe("agadir/quay/crane1/cmd", qos=1)
    client.subscribe("agadir/admin/vault", qos=1)


def on_message(client, _userdata, msg):
    topic = msg.topic
    payload = msg.payload.decode(errors="replace")
    print(f"[sim] <- {topic}: {payload[:140]}", flush=True)

    if topic == "agadir/quay/crane1/cmd":
        try:
            cmd = json.loads(payload)
        except Exception:
            return
        if cmd.get("force") == "override" and cmd.get("mode") == "diagnostic":
            resp = {
                "status": "DIAGNOSTIC_MODE",
                "override_by": str(cmd.get("op", "unknown"))[:32],
                "audit_token": FLAG2,
            }
            client.publish("agadir/quay/crane1/status", json.dumps(resp), qos=1)
            print("[sim] crane diagnostic override triggered", flush=True)
        return

    if topic == "agadir/admin/vault":
        if payload.strip().lower() == "unlock":
            client.publish(
                "agadir/admin/vault/response",
                f"VAULT_UNLOCKED token={FLAG3}",
                qos=1,
            )
            print("[sim] vault unlocked via ops admin", flush=True)


def telemetry_loop(client):
    i = 0
    while True:
        client.publish(
            "agadir/quay/crane1/status",
            json.dumps({"status": "idle", "load_kg": 0, "tick": i}),
            qos=0,
        )
        client.publish("agadir/gate/entry/count", str(1240 + i), qos=0)
        client.publish(
            "agadir/weather/wind",
            f"{round(12 + random.random() * 4, 1)}",
            qos=0,
        )
        # Hidden flag on $-prefixed topic (MQTT wildcard quirk: '#' does not
        # match leading '$').
        client.publish("$CTF/agadir/diag/backup", FLAG1, qos=0)
        i += 1
        time.sleep(5)


def main():
    try:
        client = mqtt.Client(
            client_id="agadir_sim",
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            clean_session=True,
        )
    except AttributeError:
        client = mqtt.Client(client_id="agadir_sim", clean_session=True)
    client.username_pw_set(SIM_USER, SIM_PASS)
    client.on_connect = on_connect
    client.on_message = on_message

    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, 60)
            break
        except Exception as exc:
            print(f"[sim] broker not ready: {exc}", flush=True)
            time.sleep(1)

    threading.Thread(target=telemetry_loop, args=(client,), daemon=True).start()
    client.loop_forever()


if __name__ == "__main__":
    main()
