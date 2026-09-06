#!/usr/bin/env python3
"""Aït Baha Nuclear — Modbus TCP backend (fake PLC)."""
from __future__ import annotations

import os
import threading
import time

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartTcpServer

FLAG1 = os.environ.get("FLAG1", "INFODAYS{SaamNoLimits_silent_sensor_placeholder}")
OPERATOR_CODE = b"RABAT_SAFE_42!!"

HR_SIZE = 200
IR_SIZE = 200

hr = [0] * HR_SIZE
ir = [0] * IR_SIZE

# Live reactor state (nominal)
hr[0] = 3400   # core_temp x10 (340.0 °C)
hr[1] = 120    # coolant_flow (L/s)
hr[2] = 850    # neutron_flux
hr[3] = 100    # rod_position (%)
hr[4] = 0      # scram_flag
hr[5] = 0      # operator_magic
hr[6] = 0      # maintenance_mode
hr[7] = 0      # tick (1 Hz, updated below)

# Flag 1 — ASCII bytes spread across HR 50..
for i, ch in enumerate(FLAG1.encode()):
    if 50 + i < HR_SIZE:
        hr[50 + i] = ch

# Mirror sensors into IR for redundant-sensor style reads
ir[0:4] = hr[0:4]

# Operator code — ASCII bytes in IR 100.. (read via function code 4)
for i, ch in enumerate(OPERATOR_CODE):
    if 100 + i < IR_SIZE:
        ir[100 + i] = ch

store = ModbusSlaveContext(
    hr=ModbusSequentialDataBlock(0, hr),
    ir=ModbusSequentialDataBlock(0, ir),
    di=ModbusSequentialDataBlock(0, [0] * 16),
    co=ModbusSequentialDataBlock(0, [0] * 16),
    zero_mode=True,
)
context = ModbusServerContext(slaves=store, single=True)


def tick_loop() -> None:
    while True:
        time.sleep(1)
        try:
            cur = context[0].getValues(3, 7, count=1)[0]
            context[0].setValues(3, 7, [(cur + 1) & 0xFFFF])
        except Exception:
            pass


threading.Thread(target=tick_loop, daemon=True).start()

print("[modbus] serving on 0.0.0.0:5020", flush=True)
StartTcpServer(context=context, address=("0.0.0.0", 5020))
