# Aït Baha Nuclear — OT / SCADA

**Category:** OT / ICS / SCADA
**Flags:** 3 (2 medium, 1 hard)
**HMI:** http://&lt;host&gt;:8012
**PLC (Modbus TCP, unit 1):** &lt;host&gt;:5020

> The Aït Baha nuclear facility runs on a proudly untouched legacy OT
> stack. The HMI is friendly. The PLC is *too* friendly. Three
> flags are hidden somewhere between the sensors and the interlocks —
> good luck, operator.

## For players

You get two reachable services on the challenge host:

- A Flask **HMI** on port **8012** — a normal control-room page with
  live reactor metrics and a couple of panels.
- A Modbus TCP **PLC** on port **5020** — unauthenticated, unit id 1.

Everything you need is documented inside the HMI's `/help` page. Read
it carefully. Flags are of the form `INFODAYS{...}`.

Suggested tools:
- `pymodbus` (Python)
- `modbus-cli`, `mbtget`, or your Modbus client of choice
- `curl` / `requests` for the HMI

## For the organizer

### Run

```
docker compose up -d --build ot-scada
```

Flags are regenerated per container via `entrypoint.sh` (unless you
pin them with `FLAG1` / `FLAG2` / `FLAG3` env vars in compose).

Ports mapped on the host:

- `8012` → HMI
- `5020` → Modbus TCP

### Test the solver

```
python3 solve.py           # uses localhost:8012 / localhost:5020
```

See `solve.md` for the full walkthrough and hint ladder.
