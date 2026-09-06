# Agadir MedPort — OT / MQTT SCADA

**Category:** OT / ICS / IIoT (MQTT)
**Flags:** 3 (2 medium, 1 hard)
**Broker:** &lt;host&gt;:1884  (MQTT over TCP, mosquitto)

> Agadir Med container terminal runs its crane fleet, gate counters,
> and weather station on an unauthenticated Mosquitto broker. The ops
> team is "very careful" about ACLs. There are three flags somewhere
> in the topic tree.

## For players

You get one reachable service: a Mosquitto broker on port **1884**.
Three flags are of the form `INFODAYS{...}`.

Suggested tools:
- `mosquitto_sub` / `mosquitto_pub` (apt install `mosquitto-clients`)
- `paho-mqtt` (Python)
- `base64`, `jq`

Starter:

```
mosquitto_sub -h HOST -p 1884 -t '#' -v
```

Read the MQTT spec carefully — the `#` wildcard has a famous
limitation. Flags are *not* all visible with `-t '#'`.

## For the organizer

### Run

```
docker compose up -d --build ot-scada-medport
```

Flags and broker passwords are regenerated per container via
`entrypoint.sh` unless pinned via `FLAG1` / `FLAG2` / `FLAG3` /
`OPS_PASS` / `SIM_PASS`.

Ports mapped on the host:

- `1884` → Mosquitto

### Test the solver

```
python3 solve.py           # uses localhost:1884
```

See `solve.md` for the full walkthrough and hint ladder.
