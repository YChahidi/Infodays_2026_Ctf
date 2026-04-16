# Stadium FC IR — Blue Team / Forensics

**Category:** Blue Team / Linux Forensics / Incident Response
**Flags:** 2 (1 medium, 1 hard)
**Access:** `ssh -p 2222 analyst@<host>`  (password `analyst123`)

> Stadium FC's ops jump box was compromised last night. The intrusion
> lasted less than two minutes — enough time for the attacker to plant
> persistence and stage a payload, but egress was cut before the data
> actually left. Your job is to find the persistence and recover the
> staged blob.

## For players

1. SSH into the host:
   ```
   ssh -p 2222 analyst@<host>
   # password: analyst123
   ```
2. Read `/home/analyst/BRIEFING.md` first.
3. You have **no sudo**. Everything you need is reachable with
   `analyst` privileges because the attacker was sloppy with file
   modes.
4. Flags are of the form `INFODAYS{...}`.

Tools pre-installed: `grep`, `find`, `xxd`, `file`, `base64`,
`python3`, `less`, `nano`, `vim-tiny`, `ps`, `ss`, `netstat`.

## For the organizer

### Run

```
docker compose up -d --build stadium-ir
```

Flags are regenerated per container unless pinned via `FLAG1` / `FLAG2`
env vars. The XOR key is also env-tunable (`XOR_KEY`).

Ports:

- `2222` → sshd

### Test the solver

```
python3 -m pip install paramiko
python3 solve.py      # uses localhost:2222
```

See `solve.md` for the full walkthrough and hint ladder.
