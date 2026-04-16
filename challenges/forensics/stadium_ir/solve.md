# Stadium FC IR — Writeup

Two flags. You're dropped into a compromised Debian box with only a
non-root analyst account. Your job is to find the attacker's
persistence and recover a staged exfil payload.

## Access

```
ssh -p 2222 analyst@HOST
# password: analyst123
```

First thing: read `/home/analyst/BRIEFING.md`.

## Recon

Before touching anything, get your bearings:

```
id                          # confirm uid=1000, no sudo
ps -efww                    # any processes still running as root?
ss -tlnp                    # listening ports
ls -la /etc/cron.d/         # list with -a (attacker used a dotfile!)
ls -la /etc/cron.*          # check all cron locations
cat /var/log/auth.log       # scene: brute force → successful root
```

`auth.log` paints the picture:

```
03:41:12  Failed password for root from 185.196.8.23
03:41:22  Failed password for root from 185.196.8.23
03:41:24  Accepted password for root from 185.196.8.23
03:41:41  COMMAND=... /opt/stadium/.cache/daemon.sh
03:42:03  COMMAND=/usr/bin/crontab -e
```

Attacker brute-forced root, installed a stager under
`/opt/stadium/.cache/`, and edited crontab. Good starting points.

## F1 — medium  (persistence)

`ls /etc/cron.d/` misses dotfiles. `ls -la /etc/cron.d/` shows a hidden
entry `.sysupdate`:

```
cat /etc/cron.d/.sysupdate
```

```
# stadium analytics auto-installed 2026-03-12 by ops@stadiumfc.example
...
*/5 * * * * root /opt/stadium/.cache/daemon.sh >/dev/null 2>&1
```

Follow the reference:

```
cat /opt/stadium/.cache/daemon.sh
```

```
#!/bin/bash
# stadium metrics stager
# audit_token: INFODAYS{SaamNoLimits_persistence_unearthed_...}
KEY="stadiumfc2026"
PAYLOAD="/var/tmp/.stage/payload"
...
```

The `audit_token` comment is **F1**.

## F2 — hard  (recover the staged exfil)

The stager also tells you where the staged blob is and what key it
used. The file format is `base64( xor(plain, KEY) )`. Pull it and
decode locally over SSH:

```
cat /var/tmp/.stage/payload
```

That's base64. Decode and XOR with the key:

```bash
KEY=stadiumfc2026
cat /var/tmp/.stage/payload | base64 -d \
  | python3 -c '
import sys
k = b"stadiumfc2026"
d = sys.stdin.buffer.read()
print(bytes(c ^ k[i % len(k)] for i,c in enumerate(d)).decode())'
```

Output:

```
DATAVAULT_DROP header=stadiumfc-ops
INFODAYS{SaamNoLimits_exfil_recovered_...}
EOF
```

That's **F2**.

## Hint ladder

1. *Free:* "The attacker's file is in a place `ls` misses by default.
   Always use `ls -la`."
2. *Cheap:* "`/etc/cron.d/` is only one of several cron locations.
   Check them all — the interesting one is in the first one you'd
   expect, just hidden with a dot."
3. *Medium:* "The stager script itself tells you everything F2 needs:
   the encoding, the key, and the path."
4. *Last resort:* "`base64 -d` → XOR with `stadiumfc2026` → plaintext."

## Why each difficulty

- **F1** teaches the single most common junior-analyst miss: `ls`
  without `-a`. The script behind the cron is fully readable by
  `analyst` (the attacker was sloppy), so there's no privilege gap —
  only an enumeration gap.
- **F2** is a three-step decode chain (read → base64 → XOR) plus the
  prerequisite that you actually parsed the stager script to pick up
  both the key and the payload path. Straight forensics, no guessing.
