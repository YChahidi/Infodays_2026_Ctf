#!/bin/bash
set -e

# Flags are injected by the CTF infrastructure via $FLAG1 / $FLAG2
# (see challenges/manifests guide — multi-flag section). The defaults
# below only apply when running the container locally for development.
rand_hex() { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
FLAG1="${FLAG1:-infodays{SaamNoLimits_$(rand_hex)}}"
FLAG2="${FLAG2:-infodays{SaamNoLimits_$(rand_hex)}}"

# The 7z archive is cracked with a rockyou-matched keyboard walk password.
# This matches the narrative — attacker must crack the zip (hashcat / john).
ARCHIVE_PW="1q2w3e4r5t6y"

# HMAC secret — leaked via the wiki page to the attacker.
HMAC_SECRET="${HMAC_SECRET:-$(rand_hex)}"

# ── Stage 2 gate: timestamp-seeded C rand ──────────────────────────
# Pick a random historical timestamp; attacker recovers the second via SQLi
# and has to brute force the ms offset 0..999.
EPOCH_S=$(( $(date +%s) - (RANDOM % 86400) ))
TS_STR=$(date -u -d "@${EPOCH_S}" "+%Y-%m-%d %H:%M:%S")
MS=$(( RANDOM % 1000 ))

# Derive BATISTUTA_PW using the same libc rand() as the ELF binary
BATISTUTA_PW="$(python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6')
CS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
libc.srand(${EPOCH_S} * 1000 + ${MS})
print(''.join(CS[libc.rand() % 62] for _ in range(20)))
")"

# ── Stage DB update for the boot-time timestamp ─────────────────────
mkdir -p /data
cat > /data/seed_row.sql <<EOF
USE temp;
UPDATE command_log
   SET date = '${TS_STR}',
       command = 'cd /home/batistuta/ && /opt/bin/batistuta-pwgen | passwd'
 WHERE id = 6;
EOF

# ── Build the restic backup (7z archive) at /data/restic/backup.7z ──
mkdir -p /data/restic /tmp/zipstage
printf '%s' "$FLAG1" > /tmp/zipstage/user.txt
cp /opt/bin/batistuta-pwgen /tmp/zipstage/batistuta-pwgen
cat > /tmp/zipstage/note.txt <<'NOTE'
Scouting vault dump — crespo's working copy.

The captain (batistuta) rotated his password via the pwgen tool
attached here. Check the `temp.command_log` table for the timestamp
at which it was run — the binary uses that as the seed for a
libc rand() based password generator.
NOTE
( cd /tmp/zipstage && 7z a -p"${ARCHIVE_PW}" -mhe=on /data/restic/backup.7z ./* >/dev/null )
rm -rf /tmp/zipstage

# ── Encrypt flags with their gating secrets ─────────────────────────
enc() {  # enc <plaintext> <password> → base64(salted AES-256-CBC PBKDF2)
    printf '%s' "$1" | openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$2" | base64 -w0
}
FLAG1_ENC_B64="$(enc "$FLAG1" "$ARCHIVE_PW")"
FLAG2_ENC_B64="$(enc "$FLAG2" "$BATISTUTA_PW")"

export HMAC_SECRET FLAG1_ENC_B64 FLAG2_ENC_B64

# ── Scrub plaintext secrets before spawning services ────────────────
unset FLAG1 FLAG2 BATISTUTA_PW ARCHIVE_PW

# ── Kick off supervisord in the background, wait for mariadb, seed DB ─
/usr/bin/supervisord -c /etc/supervisor/conf.d/batistuta.conf &
SUP_PID=$!

for i in $(seq 1 40); do
    mariadb -S /var/run/mysqld/mysqld.sock -u n8n \
         -p'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS' -e 'SELECT 1' temp >/dev/null 2>&1 && break
    sleep 1
done

mariadb -S /var/run/mysqld/mysqld.sock -u n8n \
    -p'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS' < /data/seed_row.sql || true
rm -f /data/seed_row.sql

wait $SUP_PID
