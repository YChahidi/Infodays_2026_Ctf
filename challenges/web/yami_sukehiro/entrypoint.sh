#!/bin/bash
set -e

# Flags are injected by the CTF infrastructure via $FLAG1 / $FLAG2
# (see challenges/manifests guide — multi-flag section). The defaults
# below only apply when running the container locally for development.
rand_hex() { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
export FLAG1="${FLAG1:-infodays{SaamNoLimits_$(rand_hex)}}"
export FLAG2="${FLAG2:-infodays{SaamNoLimits_$(rand_hex)}}"

# Per-instance captain secret (baked into hg history + used to encrypt root.txt)
CAPTAIN_SECRET="${CAPTAIN_SECRET:-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

# ── Plant user flag (FLAG1) ─────────────────────────────────────
mkdir -p /flags
echo -n "$FLAG1" > /flags/user.txt
chmod 644 /flags/user.txt

# ── Encrypt root flag with captain secret, then scrub plaintext ─
if [ ! -f /flags/root.txt.enc ]; then
    printf '%s' "$FLAG2" | openssl enc -aes-256-cbc -salt -pbkdf2 \
        -pass pass:"$CAPTAIN_SECRET" \
        -out /flags/root.txt.enc
    chmod 644 /flags/root.txt.enc
fi

# MariaDB datadir was pre-initialised at build time. Just start the daemon.
mariadbd --user=yami \
         --datadir=/var/lib/mysql \
         --socket=/var/run/mysqld/mysqld.sock \
         --bind-address=127.0.0.1 \
         --port=3306 \
         --secure-file-priv='' \
         --skip-log-bin \
         >/tmp/mariadb.log 2>&1 &

for i in $(seq 1 30); do
    if mariadb -S /var/run/mysqld/mysqld.sock -u yuno -p'3wDo7gSRZIwIHRxZ!' \
        -e 'SELECT 1' mana_db >/dev/null 2>&1; then break; fi
    sleep 1
done

# ── Seed Mercurial repo (stage-2 pivot) ─────────────────────────
if [ ! -d /opt/hg_repo/.hg ]; then
    cp /opt/hg_repo_seed/_stage1_config.py /opt/hg_repo/config.py
    cp /opt/hg_repo_seed/README.md /opt/hg_repo/README.md
    # inject the real secret into the stage-1 commit
    sed -i "s/__REPLACE_ME__/${CAPTAIN_SECRET}/" /opt/hg_repo/config.py

    cd /opt/hg_repo
    export HGUSER="yami.sukehiro@black-bulls.lab"
    hg init
    hg add config.py README.md
    hg commit -m "initial: captain vault config with secret"

    # stage-2: "remove" the secret from the tip revision (but it's still in history)
    cp /opt/hg_repo_seed/_stage2_config.py /opt/hg_repo/config.py
    hg commit -m "fix: moved CAPTAIN_SECRET into the vault (see captain.py)"
    cd -
fi

# ── Scrub secrets from environment before exec'ing supervisord ──
unset FLAG2 CAPTAIN_SECRET

# ── Start supervisord (Flask + cron simulator + captain service) ─
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/yami.conf
