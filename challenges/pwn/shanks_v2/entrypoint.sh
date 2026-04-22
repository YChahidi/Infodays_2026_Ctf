#!/bin/bash
set -e

cd /home/ctf

# Flag is injected by the CTF infrastructure via the FLAG env var
# (see challenges/manifests guide). The default below only applies when
# running the container locally for development/testing.
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    FLAG="infodays{SaamNoLimits_${RANDHEX}}"
fi

echo -n "${FLAG}" > /home/ctf/flag.txt
chmod 644 /home/ctf/flag.txt
unset FLAG

# Run the forking socket server directly (NOT via socat-exec — the whole
# canary-brute-force technique relies on fork() preserving the parent's
# memory between children).
exec ./shanks_v2 1337
