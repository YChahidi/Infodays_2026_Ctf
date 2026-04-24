#!/bin/bash
set -euo pipefail

: "${FLAG:?FLAG must be set in .env}"

printf '%s\n' "$FLAG" > /app/flag.txt
chmod 644 /app/flag.txt
unset FLAG

cd /app
exec socat -T 120 tcp-l:1337,fork,reuseaddr exec:"python3 -u /app/challenge.py",stderr
