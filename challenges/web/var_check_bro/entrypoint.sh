#!/bin/bash
set -e

# Dynamic flag — generated per container instance unless FLAG env var is provided
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 12 /dev/urandom | xxd -p)
    FLAG="INFODAYS{var_check_bro_${RANDHEX}}"
fi

echo -n "${FLAG}" > /flag.txt
chmod 644 /flag.txt
unset FLAG

# Start internal VAR service (loopback only)
python3 /app/internal/service.py &

# Start public frontend
exec python3 /app/frontend/app.py
