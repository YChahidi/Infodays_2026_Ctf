#!/bin/bash
set -e

# Dynamic flag — generated per container instance unless FLAG env var is provided
# Format: INFODAYS{SaamNoLimits_<Ronaldo quote>_<random hex>}
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 8 /dev/urandom | xxd -p)
    FLAG="INFODAYS{SaamNoLimits_your_hate_makes_me_unstoppable_${RANDHEX}}"
fi

echo -n "${FLAG}" > /flag.txt
chmod 644 /flag.txt
unset FLAG

# Start internal VAR service (loopback only)
python3 /app/internal/service.py &

# Start public frontend
exec python3 /app/frontend/app.py
