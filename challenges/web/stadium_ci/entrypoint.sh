#!/bin/bash
set -e

# Dynamic flag — generated per container instance unless FLAG env var is provided
# Format: INFODAYS{SaamNoLimits_<Messi quote>_<random hex>}
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 8 /dev/urandom | xxd -p)
    FLAG="INFODAYS{SaamNoLimits_you_can_overcome_anything_if_you_love_it_enough_${RANDHEX}}"
fi

echo -n "${FLAG}" > /flag.txt
chmod 644 /flag.txt
unset FLAG

exec python3 /app/app.py
