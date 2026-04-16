#!/bin/bash
set -e

cd /home/ctf

# Dynamic flag — regenerated per container unless FLAG env var is provided.
# Format: INFODAYS{SaamNoLimits_<Ronaldo quote>_<random hex>}
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    FLAG="INFODAYS{SaamNoLimits_talent_without_hard_work_is_nothing_${RANDHEX}}"
fi

echo -n "${FLAG}" > /home/ctf/flag.txt
chmod 644 /home/ctf/flag.txt
unset FLAG

exec socat TCP-LISTEN:8011,reuseaddr,fork EXEC:./var_replay_buffer
