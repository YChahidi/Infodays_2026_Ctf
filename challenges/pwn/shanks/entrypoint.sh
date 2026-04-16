#!/bin/bash
set -e

cd /home/ctf

# Dynamic flag — regenerated per container unless FLAG env var is provided.
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    FLAG="INFODAYS{SaamNoLimits_i_bet_my_arm_on_the_new_era_${RANDHEX}}"
fi

echo -n "${FLAG}" > /home/ctf/flag.txt
chmod 644 /home/ctf/flag.txt
unset FLAG

exec socat TCP-LISTEN:8019,reuseaddr,fork EXEC:./shanks
