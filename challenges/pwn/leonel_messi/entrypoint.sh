#!/bin/bash
set -e

cd /home/ctf

if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    FLAG="INFODAYS{SaamNoLimits_goal_journal_${RANDHEX}}"
fi

echo -n "${FLAG}" > /home/ctf/flag.txt
chmod 644 /home/ctf/flag.txt
unset FLAG

exec ./leonel_messi 1337
