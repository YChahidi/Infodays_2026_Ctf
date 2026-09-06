#!/bin/bash
set -e

cd /home/ctf

# Dynamic flag — regenerated per container unless FLAG env var is provided.
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    FLAG="INFODAYS{SaamNoLimits_format_str1ng_h4rd_m0de_${RANDHEX}}"
fi

echo -n "${FLAG}" > /home/ctf/flag.txt
chmod 644 /home/ctf/flag.txt
unset FLAG

exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./var_review
