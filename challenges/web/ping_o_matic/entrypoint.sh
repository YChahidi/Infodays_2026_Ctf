#!/bin/sh
set -e
echo -n "${FLAG:-INFODAYS{CMD_INJ3CT10N_W4F_BYP4SS_2026}}" > /tmp/flag.txt
exec python3 app.py
