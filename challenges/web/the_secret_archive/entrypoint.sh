#!/bin/sh
set -e
echo -n "${FLAG:-INFODAYS{tr4v3rsal_m4st3r_2026_standalone}}" > /tmp/the_real_flag.txt
exec python3 app.py
