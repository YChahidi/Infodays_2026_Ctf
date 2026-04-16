#!/bin/sh
set -e
export FLAG="${FLAG:-INFODAYS{b64_d3c0d3_f0und}}"
exec python3 app.py
