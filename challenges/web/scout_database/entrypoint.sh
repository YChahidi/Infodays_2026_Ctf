#!/bin/sh
set -e
export FLAG="${FLAG:-INFODAYS{SQLI_CH4R_N0_5P4C3_2026}}"
python3 init_db.py
exec python3 app.py
