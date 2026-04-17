#!/bin/bash

echo "[*] Generating secrets..."
python3 build_secret.py

echo "[*] Compiling..."

gcc legend_gate.c -o legend_gate \
    -O2 \
    -fno-pie -no-pie \
    -fstack-protector-strong \
    -s

echo "[+] Done"
