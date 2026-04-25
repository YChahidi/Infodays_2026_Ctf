#!/bin/bash
# build_and_test.sh — Ghost Protocol
# Run this on your Kali machine to build, run, and extract libc for the solve.
set -e

CHALLENGE_DIR="$(cd "$(dirname "$0")/../" && pwd)"
SOLVE_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="ghost-protocol-local"
CONTAINER="ghost-test"

echo "[*] Building Docker image..."
docker build -t "$IMAGE" "$CHALLENGE_DIR"

echo "[*] Stopping old container if running..."
docker rm -f "$CONTAINER" 2>/dev/null || true

echo "[*] Starting challenge container..."
docker run -d \
    --name "$CONTAINER" \
    -p 1337:1337 \
    -e FLAG="infodays{test_flag_replace_in_prod}" \
    "$IMAGE"

echo "[*] Waiting for socat to be ready..."
sleep 2

echo "[*] Extracting libc from container for the solve script..."
docker cp "$CONTAINER":/lib/x86_64-linux-gnu/libc.so.6 "$SOLVE_DIR/libc.so.6"
echo "[+] libc saved to solve/libc.so.6"

echo "[*] Extracting binary from container..."
docker cp "$CONTAINER":/usr/local/bin/ghost "$SOLVE_DIR/ghost"
echo "[+] Binary saved to solve/ghost"

echo ""
echo "========================================"
echo " Challenge running on localhost:1337"
echo " Test manually:  nc 127.0.0.1 1337"
echo " Run solve:      cd solve && python3 solve.py LOCAL"
echo "========================================"

echo ""
echo "[*] checksec output:"
checksec --file="$SOLVE_DIR/ghost" 2>/dev/null || \
    python3 -c "from pwn import *; e=ELF('$SOLVE_DIR/ghost'); print(e.checksec())" 2>/dev/null || \
    echo "    (install pwntools or checksec to verify flags)"
