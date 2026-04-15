#!/bin/bash
set -e

# Dynamic flag — generated per container instance unless FLAG env var is provided
if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    FLAG="INFODAYS{SaamNoLimits_the_house_always_falls_${RANDHEX}}"
fi
export FLAG

mkdir -p /app/state
cd /app

# Start anvil in the background on all interfaces so the RPC is reachable
# from outside the container. Deterministic mnemonic and chain ID keep the
# challenge reproducible.
echo "[entrypoint] starting anvil..."
anvil \
    --host 0.0.0.0 \
    --port 8545 \
    --chain-id 31337 \
    --block-time 2 \
    --silent &
ANVIL_PID=$!

# Wait for anvil JSON-RPC to come up.
for i in $(seq 1 30); do
    if curl -sf -X POST -H 'Content-Type: application/json' \
         --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
         http://127.0.0.1:8545 > /dev/null; then
        break
    fi
    sleep 0.3
done

echo "[entrypoint] deploying contracts..."
# First anvil default account / private key
DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

forge script script/Deploy.s.sol:Deploy \
    --rpc-url http://127.0.0.1:8545 \
    --private-key "${DEPLOYER_PK}" \
    --broadcast \
    --slow

echo "[entrypoint] deployed state:"
cat /app/state/deployed.json
echo

echo "[entrypoint] starting frontend..."
exec python3 /app/frontend/app.py
