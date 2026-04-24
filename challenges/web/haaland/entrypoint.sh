#!/bin/bash
set -e

if [ -z "${FLAG}" ]; then
    RANDHEX=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    FLAG="INFODAYS{SaamNoLimits_k_reuse_wrecks_the_derby_${RANDHEX}}"
fi
export FLAG

# Anvil default keys (deterministic):
#   idx 0: deployer
#   idx 1: signer (Haaland's off-chain pass signer)
#   idx 2, 3: promo holders 1 & 2 — broadcast the canary passes
export DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export SIGNER_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
export PROMO_PK_1=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
export PROMO_PK_2=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6

mkdir -p /app/state
cd /app

echo "[entrypoint] starting anvil..."
anvil --host 0.0.0.0 --port 8545 --chain-id 31337 --block-time 2 --silent &
ANVIL_PID=$!

for i in $(seq 1 30); do
    if curl -sf -X POST -H 'Content-Type: application/json' \
         --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
         http://127.0.0.1:8545 > /dev/null; then
        break
    fi
    sleep 0.3
done

echo "[entrypoint] generating k-reused promo signatures..."
eval "$(python3 /app/script/gen_promos.py)"
echo "  PROMO_SIG_1=${PROMO_SIG_1}"
echo "  PROMO_SIG_2=${PROMO_SIG_2}"

echo "[entrypoint] deploying contracts..."
forge script script/Deploy.s.sol:Deploy \
    --rpc-url http://127.0.0.1:8545 \
    --private-key "${DEPLOYER_PK}" \
    --broadcast --slow

echo "[entrypoint] deployed state:"
cat /app/state/deployed.json
echo

echo "[entrypoint] starting frontend..."
exec python3 /app/frontend/app.py
