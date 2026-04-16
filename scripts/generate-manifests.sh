#!/bin/bash
# Generate K8s manifests from challenge-template.yaml for all containerized challenges.
# Usage: bash scripts/generate-manifests.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/k8s/challenge-template.yaml"
OUTDIR="$ROOT/k8s/manifests"
mkdir -p "$OUTDIR"

generate() {
    local name="$1" category="$2" port="$3" nodeport="$4"
    sed \
        -e "s/CHALLENGE_NAME/$name/g" \
        -e "s/CATEGORY/$category/g" \
        -e "s/PORT/$port/g" \
        -e "s/NODEPORT/$nodeport/g" \
        "$TEMPLATE" > "$OUTDIR/$name.yaml"
    echo "  Generated $name.yaml"
}

echo "=== Generating K8s manifests ==="

# Web (HTTP, port 8080)
generate vip-access        Web       8080 30001
generate secret-archive    Web       8080 30002
generate ping-o-matic      Web       8080 30003
generate scout-database    Web       8080 30004
generate var-check-bro     Web       8080 30005
generate stadium-ci        Web       8080 30006
generate referee-decision  Web       8080 30007
generate man-city          Web       8080 30008
generate stadium-defi      Web       8080 30009

# Pwn (TCP, port 1337)
generate var-review        Pwn       1337 30011
generate var-replay-buffer Pwn       1337 30012
generate shanks            Pwn       1337 30013

# Misc
generate coach-gpt         Misc      8080 30014
generate referee-briefing  Misc      4444 30015
generate ait-baha-nuclear  Misc      8080 30016
generate agadir-medport    Misc      1883 30018

# Forensics
generate malware-lab       Forensics 8080 30019
generate stadium-ir        Forensics 2222 30020
generate stadium-soc       Forensics 8080 30021

echo ""
echo "=== Generated ${#} manifests in $OUTDIR ==="
echo "Note: stadium-defi (30010/8545 RPC) and ait-baha-nuclear (30017/5020 Modbus)"
echo "      need extra port entries added manually to their manifests."
