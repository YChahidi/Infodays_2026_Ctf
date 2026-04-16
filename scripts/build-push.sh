#!/bin/bash
# Infodays 2026 CTF — Build and push all challenge images to DOCR
set -euo pipefail

REGISTRY="${REGISTRY:-registry.digitalocean.com/infodays-registry}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Building base images ==="
for base in web pwn misc crypto forensics reversing osint; do
    echo "[base:$base] Building..."
    docker build -q -t "$REGISTRY/base:$base" "$ROOT/base/$base/"
    echo "[base:$base] Pushing..."
    docker push "$REGISTRY/base:$base"
done

echo ""
echo "=== Building challenge images ==="

# Only containerized challenges (type != static)
declare -A CHALLENGES=(
    # Web
    ["challenges/web/VIP_Access_Session_Inspector"]="vip-access"
    ["challenges/web/the_secret_archive"]="secret-archive"
    ["challenges/web/ping_o_matic"]="ping-o-matic"
    ["challenges/web/scout_database"]="scout-database"
    ["challenges/web/var_check_bro"]="var-check-bro"
    ["challenges/web/stadium_ci"]="stadium-ci"
    ["challenges/web/referee_decision_system"]="referee-decision"
    ["challenges/web/man_city"]="man-city"
    ["challenges/web/stadium_defi"]="stadium-defi"
    # Pwn
    ["challenges/pwn/var_review"]="var-review"
    ["challenges/pwn/var_replay_buffer"]="var-replay-buffer"
    ["challenges/pwn/shanks"]="shanks"
    # Misc
    ["challenges/misc/coach_gpt_jailbreak"]="coach-gpt"
    ["challenges/misc/referee_briefing"]="referee-briefing"
    ["challenges/misc/ait_baha_nuclear"]="ait-baha-nuclear"
    ["challenges/misc/agadir_medport"]="agadir-medport"
    # Forensics (containerized only)
    ["challenges/forensics/malware_lab_stadium"]="malware-lab"
    ["challenges/forensics/stadium_ir"]="stadium-ir"
    ["challenges/forensics/stadium_soc"]="stadium-soc"
)

for path in "${!CHALLENGES[@]}"; do
    name="${CHALLENGES[$path]}"
    echo "[$name] Building from $path..."
    docker build -q -t "$REGISTRY/$name:latest" "$ROOT/$path/"
    echo "[$name] Pushing..."
    docker push "$REGISTRY/$name:latest"
done

echo ""
echo "=== All images built and pushed ==="
