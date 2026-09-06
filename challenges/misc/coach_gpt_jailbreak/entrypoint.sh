#!/bin/bash
set -e

rand() { head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

if [ -z "${FLAG_MID}" ]; then
    export FLAG_MID="INFODAYS{SaamNoLimits_prompt_leak_$(rand)}"
fi
if [ -z "${FLAG_HARD}" ]; then
    export FLAG_HARD="INFODAYS{SaamNoLimits_coach_jailbroken_$(rand)}"
fi
if [ -z "${DEBUG_TOKEN}" ]; then
    export DEBUG_TOKEN="kickoff-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

echo "[*] dynamic flags + debug token ready"
echo "[*] starting CoachGPT on :8080"
exec python3 /app/chatbot.py
