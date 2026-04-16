#!/bin/bash
set -e

rand() { head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Dynamic flags — regenerated per container unless provided via env.
if [ -z "${FLAG1}" ]; then
    export FLAG1="INFODAYS{SaamNoLimits_agadir_hidden_topic_$(rand)}"
fi
if [ -z "${FLAG2}" ]; then
    export FLAG2="INFODAYS{SaamNoLimits_crane_diag_override_$(rand)}"
fi
if [ -z "${FLAG3}" ]; then
    export FLAG3="INFODAYS{SaamNoLimits_ops_vault_unlocked_$(rand)}"
fi

# Dynamic broker credentials.
if [ -z "${OPS_PASS}" ]; then
    export OPS_PASS="AgadirMed_$(rand)"
fi
if [ -z "${SIM_PASS}" ]; then
    export SIM_PASS="sim_$(rand)"
fi

# Generate password file for mosquitto.
rm -f /etc/mosquitto/passwd
mosquitto_passwd -c -b /etc/mosquitto/passwd opsadmin "${OPS_PASS}"
mosquitto_passwd -b    /etc/mosquitto/passwd simulator "${SIM_PASS}"
chown mosquitto:mosquitto /etc/mosquitto/passwd /etc/mosquitto/acl 2>/dev/null || true
chmod 640 /etc/mosquitto/passwd /etc/mosquitto/acl

echo "[*] dynamic flags + broker creds ready"
echo "[*] starting mosquitto broker on :1883"
mosquitto -c /etc/mosquitto/mosquitto.conf &
BROKER_PID=$!

sleep 2
echo "[*] starting simulator"
python3 /app/simulator.py &
SIM_PID=$!

wait -n "${BROKER_PID}" "${SIM_PID}"
EXIT=$?
echo "[!] a backend process exited (${EXIT}), tearing down"
kill "${BROKER_PID}" "${SIM_PID}" 2>/dev/null || true
exit "${EXIT}"
