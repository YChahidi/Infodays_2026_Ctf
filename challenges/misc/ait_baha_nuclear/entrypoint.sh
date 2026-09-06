#!/bin/bash
set -e

rand() { head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Dynamic flags — regenerated per container unless provided via env.
# Format: INFODAYS{SaamNoLimits_<phrase>_<randhex>}
if [ -z "${FLAG1}" ]; then
    export FLAG1="INFODAYS{SaamNoLimits_silent_sensor_$(rand)}"
fi
if [ -z "${FLAG2}" ]; then
    export FLAG2="INFODAYS{SaamNoLimits_calibration_bypass_$(rand)}"
fi
if [ -z "${FLAG3}" ]; then
    export FLAG3="INFODAYS{SaamNoLimits_interlock_forged_$(rand)}"
fi

echo "[*] dynamic flags ready"
echo "[*] starting Modbus PLC backend on :5020"
python3 /app/modbus_server.py &
MB_PID=$!

sleep 2
echo "[*] starting HMI on :8080"
python3 /app/hmi.py &
HMI_PID=$!

wait -n "${MB_PID}" "${HMI_PID}"
EXIT=$?
echo "[!] a backend process exited (${EXIT}), tearing down"
kill "${MB_PID}" "${HMI_PID}" 2>/dev/null || true
exit "${EXIT}"
