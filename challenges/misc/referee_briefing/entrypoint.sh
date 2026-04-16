#!/bin/bash
set -euo pipefail

: "${USER_FLAG:?USER_FLAG must be set in .env}"
: "${ROOT_FLAG:?ROOT_FLAG must be set in .env}"

# User flag: lives in a secrets dir the referee user owns but which
# the MCP server does NOT advertise in list_reports().
install -d -m 700 -o referee -g referee /app/secrets
printf '%s\n' "$USER_FLAG" > /app/secrets/user_flag.txt
chown referee:referee /app/secrets/user_flag.txt
chmod 600 /app/secrets/user_flag.txt

# Root flag: strictly root-owned, unreachable without privesc.
printf '%s\n' "$ROOT_FLAG" > /root/root_flag.txt
chown root:root /root/root_flag.txt
chmod 600 /root/root_flag.txt

# Drop the env vars from the child process's view so they cannot be
# read out of /proc/*/environ once referee has a shell.
unset USER_FLAG ROOT_FLAG

# Drop to referee and launch the MCP server.
export PORT=4444
exec runuser -u referee -- python3 -u /app/server.py
