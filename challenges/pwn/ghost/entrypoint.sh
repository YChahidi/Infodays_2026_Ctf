#!/bin/sh
# entrypoint.sh — Ghost Protocol
set -e

if [ -z "${FLAG}" ]; then
    echo "ERROR: FLAG environment variable is not set." >&2
    exit 1
fi

# Write flag to /flag.txt so players can read it after getting a shell.
# Must run as root before dropping privileges — write then chmod.
# (entrypoint runs as ghost user via USER in Dockerfile,
#  so we use a setup step that runs before socat.)
echo "${FLAG}" > /tmp/flag.txt
# Move to root-owned location — socat EXEC runs as ghost (uid 1000)
# flag.txt is readable by all so `cat /flag.txt` works after shell.
# For extra hardness, remove this chmod and let players find another way.
chmod 644 /tmp/flag.txt

# Symlink to expected path
ln -sf /tmp/flag.txt /flag.txt 2>/dev/null || true

exec "$@"
