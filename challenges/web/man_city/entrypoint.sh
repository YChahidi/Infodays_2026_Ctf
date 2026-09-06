#!/bin/sh
set -e

# Generate flags and assets (uses FLAG1-FLAG8 env vars if set,
# otherwise gen.py produces random ones and writes .env)
python3 gen.py
exec python3 app.py
