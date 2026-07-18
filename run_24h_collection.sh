#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="python3"
fi
exec "$PYTHON" -u -m ueba_detector collect \
  --output data/baseline_24h_tcp.jsonl \
  --interval 60 \
  --duration 24h
