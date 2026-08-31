#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
REQUEST_FILE="$ROOT_DIR/logs/combined_collection.duration"
DURATION="resume"
if [ -f "$REQUEST_FILE" ]; then
    DURATION="$(sed -n '1p' "$REQUEST_FILE")"
    rm -f "$REQUEST_FILE"
fi
exec "$ROOT_DIR/run_combined_collection.sh" worker "$DURATION"
