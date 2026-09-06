#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: $0 MODEL RULES [CLOUD_ENDPOINT] [INGEST_KEY_FILE] [DURATION]" >&2
  exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON="$ROOT/.venv/bin/python"
MODEL=$1
RULES=$2
ENDPOINT=${3:-}
KEY_FILE=${4:-}
DURATION=${5:-168h}
LABEL=io.hostwatch.shadow-monitor
RUNTIME="$HOME/Library/Application Support/HostWatch"
LOG_DIR="$HOME/Library/Logs/HostWatch"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

if [ ! -x "$PYTHON" ]; then
  echo "missing $PYTHON; create the virtual environment and install requirements first" >&2
  exit 1
fi
if [ ! -f "$MODEL" ] || [ ! -f "$RULES" ]; then
  echo "model or rules file does not exist" >&2
  exit 1
fi
if [ -n "$ENDPOINT" ] && [ ! -f "$KEY_FILE" ]; then
  echo "cloud reporting requires an ingest-key file" >&2
  exit 1
fi

mkdir -p "$RUNTIME/data" "$RUNTIME/reports" "$LOG_DIR" "$HOME/Library/LaunchAgents"
chmod 700 "$RUNTIME" "$RUNTIME/data" "$RUNTIME/reports"
PYTHON_COMMAND=$("$PYTHON" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')
BASE_PYTHON=$(command -v "$PYTHON_COMMAND")
PSUTIL_DIR=$("$PYTHON" -c 'import pathlib, psutil; print(pathlib.Path(psutil.__file__).parent)')
STAGE="$RUNTIME/app.new.$$"
mkdir -p "$STAGE"
cp -R "$ROOT/ueba_detector" "$STAGE/ueba_detector"
cp -R "$PSUTIL_DIR" "$STAGE/psutil"
rm -rf "$RUNTIME/app.previous"
if [ -d "$RUNTIME/app" ]; then mv "$RUNTIME/app" "$RUNTIME/app.previous"; fi
mv "$STAGE" "$RUNTIME/app"
rm -rf "$RUNTIME/app.previous"
cp "$MODEL" "$RUNTIME/model.json"
cp "$RULES" "$RUNTIME/rules.json"
chmod 600 "$RUNTIME/model.json" "$RUNTIME/rules.json"

"$BASE_PYTHON" - "$PLIST" "$LABEL" "$RUNTIME" "$LOG_DIR" "$BASE_PYTHON" \
  "$DURATION" "$ENDPOINT" "$KEY_FILE" <<'PY'
import plistlib
import sys

plist, label, runtime, log_dir, python, duration, endpoint, key_file = sys.argv[1:]
arguments = [
    "/usr/bin/caffeinate", "-im", python, "-m", "ueba_detector", "shadow-monitor",
    "--model", f"{runtime}/model.json",
    "--rules", f"{runtime}/rules.json",
    "--metrics-output", f"{runtime}/data/shadow_metrics.jsonl",
    "--events-output", f"{runtime}/data/shadow_events.jsonl",
    "--state", f"{runtime}/data/shadow_agent_state.json",
    "--identity-salt", f"{runtime}/data/shadow_identity_salt",
    "--scores-output", f"{runtime}/reports/shadow_scores.jsonl",
    "--alerts-output", f"{runtime}/reports/shadow_alerts.jsonl",
    "--duration", duration,
    "--no-package-inventory",
]
if endpoint:
    arguments.extend(["--cloud-endpoint", endpoint, "--ingest-key-file", key_file])
payload = {
    "Label": label,
    "ProgramArguments": arguments,
    "WorkingDirectory": runtime,
    "EnvironmentVariables": {"PYTHONPATH": f"{runtime}/app"},
    "RunAtLoad": True,
    "KeepAlive": {"SuccessfulExit": False},
    "ProcessType": "Background",
    "StandardOutPath": f"{log_dir}/shadow-monitor.log",
    "StandardErrorPath": f"{log_dir}/shadow-monitor.error.log",
}
with open(plist, "wb") as handle:
    plistlib.dump(payload, handle, sort_keys=False)
PY
chmod 600 "$PLIST"

launchctl bootout "gui/$UID/$LABEL" >/dev/null 2>&1 || true
sleep 1
if ! launchctl bootstrap "gui/$UID" "$PLIST"; then
  sleep 2
  launchctl bootstrap "gui/$UID" "$PLIST"
fi
launchctl kickstart -k "gui/$UID/$LABEL"
echo "HostWatch shadow monitor started"
echo "status: launchctl print gui/$UID/$LABEL"
echo "logs: $LOG_DIR"
