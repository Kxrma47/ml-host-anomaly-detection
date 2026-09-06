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
cp "$MODEL" "$RUNTIME/model.json"
cp "$RULES" "$RUNTIME/rules.json"
chmod 600 "$RUNTIME/model.json" "$RUNTIME/rules.json"

CLOUD_ARGS=""
if [ -n "$ENDPOINT" ]; then
  CLOUD_ARGS="
    <string>--cloud-endpoint</string><string>$ENDPOINT</string>
    <string>--ingest-key-file</string><string>$KEY_FILE</string>"
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/caffeinate</string><string>-im</string>
    <string>$PYTHON</string><string>-m</string><string>ueba_detector</string><string>shadow-monitor</string>
    <string>--model</string><string>$RUNTIME/model.json</string>
    <string>--rules</string><string>$RUNTIME/rules.json</string>
    <string>--metrics-output</string><string>$RUNTIME/data/shadow_metrics.jsonl</string>
    <string>--events-output</string><string>$RUNTIME/data/shadow_events.jsonl</string>
    <string>--state</string><string>$RUNTIME/data/shadow_agent_state.json</string>
    <string>--identity-salt</string><string>$RUNTIME/data/shadow_identity_salt</string>
    <string>--scores-output</string><string>$RUNTIME/reports/shadow_scores.jsonl</string>
    <string>--alerts-output</string><string>$RUNTIME/reports/shadow_alerts.jsonl</string>
    <string>--duration</string><string>$DURATION</string>
    <string>--no-package-inventory</string>$CLOUD_ARGS
  </array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$LOG_DIR/shadow-monitor.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/shadow-monitor.error.log</string>
</dict></plist>
EOF
chmod 600 "$PLIST"

launchctl bootout "gui/$UID/$LABEL" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$UID" "$PLIST"
launchctl kickstart -k "gui/$UID/$LABEL"
echo "HostWatch shadow monitor started"
echo "status: launchctl print gui/$UID/$LABEL"
echo "logs: $LOG_DIR"
