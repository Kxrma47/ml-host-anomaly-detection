#!/bin/sh
set -eu

LABEL=io.hostwatch.shadow-monitor
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
launchctl bootout "gui/$UID/$LABEL" >/dev/null 2>&1 || true
rm -f "$PLIST"
echo "HostWatch shadow monitor stopped and its LaunchAgent was removed"
echo "Local evidence remains under $HOME/Library/Application Support/HostWatch"
