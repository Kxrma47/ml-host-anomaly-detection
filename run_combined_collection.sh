#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
LOG_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOG_DIR/combined_collection.log"
COLLECTOR_PID_FILE="$LOG_DIR/combined_collection.pid"
CAFFEINATE_PID_FILE="$LOG_DIR/combined_caffeinate.pid"
REQUEST_FILE="$LOG_DIR/combined_collection.duration"
COMMAND_FILE="$ROOT_DIR/run_combined_collection.command"
PROGRESS_FILE="$LOG_DIR/combined_collection.progress"
STOP_FILE="$LOG_DIR/combined_collection.stop"
AUTOSTART_FILE="$HOME/Library/LaunchAgents/com.ueba.combined-collection.plist"

is_running() {
    local pid_file="$1"
    [ -f "$pid_file" ] && kill -0 "$(sed -n '1p' "$pid_file")" 2>/dev/null
}

show_status() {
    if is_running "$COLLECTOR_PID_FILE"; then
        echo "collector running (PID $(sed -n '1p' "$COLLECTOR_PID_FILE"))"
    else
        echo "collector not running"
    fi
    if is_running "$CAFFEINATE_PID_FILE"; then
        echo "caffeinate running (PID $(sed -n '1p' "$CAFFEINATE_PID_FILE"))"
    else
        echo "caffeinate not running"
    fi
    if [ -f "$PROGRESS_FILE" ]; then
        echo "target active seconds: $(sed -n '1p' "$PROGRESS_FILE")"
        echo "completed active seconds: $(sed -n '2p' "$PROGRESS_FILE")"
        echo "remaining active seconds: $(sed -n '3p' "$PROGRESS_FILE")"
        echo "collector restarts: $(sed -n '4p' "$PROGRESS_FILE")"
    fi
    echo "log: $LOG_FILE"
}

duration_seconds() {
    "$PYTHON_BIN" -m ueba_detector duration-seconds "$1"
}

write_progress() {
    local target="$1"
    local completed="$2"
    local remaining="$3"
    local restarts="$4"
    printf '%s\n%s\n%s\n%s\n' "$target" "$completed" "$remaining" "$restarts" > "$PROGRESS_FILE"
}

start_collection() {
    local duration="${1:-168h}"
    if is_running "$COLLECTOR_PID_FILE"; then
        show_status
        exit 0
    fi
    if [ ! -x "$PYTHON_BIN" ]; then
        echo "Missing virtual environment Python: $PYTHON_BIN" >&2
        exit 1
    fi

    mkdir -p "$LOG_DIR" "$ROOT_DIR/data"
    rm -f "$STOP_FILE"
    printf '%s\n' "$duration" > "$REQUEST_FILE"
    open -a Terminal "$COMMAND_FILE"
    sleep 2
    show_status
}

run_worker() {
    local requested_duration="${1:-resume}"
    local collector_pid=""
    local caffeinate_pid=""
    local target_seconds=""
    local completed_seconds=0
    local remaining_seconds=0
    local restart_count=0
    local session_started=0

    cleanup() {
        if [ "$session_started" -gt 0 ] && [ "$remaining_seconds" -gt 0 ]; then
            local now
            now="$(date +%s)"
            local elapsed=$((now - session_started))
            completed_seconds=$((completed_seconds + elapsed))
            remaining_seconds=$((target_seconds - completed_seconds))
            if [ "$remaining_seconds" -lt 0 ]; then
                remaining_seconds=0
            fi
            write_progress "$target_seconds" "$completed_seconds" "$remaining_seconds" "$restart_count"
            session_started=0
        fi
        if [ -n "$collector_pid" ] && kill -0 "$collector_pid" 2>/dev/null; then
            kill "$collector_pid" 2>/dev/null || true
        fi
        if [ -n "$caffeinate_pid" ] && kill -0 "$caffeinate_pid" 2>/dev/null; then
            kill "$caffeinate_pid" 2>/dev/null || true
        fi
        rm -f "$COLLECTOR_PID_FILE" "$CAFFEINATE_PID_FILE"
    }
    trap cleanup EXIT INT TERM

    cd "$ROOT_DIR"
    mkdir -p "$LOG_DIR" "$ROOT_DIR/data"
    if [ "$requested_duration" = "resume" ] && [ -f "$PROGRESS_FILE" ]; then
        target_seconds="$(sed -n '1p' "$PROGRESS_FILE")"
        completed_seconds="$(sed -n '2p' "$PROGRESS_FILE")"
        remaining_seconds="$(sed -n '3p' "$PROGRESS_FILE")"
        restart_count="$(sed -n '4p' "$PROGRESS_FILE")"
    else
        if [ "$requested_duration" = "resume" ]; then
            requested_duration="168h"
        fi
        target_seconds="$(duration_seconds "$requested_duration")"
        completed_seconds=0
        remaining_seconds="$target_seconds"
        restart_count=0
        write_progress "$target_seconds" "$completed_seconds" "$remaining_seconds" "$restart_count"
    fi

    rm -f "$STOP_FILE"
    while [ "$remaining_seconds" -gt 0 ]; do
        printf '\n[%s] starting combined collection with %s active seconds remaining\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$remaining_seconds" >> "$LOG_FILE"
        session_started="$(date +%s)"
        "$PYTHON_BIN" -m ueba_detector collect-all \
            --metrics-output "$ROOT_DIR/data/mac_metrics.jsonl" \
            --events-output "$ROOT_DIR/data/mac_events.jsonl" \
            --state "$ROOT_DIR/data/mac_agent_state.json" \
            --metric-interval 60 \
            --event-interval 2 \
            --package-interval 3600 \
            --heartbeat-interval 60 \
            --duration "${remaining_seconds}s" \
            --max-file-mb 250 \
            --retention-days 30 \
            --no-package-inventory >> "$LOG_FILE" 2>&1 &
        collector_pid=$!
        printf '%s\n' "$collector_pid" > "$COLLECTOR_PID_FILE"

        /usr/bin/caffeinate -im -w "$collector_pid" >> "$LOG_FILE" 2>&1 &
        caffeinate_pid=$!
        printf '%s\n' "$caffeinate_pid" > "$CAFFEINATE_PID_FILE"
        echo "Combined collection is running. This Terminal window may remain in the background."
        echo "Collector PID: $collector_pid"
        echo "Caffeinate PID: $caffeinate_pid"
        echo "Remaining active seconds: $remaining_seconds"
        echo "Log: $LOG_FILE"

        set +e
        wait "$collector_pid"
        local status=$?
        set -e
        local ended
        ended="$(date +%s)"
        local elapsed=$((ended - session_started))
        session_started=0
        completed_seconds=$((completed_seconds + elapsed))
        remaining_seconds=$((target_seconds - completed_seconds))
        if [ "$remaining_seconds" -lt 0 ]; then
            remaining_seconds=0
        fi
        if kill -0 "$caffeinate_pid" 2>/dev/null; then
            kill "$caffeinate_pid" 2>/dev/null || true
        fi
        collector_pid=""
        caffeinate_pid=""
        rm -f "$COLLECTOR_PID_FILE" "$CAFFEINATE_PID_FILE"
        write_progress "$target_seconds" "$completed_seconds" "$remaining_seconds" "$restart_count"

        if [ -f "$STOP_FILE" ] || [ "$remaining_seconds" -eq 0 ]; then
            break
        fi
        restart_count=$((restart_count + 1))
        write_progress "$target_seconds" "$completed_seconds" "$remaining_seconds" "$restart_count"
        printf '[%s] collector exited with status %s; restarting in 5 seconds\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status" >> "$LOG_FILE"
        sleep 5
    done
    rm -f "$STOP_FILE"
}

stop_collection() {
    mkdir -p "$LOG_DIR"
    : > "$STOP_FILE"
    if is_running "$COLLECTOR_PID_FILE"; then
        kill "$(sed -n '1p' "$COLLECTOR_PID_FILE")"
    fi
    if is_running "$CAFFEINATE_PID_FILE"; then
        kill "$(sed -n '1p' "$CAFFEINATE_PID_FILE")" 2>/dev/null || true
    fi
    rm -f "$COLLECTOR_PID_FILE" "$CAFFEINATE_PID_FILE"
    echo "combined collection stopped"
}

install_autostart() {
    mkdir -p "$(dirname "$AUTOSTART_FILE")"
    cat > "$AUTOSTART_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.ueba.combined-collection</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/open</string><string>-a</string><string>Terminal</string><string>$COMMAND_FILE</string></array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
    chmod 600 "$AUTOSTART_FILE"
    echo "autostart installed for the next macOS login: $AUTOSTART_FILE"
}

uninstall_autostart() {
    rm -f "$AUTOSTART_FILE"
    echo "autostart removed"
}

case "${1:-start}" in
    start)
        start_collection "${2:-168h}"
        ;;
    status)
        show_status
        ;;
    stop)
        stop_collection
        ;;
    worker)
        run_worker "${2:-resume}"
        ;;
    install-autostart)
        install_autostart
        ;;
    uninstall-autostart)
        uninstall_autostart
        ;;
    *)
        echo "usage: $0 {start [duration]|status|stop|install-autostart|uninstall-autostart}" >&2
        exit 2
        ;;
esac
