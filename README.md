# ML Host Anomaly Detection

[![Tests](https://github.com/Kxrma47/ml-host-anomaly-detection/actions/workflows/tests.yml/badge.svg)](https://github.com/Kxrma47/ml-host-anomaly-detection/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-research%20prototype-7C3AED)
[![GitHub stars](https://img.shields.io/github/stars/Kxrma47/ml-host-anomaly-detection?style=social)](https://github.com/Kxrma47/ml-host-anomaly-detection/stargazers)

**A reproducible UEBA-style pipeline for detecting anomalous workstation
telemetry with a compact neural autoencoder.**

<p align="center">
  <img src="docs/assets/terminal-demo.gif" width="100%" alt="Terminal demo showing the reproducible anomaly-detection benchmark" />
</p>

It collects local host telemetry, trains an autoencoder on normal behavior, and then uses the saved model to monitor new samples. The goal is not to replace an EDR or SIEM product. The goal is to show the full pipeline: data collection, normalization, model training, threshold selection, monitoring, and anomaly reporting.

## Verified benchmark

| Signal | Result |
| --- | ---: |
| Real baseline telemetry | 1,439 samples / 24 hours |
| Injected anomaly detection | 26 / 26 |
| False negatives | 0 |
| Normal false positives | 3 / 94 |
| Recall | 1.0 |

The benchmark is fully reproducible from deterministic synthetic data. See
[Reproducing the demo](docs/reproducibility.md) for the clean-room workflow and
machine-readable output checks.

## Pipeline

<p align="center">
  <img src="docs/pipeline.svg" width="100%" alt="Telemetry collection, feature normalization, autoencoder training, threshold calibration, scoring, and anomaly reporting pipeline" />
</p>

Version 0.4 adds combined training, live-safe readiness audits, host-specific rule calibration, chronological evaluation, resilient collection supervision, compressed rotation/retention, and a local progress dashboard.

## What is collected

The collector records aggregated host metrics:

- CPU, memory, swap, and load average
- process, user process, and thread counts
- network traffic rates
- TCP connection counters
- number of unique remote ports
- disk read and write rates

These signals are simple, but they are useful for a prototype because they change during common suspicious patterns: process bursts, network scanning, heavy file access, and abnormal resource usage.

## Security events

The `collect-events` agent adds event context that aggregate metrics cannot provide:

- process starts and stops, including parent PID, executable, user, and redacted command line
- interactive login-session starts and ends
- SSH/PAM authentication successes and failures from supported authentication logs
- `sudo` privilege-elevation events with redacted commands
- installed package inventory and package install, removal, and version changes
- agent heartbeat and isolated collector-error events

Every record uses a versioned, OCSF-aligned JSON schema with a unique event ID, UTC timestamp, host, category, class, activity, status, severity, source, and structured event data.

Passwords, tokens, API keys, cookies, authorization headers, and URL credentials are redacted locally before events are persisted. The agent is not a keylogger and does not collect password or web-form contents.

## Repository layout

```text
ueba_detector/                 source code
ueba_detector/event_collectors/ event-based host collectors
tests/                         unit tests
data/baseline_24h_tcp.jsonl    anonymized 24-hour baseline dataset
models/ueba_model.json         trained model
reports/                       monitoring and anomaly report examples
examples/demo_run/             synthetic demo data and outputs
report.txt                     full bilingual report
```

## Quick start

Clone the repository, then run the complete setup, test, and deterministic demo
with one command:

```bash
make quickstart
```

## Manual installation

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Collect security events

Run continuously with the default process, session, authentication-log, and package collectors:

```bash
python3 -m ueba_detector collect-events \
  --output data/security_events.jsonl \
  --state data/agent_state.json
```

Run a five-minute check without the slower package inventory:

```bash
python3 -m ueba_detector collect-events \
  --duration 5m \
  --no-packages
```

On the first run, existing processes, sessions, and old authentication-log lines are used as a baseline and are not replayed. The initial package inventory is emitted once. Later runs use `data/agent_state.json` to detect changes without replaying prior activity.

Useful controls:

```text
--auth-log PATH             add an explicit authentication log
--replay-auth-logs          process existing log contents on first run
--emit-existing-processes   emit the initial process inventory
--emit-existing-sessions    emit currently active sessions
--no-package-inventory      baseline packages without emitting every package
--package-interval 300      package inventory refresh frequency
```

Process and authentication visibility depends on operating-system permissions. A production service should run under a dedicated, least-privileged account with explicit read access to the required event sources. Collector failures do not terminate the agent; they are emitted as `collector_error` records.

## Combined collection and training

Collect metrics and events together for seven days on macOS:

```bash
caffeinate -im .venv/bin/python -m ueba_detector collect-all \
  --metrics-output data/mac_metrics.jsonl \
  --events-output data/mac_events.jsonl \
  --state data/mac_agent_state.json \
  --metric-interval 60 \
  --event-interval 2 \
  --duration 168h \
  --no-package-inventory
```

`caffeinate -im` prevents idle system and disk sleep while collection is running. It cannot keep a Mac awake after the laptop lid is closed, and the Mac should remain connected to power.

The repository also includes a background wrapper:

```bash
./run_combined_collection.sh start 168h
./run_combined_collection.sh status
./run_combined_collection.sh stop
```

It opens a persistent Terminal worker, runs the collector with a paired `caffeinate -im` process, stores both process IDs under `logs/`, checkpoints active seconds, and writes progress to `logs/combined_collection.log`. On the next run, the supervisor restarts a crashed collector until the requested active duration is reached. Intentional `stop` creates a stop marker so the supervisor does not restart it.

Future wrapper runs rotate metric and event files at 250 MB, gzip completed segments, and retain rotated segments for 30 days. Audit, feature-building, and training commands transparently read the compressed segments together with the active file. Collection commands also expose these settings directly:

```text
--max-file-mb 250
--retention-days 30
--no-compress-rotated
```

An optional login launcher can resume an unfinished checkpoint after macOS login:

```bash
./run_combined_collection.sh install-autostart
./run_combined_collection.sh uninstall-autostart
```

The launcher opens Terminal because macOS privacy controls prevent a background `launchd` Python process from directly executing a project inside `Downloads`. It is not enabled automatically during an active collection.

Audit the files at any time while collection is still running:

```bash
.venv/bin/python -m ueba_detector audit-data \
  --metrics data/mac_metrics.jsonl \
  --events data/mac_events.jsonl \
  --output reports/training_readiness.json
```

The audit reads a fixed-size snapshot, so an event appended during the check cannot corrupt the report. It checks malformed and duplicate records, timestamp and feature validity, per-host minute coverage, missing windows, long gaps, collector errors, event distribution, and rule-flagged windows. It then proposes chronological 70/15/15 splits using only training candidates. A rule that flags more than 5% of all windows is reported as noisy and is not automatically excluded; this prevents an uncalibrated rule from silently removing a large share of otherwise valid baseline data.

Readiness states:

```text
INSUFFICIENT         fewer than 1,440 clean windows (one day)
PRELIMINARY          enough for an early experiment, but fewer than 10,080 clean windows
INVALID              enough windows exist, but structural data errors block training
READY_WITH_WARNINGS  seven-day target reached, with quality warnings to review
READY                seven-day target reached with no detected quality problems
```

Generate a self-contained local dashboard while collection is running:

```bash
.venv/bin/python -m ueba_detector dashboard \
  --metrics data/mac_metrics.jsonl \
  --events data/mac_events.jsonl \
  --output reports/status_dashboard.html
```

The dashboard embeds readiness, data quality, event distribution, largest gaps, and downsampled CPU, memory, process, network, and disk trends. It has no external scripts or network dependencies.

Train one model from both files:

```bash
.venv/bin/python -m ueba_detector train-combined \
  --metrics data/mac_metrics.jsonl \
  --events data/mac_events.jsonl \
  --features-output data/combined_train.jsonl \
  --model models/mac_combined_model.json
```

The builder groups data by host and minute. Each row contains the original 22 metrics plus 15 event features: process, authentication, session, privilege, package, collector-error, unique-process, unique-user, unique-source, and total-event activity.

Score newly built combined windows with ML and security rules:

```bash
.venv/bin/python -m ueba_detector score-combined \
  --model models/mac_combined_model.json \
  --input data/combined_train.jsonl \
  --report reports/combined_anomalies.jsonl
```

The rule layer explains clear patterns such as failed-login bursts, successful login alongside repeated failures, process-start bursts, package-change bursts, and repeated privilege elevation.

Calibrate those rules from a combined baseline instead of using only fixed defaults:

```bash
.venv/bin/python -m ueba_detector calibrate-rules \
  --input data/combined_train.jsonl \
  --output models/mac_combined_rules.json
```

Calibration keeps the defensive minimum thresholds but raises rules that are common on the host. For example, a process-start threshold that fires throughout normal macOS background activity is moved above the configured baseline quantile.

Run chronological model evaluation directly from metric and event files:

```bash
.venv/bin/python -m ueba_detector evaluate-combined \
  --metrics data/mac_metrics.jsonl \
  --events data/mac_events.jsonl \
  --features-output data/evaluation_features.jsonl \
  --model models/evaluated_combined_model.json \
  --rules-output models/evaluated_rules.json \
  --report reports/evaluation.json
```

This uses a 70/15/15 chronological split, trains only on labeled-normal windows when labels exist, calibrates the ML threshold on validation data, calibrates rules on the training baseline, and compares ML-only, rules-only, and combined detection. Labeled synthetic data also receives precision, recall, accuracy, false-positive rate, and detection-delay results. Real unlabeled host data reports anomaly rates and ML/rule disagreement without inventing ground-truth accuracy.

Run the self-contained combined test:

```bash
.venv/bin/python -m ueba_detector demo-combined \
  --output-dir examples/combined_demo
```

Current synthetic combined-demo result:

```text
train windows: 360
test windows: 120
combined features: 37
injected anomalies: 35
detected injected anomalies: 35
normal windows: 85
normal false positives: 4
false negatives: 0
recall: 1.0
```

## Run the demo

```bash
python3 -m ueba_detector demo --output-dir examples/demo_run
```

The demo creates synthetic normal samples and injects three anomaly types:

- `network_scan`
- `bulk_file_access`
- `suspicious_process_burst`

Current model-demo result:

```text
train samples: 360
test samples: 120
injected anomalies: 26
detected injected anomalies: 26
normal samples: 94
normal false positives: 3
false negatives: 0
recall: 1.0
```

## Train on collected data

The repository includes an anonymized 24-hour baseline collected from a real workstation:

```text
rows: 1439
duration: 24.007 hours
max gap: 60.336 seconds
gaps over 90 seconds: 0
```

To train from that file:

```bash
python3 -m ueba_detector train \
  --input data/baseline_24h_tcp.jsonl \
  --model models/ueba_model.json
```

Current training result:

```text
trained on 1439 samples
model saved to models/ueba_model.json
anomaly threshold: 3.176267
```

## Monitor live telemetry

```bash
python3 -m ueba_detector monitor \
  --model models/ueba_model.json \
  --report reports/live_anomalies.jsonl \
  --interval 10
```

The monitor writes a JSONL record only when it sees an anomaly. A short live check after training produced normal scores, which is expected because the model was trained on normal behavior from the same machine profile.

## Tests

```bash
python3 -m unittest discover -s tests
```

Current event and model test result:

```text
Ran 32 tests
OK
```

## Notes

- `report.txt` contains the full report in Russian and English.
- `reports/demo_anomalies.jsonl` contains example anomaly records.
- The 24-hour dataset has the host name anonymized before publishing.
- Event and state files use owner-only permissions on POSIX systems; state updates are atomic.
- Event persistence is at-least-once. Source events use deterministic IDs so a backend can deduplicate a replay after a crash.
- Windows Event Log, Linux eBPF/auditd, macOS Endpoint Security, file events, DNS, central ingestion, rule correlation, and automated response remain future production phases.
- This is an advanced prototype, not yet a replacement for a production EDR or SIEM.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Mahidul Haque.
