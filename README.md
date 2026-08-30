# ML Host Anomaly Detection

This project is a small UEBA-style prototype for detecting unusual activity on a workstation.

It collects local host telemetry, trains an autoencoder on normal behavior, and then uses the saved model to monitor new samples. The goal is not to replace an EDR or SIEM product. The goal is to show the full pipeline: data collection, normalization, model training, threshold selection, monitoring, and anomaly reporting.

## What is collected

The collector records aggregated host metrics:

- CPU, memory, swap, and load average
- process, user process, and thread counts
- network traffic rates
- TCP connection counters
- number of unique remote ports
- disk read and write rates

These signals are simple, but they are useful for a prototype because they change during common suspicious patterns: process bursts, network scanning, heavy file access, and abnormal resource usage.

## Repository layout

```text
ueba_detector/                 source code
tests/                         unit tests
data/baseline_24h_tcp.jsonl    anonymized 24-hour baseline dataset
models/ueba_model.json         trained model
reports/                       monitoring and anomaly report examples
examples/demo_run/             synthetic demo data and outputs
report.txt                     full bilingual report
```

## Install

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

## Run the demo

```bash
python3 -m ueba_detector demo --output-dir examples/demo_run
```

The demo creates synthetic normal samples and injects three anomaly types:

- `network_scan`
- `bulk_file_access`
- `suspicious_process_burst`

Current demo result:

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

For a clean-room verification workflow, expected artifacts, and metric checks,
see [Reproducing the demo](docs/reproducibility.md).

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

Current result:

```text
Ran 8 tests
OK
```

## Notes

- `report.txt` contains the full report in Russian and English.
- `reports/demo_anomalies.jsonl` contains example anomaly records.
- The 24-hour dataset has the host name anonymized before publishing.
- This is a prototype intended for a test assignment, not a production security system.
