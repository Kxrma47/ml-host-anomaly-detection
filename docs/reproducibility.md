# Reproducing the demo

The synthetic demo is deterministic: it uses seed `7` for training samples,
seed `8` for test samples, and seed `7` for autoencoder initialization. This
makes it possible to verify the full pipeline without collecting host data.

## Clean-room run

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -p 'test_*.py'

demo_dir="$(mktemp -d)"
python3 -m ueba_detector demo --output-dir "$demo_dir"
python3 -m json.tool "$demo_dir/demo_metrics.json"
```

On Windows PowerShell, replace the activation and temporary-directory commands:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py"

$demoDir = Join-Path $env:TEMP "ueba-demo"
python -m ueba_detector demo --output-dir $demoDir
python -m json.tool (Join-Path $demoDir "demo_metrics.json")
```

## Expected verification signals

With the default arguments, the run should report:

- 360 training samples and 120 test samples
- 26 injected anomalies detected out of 26
- 3 false positives among 94 normal samples
- zero false negatives and recall of `1.0`

The generated `demo_metrics.json` is the machine-readable source for these
figures. `demo_summary.txt` contains the human-readable anomaly report.

## Generated artifacts

| File | Purpose |
| --- | --- |
| `demo_train.jsonl` | Synthetic normal telemetry used for training |
| `demo_test.jsonl` | Synthetic evaluation telemetry with injected scenarios |
| `demo_model.json` | Fitted autoencoder parameters and threshold |
| `demo_scores.jsonl` | Score, severity, and top features for every test sample |
| `demo_anomalies.jsonl` | Detected anomaly events only |
| `demo_metrics.json` | Aggregate evaluation metrics |
| `demo_summary.txt` | Human-readable anomaly report |

## Changing the experiment

The demo exposes its main experimental controls:

```bash
python3 -m ueba_detector demo \
  --output-dir /tmp/ueba-demo-seed-21 \
  --seed 21 \
  --train-samples 500 \
  --test-samples 200 \
  --epochs 240 \
  --threshold-quantile 0.999
```

Results produced with different seeds or sample counts should not be compared
directly with the repository's default benchmark. Record the full command and
retain `demo_metrics.json` when reporting a modified experiment.
