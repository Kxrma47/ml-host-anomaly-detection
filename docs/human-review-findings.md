# What the first human review found

The first real-host review used a private seven-day recording containing 10,111
one-minute windows. The original model and calibrated rules produced 75 alerts.
Every alert was checked against the surrounding process, session, package,
resource, and network context instead of being labeled from severity alone.

Seventy alerts were explained by ordinary activity. The recurring causes were
macOS service restarts and indexing, software updates, local terminal-session
changes, collector failures, browser downloads, Python multiprocessing, compiler
work, package installation, and automated web tests.

Five windows remained suspicious because remote-access tooling was installed or
started. Local records showed a conventional graphical installer workflow, but
the telemetry could not establish that the owner authorized the software or the
corresponding remote session. Those windows were not promoted to confirmed
attacks, and they were excluded from reviewed baseline training.

The project's review metric counts both suspicious and confirmed-attack labels
as positive. On this recording, the original alert precision was therefore 5 of
75, or 6.7%. This is a useful measurement of alert quality, not an accuracy or
recall claim. Alert review cannot reveal attacks that the detector failed to
surface, and this recording contains no confirmed attack examples.

## Candidate comparison

The reviewed model trained on 10,106 windows after the five unresolved windows
were removed. Three configurations were rescored on the same history:

| Configuration | Alerts | Reviewed benign | Reviewed suspicious | Reviewed precision |
| --- | ---: | ---: | ---: | ---: |
| Original model and rules | 75 | 70 | 5 | 6.7% |
| Reviewed model and recalibrated rules | 68 | 63 | 5 | 7.4% |
| Reviewed model and original rules | 64 | 59 | 5 | 7.8% |

Recalibration lowered the process-start threshold from 83 to 81 and introduced
four new benign alerts. The better retrospective configuration is the reviewed
model with the original rules: it removed 11 benign alerts, introduced no new
alerts, and retained all five suspicious windows.

That candidate remains shadow-only. Training and evaluation reused the same
recording, so the apparent improvement may not generalize. Promotion requires a
separate labeled monitoring period, review of every disagreement between the two
models, and attack simulations or an external labeled dataset that can measure
recall.

The repository publishes only these aggregate results. Raw host events, alert
timestamps, process paths, command lines, analyst notes, review files, and
host-specific model artifacts are intentionally excluded.
