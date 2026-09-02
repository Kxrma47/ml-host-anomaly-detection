# Threat Model

## Scope

The protected system is the local `ueba-detector` agent, its metric and event
collectors, JSONL/state files, trained model artifacts and generated reports.
The current trust boundary is one monitored host. A remote control plane, fleet
identity service and centralized SIEM are outside the current implementation.

## Assets

- Availability and integrity of telemetry, events and collector state
- Confidentiality of host, user, process and authentication metadata
- Integrity and reproducibility of training datasets and model artifacts
- Accuracy and explainability of anomaly and rule decisions
- Availability of monitoring during individual sensor failures

## Threats and implemented controls

| Threat | Impact | Implemented control | Residual risk |
| --- | --- | --- | --- |
| Secret or credential capture | Privacy breach | Sensitive-key and secret-pattern redaction before persistence; no keylogger or form capture | An unknown secret format may evade patterns |
| Malicious command-line content | Credential exposure | Argument-aware command-line redaction and URL credential removal | Process metadata remains sensitive |
| Training-data poisoning | Raised thresholds and missed attacks | Explicitly labeled attacks are excluded; candidate windows with collector errors or non-noisy rules are excluded; provenance hashes are recorded | Unlabeled attacks can contaminate an unsupervised baseline |
| Dataset or model-input tampering | Irreproducible or manipulated model | SHA-256 and size verification, git revision, parameters and platform provenance | No signature or remote transparency log yet |
| Evasion by low-and-slow activity | False negative | Metric/event fusion, calibrated rules, chronological tests, drift detection and incident correlation | No detector can guarantee complete detection |
| Flooding and alert storms | Resource exhaustion and analyst overload | Rotation, compression, retention, stress tests, cooldown grouping and incident aggregation | No distributed backpressure or central quota |
| Collector crash or permission failure | Visibility gap | Per-collector failure isolation, error events, heartbeats and corrupt-state quarantine | OS privacy controls can still prevent collection |
| State corruption or disk failure | Duplicate/lost context | Atomic state persistence, quarantine recovery and at-least-once ordering | Disk exhaustion remains an operational risk |
| Replay or duplicate events | Inflated counts | Deterministic IDs where possible and replay deduplication | Live ingestion does not yet maintain a global replay cache |
| Schema confusion | Broken integrations | OCSF 1.8.0 envelope, numeric invariant validation and deterministic legacy migration | Full upstream schema validation remains a release step |

## Trust assumptions

- The operating system, Python runtime and installed dependencies are not already compromised.
- The service account has only the permissions needed for configured sensors and files.
- Host time is sufficiently correct for chronological windows.
- Operators protect the machine, repository, model files and report directory.
- Dataset labels used for benchmark metrics are trustworthy.

## Not in scope

- Keylogging, password capture, browser form capture or TLS interception
- Automatic blocking, process termination or account lockout
- Kernel-level anti-tamper, malware prevention or forensic memory acquisition
- Legal compliance decisions and organizational certification
- A guarantee of 100% accuracy or detection of every attack

