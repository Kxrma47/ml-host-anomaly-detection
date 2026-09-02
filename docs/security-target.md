# Common Criteria Security Target Outline

This is a readiness outline, not an evaluated or certified Security Target.

## TOE reference

- **Name:** UEBA Detector
- **Version:** 0.6.0
- **Type:** Local host telemetry, security-event normalization and anomaly-detection application
- **Boundary:** Python package, configured collectors, local persistence, model training/scoring and report commands

The operating system, Python interpreter, `psutil`, authentication log sources,
terminal supervisor, hardware and any remote SIEM are in the operational
environment, not the Target of Evaluation (TOE).

## TOE security functions

1. **Data minimization and redaction:** removes recognized credentials, tokens,
   cookies, authorization values and URL user information before event storage.
2. **Security-event normalization:** produces stable legacy records plus OCSF
   1.8.0 core envelopes and validates identifier invariants.
3. **Failure isolation:** prevents one sensor exception from stopping other
   collectors and emits a redacted error event.
4. **State protection and recovery:** uses owner-only file modes where supported,
   atomic persistence and quarantine of corrupt state.
5. **Detection:** combines aggregated host metrics, normalized event counts,
   calibrated rules and an autoencoder score.
6. **Audit and evidence:** validates datasets, records provenance hashes, detects
   drift, supports deterministic replay and generates standards-readiness reports.

## Security problem definition

Threats include unauthorized disclosure through telemetry, modification of
training evidence, baseline poisoning, sensor failure, event replay, malformed
input and resource exhaustion. Organizational threats, privileged OS compromise
and physical attacks are handled by the operational environment.

## Security objectives

- Persist no known plaintext credential fields.
- Detect malformed, incomplete, duplicate and non-finite inputs before training.
- Preserve enough provenance to identify changed datasets.
- Continue collecting from healthy sensors when one sensor fails.
- Keep machine-readable evidence for quality, performance and detection gates.
- Require explicit external evaluation before making a certification claim.

## Assurance evidence available

- Source code and deterministic unit tests
- Linux, macOS and Windows CI runs
- Synthetic benchmark and stress-test outputs
- Dataset validation, readiness, drift and model-comparison reports
- OCSF core conformance report and event migration path
- Threat model, standards mapping and reproducibility instructions

## Evaluation gaps

Before a Common Criteria evaluation, the sponsor must select a Protection
Profile or assurance package, complete functional and assurance requirements,
define the evaluated configuration, provide administrator/user guidance, perform
vulnerability analysis and engage an accredited laboratory. This repository
does not assign itself an Evaluation Assurance Level.

