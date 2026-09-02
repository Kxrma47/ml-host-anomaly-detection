# Standards Readiness

This repository uses standards as engineering requirements, not as marketing
claims. `python -m ueba_detector standards-test` creates JSON and Markdown
evidence and fails the automated release gate when a mandatory threshold is not
met.

Passing the command does **not** certify this software. ISO/IEC 27001 and
ISO/IEC 42001 apply to organizational management systems. Common Criteria
(ISO/IEC 15408) certification requires a Security Target, an assurance level,
and an accredited independent evaluation.

## Automated control matrix

| Control | Project test | Default acceptance threshold |
| --- | --- | --- |
| OCSF 1.8.0 core | Numeric category, class, activity, severity, status, time, metadata and `type_uid` invariants | Every supplied event passes after deterministic migration of legacy records |
| ISO/IEC 5259 and ISO/IEC 25012 readiness | Metric/event schema, values, completeness, chronology and privacy validation | Valid datasets and quality score at least 95 |
| ISO/IEC 5259 and ISO/IEC 23894 readiness | Baseline completeness | At least 95% observed-window coverage and 10,080 clean windows |
| ISO/IEC 23894 technical risk controls | External labeled holdout | At least 90% recall and at most 10% false-positive rate for one declared method |
| ISO/IEC 25010 performance efficiency | Synthetic combined-pipeline stress test | At least 1,000 windows/second and at most 256 MiB peak Python allocation |
| ISO/IEC 25010 quality characteristics | Unit, failure recovery, privacy, integrity, replay, drift and portability tests | Complete test suite passes |

The numerical thresholds are this project's release policy. The ISO standards
provide the quality and risk-management concepts; they do not prescribe these
specific benchmark numbers.

## Event interoperability

New `SecurityEvent` records preserve the original project schema and include an
`ocsf` object targeting OCSF 1.8.0. The envelope contains the required core
identifiers and class-specific primary objects for process, authentication,
software inventory, device inventory and detection finding events. Existing
JSONL data is upgraded in memory during standards audits, so old evidence remains
usable and auditable.

The local validator checks deterministic core invariants. Before a production
interoperability claim, compile the official OCSF schema and validate exported
events with the upstream OCSF Toolkit. Local checks do not replace the official
schema compiler or toolkit.

## Evidence command

```bash
python3 -m ueba_detector standards-test \
  --readiness reports/training_readiness.json \
  --metrics-validation reports/dataset_validation.json \
  --events-validation reports/event_validation.json \
  --events data/mac_events.jsonl \
  --model-comparison reports/model_comparison.json \
  --stress reports/stress_test.json
```

Outputs:

- `reports/standards_readiness.json`: machine-readable release decision and evidence
- `reports/standards_readiness.md`: human-readable control matrix
- process exit code `0` on pass and nonzero on a failed mandatory gate

The CI `standards-gate` job recreates all evidence from deterministic fixtures
on a clean Ubuntu runner. Unit tests also run on Linux, macOS and Windows. The
security workflow adds CodeQL static analysis, Python dependency vulnerability
auditing and weekly dependency update checks.

## Controls requiring external work

| Standard | Repository contribution | Work outside this repository |
| --- | --- | --- |
| ISO/IEC 27001:2022 | Security documentation, integrity evidence, privacy-by-design controls | Define ISMS scope, risk register, policies, owners, Statement of Applicability, internal audit, management review and certification audit |
| ISO/IEC 42001:2023 | Model provenance, data quality, evaluation, drift checks and declared limitations | Define AI management system, roles, impact assessment, lifecycle governance, supplier controls, monitoring and certification audit |
| ISO/IEC 15408 Common Criteria | Security Target outline, explicit TOE boundary and testable security functions | Select EAL/assurance package, complete Security Target and use an accredited evaluation laboratory |
| Privacy law and ISO/IEC 27701 | Local redaction, no keylogging, pseudonymized adapters, file permissions | Establish lawful basis, retention/deletion rules, notices, data-subject processes, DPIA and jurisdiction-specific legal review |

## References

- [OCSF schema](https://github.com/ocsf/ocsf-schema)
- [OCSF Toolkit](https://github.com/ocsf/ocsf-toolkit)
- [ISO/IEC 27001 overview](https://www.iso.org/standard/27001)
- [ISO/IEC 42001 overview](https://www.iso.org/standard/81230.html)
- [Common Criteria portal](https://www.commoncriteriaportal.org/)
