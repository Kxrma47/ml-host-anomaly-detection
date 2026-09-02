from __future__ import annotations

import gzip
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ocsf import OCSF_VERSION, upgrade_event_record, validate_ocsf_core
from .storage import jsonl_dataset_paths


PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT_RUN"
EXTERNAL_REQUIRED = "EXTERNAL_REQUIRED"


def _load_json(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    target = Path(path)
    if not target.exists():
        return None
    value = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {target}")
    return value


def audit_ocsf_events(path: str | Path) -> dict[str, Any]:
    total = 0
    native = 0
    migrated = 0
    invalid = 0
    issue_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()
    for segment in jsonl_dataset_paths(path):
        opener = gzip.open if segment.suffix == ".gz" else Path.open
        with opener(segment, "rt", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    invalid += 1
                    issue_counts["malformed JSON"] += 1
                    continue
                if not isinstance(row, dict):
                    invalid += 1
                    issue_counts["record is not an object"] += 1
                    continue
                total += 1
                if isinstance(row.get("ocsf"), dict):
                    native += 1
                    event = row["ocsf"]
                else:
                    migrated += 1
                    event = upgrade_event_record(row)["ocsf"]
                issues = validate_ocsf_core(event)
                if issues:
                    invalid += 1
                    issue_counts.update(issues)
                class_counts[str(event.get("class_name") or "unknown")] += 1
    return {
        "schema_version": OCSF_VERSION,
        "records": total,
        "native_envelopes": native,
        "legacy_records_migrated": migrated,
        "invalid_records": invalid,
        "valid": total > 0 and invalid == 0,
        "classes": dict(sorted(class_counts.items())),
        "issues": dict(issue_counts.most_common()),
    }


def run_unit_tests(test_directory: str | Path = "tests") -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        str(test_directory),
        "-p",
        "test_*.py",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    output = "\n".join(value for value in (completed.stdout, completed.stderr) if value).strip()
    summary = output.splitlines()[-1] if output else "no test output"
    return {
        "command": command,
        "passed": completed.returncode == 0,
        "return_code": completed.returncode,
        "summary": summary,
    }


def _control(
    control_id: str,
    title: str,
    status: str,
    standards: list[str],
    evidence: dict[str, Any] | str,
    *,
    mandatory: bool = True,
) -> dict[str, Any]:
    return {
        "id": control_id,
        "title": title,
        "status": status,
        "mandatory_release_gate": mandatory,
        "standards_mapping": standards,
        "evidence": evidence,
    }


def build_standards_report(
    *,
    readiness: dict[str, Any] | None,
    metrics_validation: dict[str, Any] | None,
    events_validation: dict[str, Any] | None,
    ocsf_audit: dict[str, Any] | None,
    model_comparison: dict[str, Any] | None,
    stress: dict[str, Any] | None,
    unit_tests: dict[str, Any] | None,
    minimum_coverage: float = 0.95,
    minimum_clean_windows: int = 10_080,
    minimum_recall: float = 0.90,
    maximum_false_positive_rate: float = 0.10,
    minimum_windows_per_second: float = 1_000.0,
    maximum_peak_memory_mib: float = 256.0,
) -> dict[str, Any]:
    if not 0.0 <= minimum_coverage <= 1.0:
        raise ValueError("minimum_coverage must be between 0 and 1")
    controls: list[dict[str, Any]] = []

    if ocsf_audit is None:
        controls.append(
            _control(
                "FMT-OCSF-001",
                "OCSF core event invariants",
                NOT_RUN,
                ["OCSF 1.8.0"],
                "No event stream was supplied.",
            )
        )
    else:
        controls.append(
            _control(
                "FMT-OCSF-001",
                "OCSF core event invariants",
                PASS if ocsf_audit.get("valid") else FAIL,
                ["OCSF 1.8.0"],
                ocsf_audit,
            )
        )

    for control_id, title, validation in (
        ("DQ-ISO5259-001", "Metric schema and value quality", metrics_validation),
        ("DQ-ISO5259-002", "Event schema and chronology quality", events_validation),
    ):
        if validation is None:
            status = NOT_RUN
            evidence: dict[str, Any] | str = "No validation report was supplied."
        else:
            quality = float(validation.get("quality_score", 0.0) or 0.0)
            status = PASS if validation.get("valid") and quality >= 95.0 else FAIL
            evidence = {
                "valid": bool(validation.get("valid")),
                "quality_score": quality,
                "records": int(validation.get("records", 0) or 0),
                "errors": validation.get("errors", {}),
                "warnings": validation.get("warnings", {}),
            }
        controls.append(
            _control(
                control_id,
                title,
                status,
                ["ISO/IEC 5259 readiness", "ISO/IEC 25012 data quality model"],
                evidence,
            )
        )

    if readiness is None:
        coverage_status = NOT_RUN
        coverage_evidence: dict[str, Any] | str = "No training-readiness report was supplied."
    else:
        coverage = readiness.get("coverage", {})
        combined = readiness.get("combined", {})
        ratio = float(coverage.get("coverage_ratio", 0.0) or 0.0)
        clean = int(combined.get("clean_windows", 0) or 0)
        coverage_status = PASS if ratio >= minimum_coverage and clean >= minimum_clean_windows else FAIL
        coverage_evidence = {
            "coverage_ratio": ratio,
            "minimum_coverage": minimum_coverage,
            "clean_windows": clean,
            "minimum_clean_windows": minimum_clean_windows,
            "missing_windows": int(coverage.get("missing_windows", 0) or 0),
            "gap_count": int(coverage.get("gap_count", 0) or 0),
        }
    controls.append(
        _control(
            "DQ-ISO5259-003",
            "Training coverage and completeness",
            coverage_status,
            ["ISO/IEC 5259 readiness", "ISO/IEC 23894 technical risk controls"],
            coverage_evidence,
        )
    )

    selected_model: dict[str, Any] | None = None
    selected_name: str | None = None
    if model_comparison:
        for name, metrics in model_comparison.get("methods", {}).items():
            if not isinstance(metrics, dict) or metrics.get("recall") is None:
                continue
            recall = float(metrics.get("recall", 0.0) or 0.0)
            fpr = float(metrics.get("false_positive_rate", 1.0) or 0.0)
            if recall >= minimum_recall and fpr <= maximum_false_positive_rate:
                selected_name = str(name)
                selected_model = metrics
                break
    if model_comparison is None:
        model_status = NOT_RUN
        model_evidence: dict[str, Any] | str = "No labeled holdout comparison was supplied."
    elif selected_model is None:
        model_status = FAIL
        model_evidence = {
            "minimum_recall": minimum_recall,
            "maximum_false_positive_rate": maximum_false_positive_rate,
            "methods": model_comparison.get("methods", {}),
        }
    else:
        model_status = PASS
        model_evidence = {
            "selected_method": selected_name,
            "recall": selected_model.get("recall"),
            "false_positive_rate": selected_model.get("false_positive_rate"),
            "precision": selected_model.get("precision"),
            "split": model_comparison.get("split", {}),
            "criteria": {
                "minimum_recall": minimum_recall,
                "maximum_false_positive_rate": maximum_false_positive_rate,
            },
        }
    controls.append(
        _control(
            "ML-ISO23894-001",
            "Labeled holdout detection quality",
            model_status,
            ["ISO/IEC 23894 technical risk controls", "ISO/IEC 25010 effectiveness evidence"],
            model_evidence,
        )
    )

    if stress is None:
        stress_status = NOT_RUN
        stress_evidence: dict[str, Any] | str = "No stress-test report was supplied."
    else:
        throughput = float(stress.get("windows_per_second", 0.0) or 0.0)
        memory_mib = float(stress.get("peak_memory_bytes", 0.0) or 0.0) / 1024 / 1024
        stress_status = (
            PASS
            if throughput >= minimum_windows_per_second and memory_mib <= maximum_peak_memory_mib
            else FAIL
        )
        stress_evidence = {
            "windows": int(stress.get("combined_rows", 0) or 0),
            "windows_per_second": throughput,
            "minimum_windows_per_second": minimum_windows_per_second,
            "peak_memory_mib": memory_mib,
            "maximum_peak_memory_mib": maximum_peak_memory_mib,
        }
    controls.append(
        _control(
            "QUAL-ISO25010-001",
            "Performance efficiency and bounded memory",
            stress_status,
            ["ISO/IEC 25010 performance efficiency"],
            stress_evidence,
        )
    )

    if unit_tests is None:
        test_status = NOT_RUN
        test_evidence: dict[str, Any] | str = "Unit tests were not executed by this audit."
    else:
        test_status = PASS if unit_tests.get("passed") else FAIL
        test_evidence = unit_tests
    controls.append(
        _control(
            "QUAL-ISO25010-002",
            "Automated functional and resilience regression suite",
            test_status,
            ["ISO/IEC 25010 reliability, security, maintainability, portability"],
            test_evidence,
        )
    )

    external_controls = [
        _control(
            "ORG-ISO27001-001",
            "Information security management system certification",
            EXTERNAL_REQUIRED,
            ["ISO/IEC 27001:2022"],
            "Organization-wide ISMS, risk treatment, audit, and certification body are required.",
            mandatory=False,
        ),
        _control(
            "ORG-ISO42001-001",
            "AI management system certification",
            EXTERNAL_REQUIRED,
            ["ISO/IEC 42001:2023"],
            "Organization-wide AI governance, impact assessment, monitoring, and external audit are required.",
            mandatory=False,
        ),
        _control(
            "EVAL-ISO15408-001",
            "Common Criteria product evaluation",
            EXTERNAL_REQUIRED,
            ["ISO/IEC 15408 Common Criteria"],
            "A Security Target, selected assurance level, and accredited evaluation laboratory are required.",
            mandatory=False,
        ),
    ]
    controls.extend(external_controls)

    mandatory = [item for item in controls if item["mandatory_release_gate"]]
    counts = Counter(str(item["status"]) for item in controls)
    automated_ready = bool(mandatory) and all(item["status"] == PASS for item in mandatory)
    return {
        "report_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "automated technical standards-readiness controls",
        "automated_release_ready": automated_ready,
        "certification_status": "NOT_CERTIFIED",
        "certification_note": (
            "Passing this report is technical evidence only. It is not ISO certification, "
            "Common Criteria certification, legal approval, or a guarantee of 100% detection accuracy."
        ),
        "summary": dict(sorted(counts.items())),
        "controls": controls,
    }


def run_standards_audit(
    *,
    readiness_path: str | Path | None,
    metrics_validation_path: str | Path | None,
    events_validation_path: str | Path | None,
    events_path: str | Path | None,
    model_comparison_path: str | Path | None,
    stress_path: str | Path | None,
    run_tests: bool,
    test_directory: str | Path = "tests",
    **thresholds: Any,
) -> dict[str, Any]:
    return build_standards_report(
        readiness=_load_json(readiness_path),
        metrics_validation=_load_json(metrics_validation_path),
        events_validation=_load_json(events_validation_path),
        ocsf_audit=audit_ocsf_events(events_path) if events_path else None,
        model_comparison=_load_json(model_comparison_path),
        stress=_load_json(stress_path),
        unit_tests=run_unit_tests(test_directory) if run_tests else None,
        **thresholds,
    )


def standards_markdown(report: dict[str, Any]) -> str:
    state = "PASS" if report.get("automated_release_ready") else "FAIL"
    lines = [
        "# Standards Readiness Report",
        "",
        f"Automated release gate: **{state}**",
        "",
        f"Certification status: **{report.get('certification_status')}**",
        "",
        str(report.get("certification_note")),
        "",
        "| Control | Status | Standards mapping | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for control in report.get("controls", []):
        evidence = control.get("evidence")
        if isinstance(evidence, dict):
            evidence_text = ", ".join(f"{key}={value}" for key, value in list(evidence.items())[:4])
        else:
            evidence_text = str(evidence)
        evidence_text = evidence_text.replace("|", "\\|").replace("\n", " ")
        mappings = ", ".join(control.get("standards_mapping", []))
        lines.append(
            f"| {control.get('id')}: {control.get('title')} | {control.get('status')} | "
            f"{mappings} | {evidence_text} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "`PASS` means the repository's explicit, machine-testable threshold passed. "
            "`EXTERNAL_REQUIRED` means an organizational or accredited assessment is outside this codebase.",
            "",
        ]
    )
    return "\n".join(lines)


def write_standards_reports(
    json_path: str | Path,
    markdown_path: str | Path,
    report: dict[str, Any],
) -> None:
    json_target = Path(json_path)
    markdown_target = Path(markdown_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_target.write_text(standards_markdown(report), encoding="utf-8")
