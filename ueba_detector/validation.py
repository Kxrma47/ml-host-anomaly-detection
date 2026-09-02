from __future__ import annotations

import gzip
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .combined import parse_timestamp
from .features import FEATURE_NAMES
from .ocsf import validate_ocsf_core
from .redaction import REDACTED, is_sensitive_key, redact_text
from .storage import jsonl_dataset_paths


EVENT_REQUIRED_FIELDS = (
    "event_id",
    "timestamp",
    "host",
    "event_type",
    "source",
)
METRIC_PERCENT_FEATURES = {"cpu_percent", "memory_percent", "swap_percent"}


def find_secret_exposures(value: Any, path: str = "$") -> list[dict[str, str]]:
    """Return locations that would be changed by the persistence redactor."""
    findings: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            item_path = f"{path}.{key}"
            if is_sensitive_key(key) and item not in (None, "", REDACTED):
                findings.append({"path": item_path, "reason": "unredacted sensitive field"})
            else:
                findings.extend(find_secret_exposures(item, item_path))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            findings.extend(find_secret_exposures(item, f"{path}[{index}]"))
    elif isinstance(value, str) and value != REDACTED and redact_text(value) != value:
        findings.append({"path": path, "reason": "secret-like text"})
    return findings


def _record_issue(
    counts: Counter[str],
    examples: dict[str, list[dict[str, Any]]],
    code: str,
    index: int,
    detail: str,
) -> None:
    counts[code] += 1
    if len(examples[code]) < 5:
        examples[code].append({"row": index, "detail": detail})


def validate_records(rows: list[dict[str, Any]], *, kind: str = "auto") -> dict[str, Any]:
    if kind not in {"auto", "metrics", "events", "combined"}:
        raise ValueError("kind must be auto, metrics, events, or combined")
    if kind == "auto":
        first = rows[0] if rows else {}
        kind = "events" if "event_type" in first else "metrics"

    errors: Counter[str] = Counter()
    warnings: Counter[str] = Counter()
    examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    identities: set[str] = set()
    last_epoch_by_host: dict[str, float] = {}

    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            _record_issue(errors, examples, "non_object", index, "record is not an object")
            continue

        raw_timestamp = row.get("timestamp")
        try:
            epoch = parse_timestamp(raw_timestamp)
        except (TypeError, ValueError, OverflowError):
            _record_issue(errors, examples, "invalid_timestamp", index, str(raw_timestamp))
            epoch = None
        host = str(row.get("host") or "unknown")
        if epoch is not None:
            previous = last_epoch_by_host.get(host)
            if previous is not None and epoch < previous:
                _record_issue(
                    warnings,
                    examples,
                    "out_of_order",
                    index,
                    f"{raw_timestamp} is before the preceding {host} record",
                )
            last_epoch_by_host[host] = max(previous or epoch, epoch)

        if kind == "events":
            for field in EVENT_REQUIRED_FIELDS:
                if row.get(field) in (None, ""):
                    _record_issue(errors, examples, f"missing_{field}", index, field)
            event_id = str(row.get("event_id") or "")
            if event_id:
                if event_id in identities:
                    _record_issue(warnings, examples, "duplicate_identity", index, event_id)
                identities.add(event_id)
            ocsf = row.get("ocsf")
            if ocsf is not None:
                for detail in validate_ocsf_core(ocsf):
                    _record_issue(errors, examples, "invalid_ocsf_core", index, detail)
        else:
            identity = f"{host}\x1f{raw_timestamp}"
            if identity in identities:
                _record_issue(warnings, examples, "duplicate_identity", index, identity)
            identities.add(identity)
            for feature in FEATURE_NAMES:
                if feature not in row or row.get(feature) in (None, ""):
                    _record_issue(errors, examples, "missing_feature", index, feature)
                    continue
                try:
                    numeric = float(row[feature])
                except (TypeError, ValueError):
                    _record_issue(errors, examples, "non_numeric_feature", index, feature)
                    continue
                if not math.isfinite(numeric):
                    _record_issue(errors, examples, "non_finite_feature", index, feature)
                elif numeric < 0:
                    _record_issue(warnings, examples, "negative_feature", index, feature)
                elif feature in METRIC_PERCENT_FEATURES and numeric > 100:
                    _record_issue(warnings, examples, "percent_out_of_range", index, feature)

        exposures = find_secret_exposures(row)
        for exposure in exposures:
            _record_issue(
                errors,
                examples,
                "secret_exposure",
                index,
                f"{exposure['path']}: {exposure['reason']}",
            )

    error_total = sum(errors.values())
    warning_total = sum(warnings.values())
    denominator = max(1, len(rows))
    penalty = min(1.0, (error_total / denominator) * 5.0 + (warning_total / denominator) * 0.25)
    score = 100.0 * (1.0 - penalty)
    return {
        "kind": kind,
        "records": len(rows),
        "valid": error_total == 0,
        "quality_score": score,
        "errors": dict(sorted(errors.items())),
        "warnings": dict(sorted(warnings.items())),
        "examples": dict(sorted(examples.items())),
    }


def validate_dataset(path: str | Path, *, kind: str = "auto") -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    diagnostics: Counter[str] = Counter()
    segments = jsonl_dataset_paths(path)
    if not segments:
        raise FileNotFoundError(path)
    for segment in segments:
        opener = gzip.open if segment.suffix == ".gz" else Path.open
        with opener(segment, "rt", encoding="utf-8") as stream:
            lines = stream.readlines()
        for index, line in enumerate(lines):
            if not line.strip():
                diagnostics["blank_rows"] += 1
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                if index == len(lines) - 1 and not line.endswith(("\n", "\r")):
                    diagnostics["trailing_partial_rows"] += 1
                else:
                    diagnostics["malformed_rows"] += 1
                continue
            if not isinstance(value, dict):
                diagnostics["non_object_rows"] += 1
                continue
            rows.append(value)
    report = validate_records(rows, kind=kind)
    report["segments"] = len(segments)
    report["file_diagnostics"] = dict(sorted(diagnostics.items()))
    structural_errors = diagnostics["malformed_rows"] + diagnostics["non_object_rows"]
    if structural_errors:
        report["valid"] = False
        report["errors"]["structural_file_rows"] = structural_errors
        structural_penalty = min(100.0, structural_errors / max(1, len(rows)) * 500.0)
        report["quality_score"] = max(
            0.0,
            float(report["quality_score"]) - structural_penalty,
        )
    if diagnostics["trailing_partial_rows"]:
        report["warnings"]["trailing_partial_rows"] = diagnostics["trailing_partial_rows"]
        report["quality_score"] = max(
            0.0,
            float(report["quality_score"])
            - min(25.0, diagnostics["trailing_partial_rows"] / max(1, len(rows)) * 25.0),
        )
    return report
