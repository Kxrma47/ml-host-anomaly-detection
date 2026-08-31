from __future__ import annotations

import json
import gzip
import math
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .combined import build_combined_samples, evaluate_security_rules, parse_timestamp
from .features import FEATURE_NAMES
from .storage import jsonl_dataset_paths


def _utc_timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _read_jsonl_snapshot(path: str | Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    diagnostics = {
        "snapshot_bytes": 0,
        "segments": 0,
        "total_lines": 0,
        "blank_lines": 0,
        "malformed_rows": 0,
        "non_object_rows": 0,
        "trailing_partial_rows": 0,
        "valid_object_rows": 0,
    }
    segments = jsonl_dataset_paths(path)
    if not segments:
        raise FileNotFoundError(path)
    diagnostics["segments"] = len(segments)
    for target in segments:
        snapshot_bytes = target.stat().st_size
        diagnostics["snapshot_bytes"] += snapshot_bytes
        if target.suffix == ".gz":
            with gzip.open(target, "rb") as stream:
                payload = stream.read()
        else:
            with target.open("rb") as stream:
                payload = stream.read(snapshot_bytes)

        lines = payload.splitlines(keepends=True)
        diagnostics["total_lines"] += len(lines)
        for index, raw_line in enumerate(lines):
            is_trailing_line = index == len(lines) - 1 and not raw_line.endswith((b"\n", b"\r"))
            stripped = raw_line.strip()
            if not stripped:
                diagnostics["blank_lines"] += 1
                continue
            try:
                value = json.loads(stripped.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                if is_trailing_line:
                    diagnostics["trailing_partial_rows"] += 1
                else:
                    diagnostics["malformed_rows"] += 1
                continue
            if not isinstance(value, dict):
                diagnostics["non_object_rows"] += 1
                continue
            rows.append(value)
            diagnostics["valid_object_rows"] += 1
    return rows, diagnostics


def _analyze_timestamps(
    rows: list[dict[str, Any]],
    *,
    identity_fields: tuple[str, ...],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    usable: list[dict[str, Any]] = []
    epochs: list[float] = []
    identities: set[tuple[str, ...]] = set()
    duplicate_rows = 0
    missing_timestamps = 0
    invalid_timestamps = 0
    hosts: Counter[str] = Counter()

    for row in rows:
        raw_timestamp = row.get("timestamp")
        if raw_timestamp is None or raw_timestamp == "":
            missing_timestamps += 1
            continue
        try:
            epoch = parse_timestamp(raw_timestamp)
        except (TypeError, ValueError, OverflowError):
            invalid_timestamps += 1
            continue
        identity = tuple(str(row.get(field) or "") for field in identity_fields)
        if any(identity):
            if identity in identities:
                duplicate_rows += 1
            else:
                identities.add(identity)
        host = str(row.get("host") or "unknown")
        hosts[host] += 1
        epochs.append(epoch)
        usable.append(row)

    return usable, {
        "usable_rows": len(usable),
        "missing_timestamp_rows": missing_timestamps,
        "invalid_timestamp_rows": invalid_timestamps,
        "duplicate_rows": duplicate_rows,
        "hosts": dict(sorted(hosts.items())),
        "first_timestamp": _utc_timestamp(min(epochs)) if epochs else None,
        "last_timestamp": _utc_timestamp(max(epochs)) if epochs else None,
    }


def _analyze_metric_features(rows: list[dict[str, Any]]) -> dict[str, Any]:
    missing: Counter[str] = Counter()
    non_numeric: Counter[str] = Counter()
    non_finite: Counter[str] = Counter()
    issue_rows = 0

    for row in rows:
        row_has_issue = False
        for feature in FEATURE_NAMES:
            value = row.get(feature)
            if feature not in row or value is None or value == "":
                missing[feature] += 1
                row_has_issue = True
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                non_numeric[feature] += 1
                row_has_issue = True
                continue
            if not math.isfinite(numeric):
                non_finite[feature] += 1
                row_has_issue = True
        if row_has_issue:
            issue_rows += 1

    return {
        "required_features": len(FEATURE_NAMES),
        "rows_with_feature_issues": issue_rows,
        "missing_values": dict(sorted(missing.items())),
        "non_numeric_values": dict(sorted(non_numeric.items())),
        "non_finite_values": dict(sorted(non_finite.items())),
    }


def _coverage(rows: list[dict[str, Any]], window_seconds: int) -> dict[str, Any]:
    windows_by_host: dict[str, set[int]] = defaultdict(set)
    for row in rows:
        epoch = int(parse_timestamp(row["timestamp"]))
        start = epoch - (epoch % window_seconds)
        windows_by_host[str(row.get("host") or "unknown")].add(start)

    gaps: list[dict[str, Any]] = []
    host_summaries: dict[str, dict[str, Any]] = {}
    observed_total = 0
    expected_total = 0
    for host, window_set in sorted(windows_by_host.items()):
        ordered = sorted(window_set)
        observed = len(ordered)
        expected = ((ordered[-1] - ordered[0]) // window_seconds) + 1 if ordered else 0
        observed_total += observed
        expected_total += expected
        for previous, current in zip(ordered, ordered[1:]):
            delta = current - previous
            if delta <= window_seconds:
                continue
            missing = max(0, (delta // window_seconds) - 1)
            gaps.append(
                {
                    "host": host,
                    "after": _utc_timestamp(previous),
                    "before": _utc_timestamp(current),
                    "gap_seconds": delta,
                    "missing_windows": missing,
                }
            )
        host_summaries[host] = {
            "observed_windows": observed,
            "expected_windows": expected,
            "missing_windows": max(0, expected - observed),
            "first_window": _utc_timestamp(ordered[0]) if ordered else None,
            "last_window": _utc_timestamp(ordered[-1]) if ordered else None,
        }

    sorted_gaps = sorted(gaps, key=lambda item: int(item["gap_seconds"]), reverse=True)
    return {
        "window_seconds": window_seconds,
        "observed_windows": observed_total,
        "expected_windows": expected_total,
        "missing_windows": max(0, expected_total - observed_total),
        "coverage_ratio": observed_total / expected_total if expected_total else 0.0,
        "duplicate_window_samples": max(0, len(rows) - observed_total),
        "gap_count": len(gaps),
        "max_gap_seconds": int(sorted_gaps[0]["gap_seconds"]) if sorted_gaps else 0,
        "largest_gaps": sorted_gaps[:100],
        "hosts": host_summaries,
    }


def _split_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: (parse_timestamp(row["timestamp"]), str(row["host"])))
    total = len(ordered)
    if total >= 3:
        validation_count = max(1, int(total * 0.15))
        test_count = max(1, int(total * 0.15))
        train_count = total - validation_count - test_count
    else:
        train_count = total
        validation_count = 0
        test_count = 0
    groups = {
        "train": ordered[:train_count],
        "validation": ordered[train_count : train_count + validation_count],
        "test": ordered[train_count + validation_count :],
    }

    summary: dict[str, Any] = {"strategy": "chronological", "ratios": [0.70, 0.15, 0.15]}
    for name, group in groups.items():
        summary[name] = {
            "windows": len(group),
            "start": group[0]["timestamp"] if group else None,
            "end": group[-1]["timestamp"] if group else None,
        }
    return summary


def audit_training_data(
    metrics_path: str | Path,
    events_path: str | Path,
    *,
    window_seconds: int = 60,
    minimum_windows: int = 1_440,
    recommended_windows: int = 10_080,
    max_rule_exclusion_ratio: float = 0.05,
) -> dict[str, Any]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if minimum_windows <= 0:
        raise ValueError("minimum_windows must be positive")
    if recommended_windows < minimum_windows:
        raise ValueError("recommended_windows must be at least minimum_windows")
    if not 0.0 <= max_rule_exclusion_ratio <= 1.0:
        raise ValueError("max_rule_exclusion_ratio must be between 0 and 1")

    metric_rows, metric_jsonl = _read_jsonl_snapshot(metrics_path)
    event_rows, event_jsonl = _read_jsonl_snapshot(events_path)
    usable_metrics, metric_timestamps = _analyze_timestamps(
        metric_rows,
        identity_fields=("host", "timestamp"),
    )
    usable_events, event_timestamps = _analyze_timestamps(
        event_rows,
        identity_fields=("event_id",),
    )
    metric_features = _analyze_metric_features(usable_metrics)
    coverage = _coverage(usable_metrics, window_seconds)

    event_types = Counter(str(row.get("event_type") or "missing") for row in usable_events)
    combined = build_combined_samples(
        usable_metrics,
        usable_events,
        window_seconds=window_seconds,
    )
    evaluated_windows: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    rule_counts: Counter[str] = Counter()
    flagged_windows = 0
    for row in combined:
        rules = evaluate_security_rules(row)
        evaluated_windows.append((row, rules))
        for rule in rules:
            rule_counts[str(rule["rule_id"])] += 1
        if rules:
            flagged_windows += 1

    noisy_rules = {
        rule_id: {
            "windows": count,
            "ratio": count / len(combined) if combined else 0.0,
        }
        for rule_id, count in sorted(rule_counts.items())
        if combined and count / len(combined) > max_rule_exclusion_ratio
    }
    training_windows: list[dict[str, Any]] = []
    excluded_windows = 0
    for row, rules in evaluated_windows:
        has_collector_error = int(row.get("event_collector_error_count", 0) or 0) > 0
        has_non_noisy_rule = any(str(rule["rule_id"]) not in noisy_rules for rule in rules)
        if has_collector_error or has_non_noisy_rule:
            excluded_windows += 1
        else:
            training_windows.append(row)

    warnings: list[str] = []
    blockers: list[str] = []
    malformed = metric_jsonl["malformed_rows"] + event_jsonl["malformed_rows"]
    non_objects = metric_jsonl["non_object_rows"] + event_jsonl["non_object_rows"]
    if metric_features["rows_with_feature_issues"]:
        blockers.append("metric rows contain missing, non-numeric, or non-finite required features")
    if malformed or non_objects:
        blockers.append("one or more complete JSONL rows are malformed or are not objects")
    if coverage["coverage_ratio"] < 0.95:
        warnings.append("metric coverage is below 95% across the observed time span")
    if coverage["max_gap_seconds"] > window_seconds * 5:
        warnings.append("the dataset contains a metric gap longer than five windows")
    if metric_timestamps["duplicate_rows"]:
        warnings.append("duplicate metric timestamps were found")
    if event_timestamps["duplicate_rows"]:
        warnings.append("duplicate event identities were found")
    collector_errors = event_types.get("collector_error", 0)
    if collector_errors:
        warnings.append("collector-error events were recorded")
    for rule_id, details in noisy_rules.items():
        warnings.append(
            f"rule {rule_id} flags {float(details['ratio']):.1%} of windows and was not "
            "auto-excluded; calibrate it before detection"
        )

    clean_count = len(training_windows)
    if clean_count < minimum_windows:
        state = "insufficient"
        blockers.append(f"fewer than {minimum_windows} clean windows are available")
    elif blockers:
        state = "invalid"
    elif clean_count < recommended_windows:
        state = "preliminary"
        warnings.append(f"fewer than the recommended {recommended_windows} clean windows are available")
    elif warnings:
        state = "ready_with_warnings"
    else:
        state = "ready"

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "configuration": {
            "window_seconds": window_seconds,
            "minimum_windows": minimum_windows,
            "recommended_windows": recommended_windows,
            "recommended_duration_hours": recommended_windows * window_seconds / 3600.0,
            "max_rule_exclusion_ratio": max_rule_exclusion_ratio,
        },
        "sources": {
            "metrics": str(Path(metrics_path)),
            "events": str(Path(events_path)),
        },
        "metrics": {
            "jsonl": metric_jsonl,
            "timestamps": metric_timestamps,
            "features": metric_features,
        },
        "events": {
            "jsonl": event_jsonl,
            "timestamps": event_timestamps,
            "event_types": dict(sorted(event_types.items())),
            "collector_errors": collector_errors,
        },
        "coverage": coverage,
        "combined": {
            "windows": len(combined),
            "flagged_windows": flagged_windows,
            "excluded_windows": excluded_windows,
            "clean_windows": clean_count,
            "rule_counts": dict(sorted(rule_counts.items())),
            "noisy_rules": noisy_rules,
        },
        "proposed_splits": _split_summary(training_windows),
        "readiness": {
            "state": state,
            "ready_for_preliminary_training": clean_count >= minimum_windows and not blockers,
            "ready_for_final_training": state == "ready",
            "progress_ratio": min(1.0, clean_count / recommended_windows),
            "remaining_clean_windows": max(0, recommended_windows - clean_count),
            "blockers": blockers,
            "warnings": warnings,
        },
    }


def write_readiness_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
