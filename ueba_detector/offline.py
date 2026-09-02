from __future__ import annotations

import time
import tracemalloc
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

from .combined import build_combined_samples, parse_timestamp
from .features import FEATURE_NAMES
from .simulate import generate_normal_samples, generate_security_events


SEVERITY_RANK = {"normal": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def replay_records(
    rows: list[dict[str, Any]],
    handler: Callable[[dict[str, Any]], Any] | None = None,
    *,
    speed: float = 0.0,
    max_sleep: float = 1.0,
    deduplicate: bool = True,
) -> tuple[list[Any], dict[str, Any]]:
    if speed < 0:
        raise ValueError("speed must not be negative")
    parsed: list[tuple[float, int, dict[str, Any]]] = []
    invalid = 0
    out_of_order = 0
    previous: float | None = None
    for index, row in enumerate(rows):
        try:
            epoch = parse_timestamp(row.get("timestamp"))
        except (TypeError, ValueError, OverflowError):
            invalid += 1
            continue
        if previous is not None and epoch < previous:
            out_of_order += 1
        previous = epoch
        parsed.append((epoch, index, row))
    parsed.sort(key=lambda item: (item[0], item[1]))

    seen: set[str] = set()
    duplicate_count = 0
    outputs: list[Any] = []
    handler_errors = 0
    prior_epoch: float | None = None
    callback = handler or (lambda row: row)
    started = time.perf_counter()
    for epoch, _index, row in parsed:
        identity = str(row.get("event_id") or f"{row.get('host')}\x1f{row.get('timestamp')}")
        if deduplicate and identity in seen:
            duplicate_count += 1
            continue
        seen.add(identity)
        if speed > 0 and prior_epoch is not None:
            time.sleep(min(max_sleep, max(0.0, epoch - prior_epoch) / speed))
        try:
            outputs.append(callback(row))
        except Exception:
            handler_errors += 1
        prior_epoch = epoch
    elapsed = time.perf_counter() - started
    return outputs, {
        "input_records": len(rows),
        "replayed_records": len(outputs),
        "invalid_timestamps": invalid,
        "duplicates_skipped": duplicate_count,
        "out_of_order_input": out_of_order,
        "handler_errors": handler_errors,
        "elapsed_seconds": elapsed,
        "records_per_second": len(outputs) / elapsed if elapsed else 0.0,
    }


def _severity(row: dict[str, Any]) -> str:
    value = str(row.get("severity") or "informational").lower()
    return value if value in SEVERITY_RANK else "informational"


def _row_timestamp(row: dict[str, Any]) -> Any:
    sample = row.get("sample") if isinstance(row.get("sample"), dict) else {}
    return (
        row.get("timestamp")
        or row.get("event_timestamp")
        or sample.get("timestamp")
        or row.get("detected_at")
    )


def _fingerprint(row: dict[str, Any]) -> str:
    rules = row.get("detection_rules") or row.get("rules") or []
    rule_ids = sorted(
        str(rule.get("rule_id")) for rule in rules if isinstance(rule, dict) and rule.get("rule_id")
    )
    top = row.get("top_features") or []
    features = sorted(
        str(item.get("feature")) for item in top[:3] if isinstance(item, dict) and item.get("feature")
    )
    signal = rule_ids or features or [str(row.get("event_type") or row.get("category") or "signal")]
    return "|".join([str(row.get("host") or "unknown"), *signal])


def group_alerts(rows: list[dict[str, Any]], *, cooldown_seconds: float = 300.0) -> list[dict[str, Any]]:
    if cooldown_seconds < 0:
        raise ValueError("cooldown_seconds must not be negative")
    groups: list[dict[str, Any]] = []
    active: dict[str, dict[str, Any]] = {}
    for row in sorted(rows, key=lambda item: parse_timestamp(_row_timestamp(item))):
        epoch = parse_timestamp(_row_timestamp(row))
        timestamp = _row_timestamp(row)
        fingerprint = _fingerprint(row)
        group = active.get(fingerprint)
        if group is None or epoch - float(group["last_epoch"]) > cooldown_seconds:
            group = {
                "fingerprint": fingerprint,
                "host": str(row.get("host") or "unknown"),
                "first_timestamp": timestamp,
                "last_timestamp": timestamp,
                "last_epoch": epoch,
                "count": 0,
                "severity": "informational",
                "evidence": [],
            }
            active[fingerprint] = group
            groups.append(group)
        group["count"] += 1
        group["last_timestamp"] = timestamp
        group["last_epoch"] = epoch
        severity = _severity(row)
        if SEVERITY_RANK[severity] > SEVERITY_RANK[str(group["severity"])]:
            group["severity"] = severity
        if len(group["evidence"]) < 20:
            group["evidence"].append(row)
    for group in groups:
        group.pop("last_epoch", None)
    return groups


def correlate_incidents(
    rows: list[dict[str, Any]],
    *,
    max_gap_seconds: float = 900.0,
) -> list[dict[str, Any]]:
    if max_gap_seconds <= 0:
        raise ValueError("max_gap_seconds must be positive")
    by_host: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_host.setdefault(str(row.get("host") or "unknown"), []).append(row)

    incidents: list[dict[str, Any]] = []
    for host, host_rows in sorted(by_host.items()):
        ordered = sorted(host_rows, key=lambda item: parse_timestamp(_row_timestamp(item)))
        current: list[dict[str, Any]] = []
        last_epoch: float | None = None
        for row in ordered:
            epoch = parse_timestamp(_row_timestamp(row))
            if current and last_epoch is not None and epoch - last_epoch > max_gap_seconds:
                incidents.append(_build_incident(host, current))
                current = []
            current.append(row)
            last_epoch = epoch
        if current:
            incidents.append(_build_incident(host, current))
    return incidents


def _build_incident(host: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    event_types = Counter(str(row.get("event_type") or row.get("category") or "anomaly") for row in rows)
    severities = [_severity(row) for row in rows]
    severity = max(severities, key=lambda item: SEVERITY_RANK[item])
    timeline = [
        {
            "timestamp": _row_timestamp(row),
            "type": str(row.get("event_type") or row.get("category") or "anomaly"),
            "severity": _severity(row),
            "summary": str(
                row.get("description")
                or row.get("explanation")
                or row.get("scenario")
                or "security signal"
            ),
        }
        for row in rows
    ]
    return {
        "incident_id": f"{host}:{_row_timestamp(rows[0])}:{len(rows)}",
        "host": host,
        "first_timestamp": _row_timestamp(rows[0]),
        "last_timestamp": _row_timestamp(rows[-1]),
        "severity": severity,
        "signal_count": len(rows),
        "event_types": dict(sorted(event_types.items())),
        "timeline": timeline,
    }


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2.0


def build_drift_profile(rows: list[dict[str, Any]], feature_names: list[str] | None = None) -> dict[str, Any]:
    if not rows:
        raise ValueError("need at least one row")
    names = feature_names or FEATURE_NAMES
    features: dict[str, dict[str, float]] = {}
    for name in names:
        values = [float(row.get(name, 0.0) or 0.0) for row in rows]
        median = _median(values)
        mad = _median([abs(value - median) for value in values])
        features[name] = {"median": median, "mad": mad, "minimum": min(values), "maximum": max(values)}
    return {"rows": len(rows), "features": features}


def compare_drift(
    reference_rows: list[dict[str, Any]],
    current_rows: list[dict[str, Any]],
    *,
    feature_names: list[str] | None = None,
    shift_threshold: float = 4.0,
    feature_ratio_threshold: float = 0.2,
) -> dict[str, Any]:
    reference = build_drift_profile(reference_rows, feature_names)
    current = build_drift_profile(current_rows, feature_names)
    shifts: dict[str, dict[str, Any]] = {}
    drifted = 0
    for name, baseline in reference["features"].items():
        observed = current["features"][name]
        scale = max(float(baseline["mad"]) * 1.4826, abs(float(baseline["median"])) * 0.01, 1e-6)
        score = abs(float(observed["median"]) - float(baseline["median"])) / scale
        is_drifted = score >= shift_threshold
        drifted += int(is_drifted)
        shifts[name] = {
            "reference_median": baseline["median"],
            "current_median": observed["median"],
            "robust_shift": score,
            "drifted": is_drifted,
        }
    ratio = drifted / len(shifts) if shifts else 0.0
    return {
        "reference_rows": len(reference_rows),
        "current_rows": len(current_rows),
        "drifted_features": drifted,
        "feature_count": len(shifts),
        "drift_ratio": ratio,
        "drift_detected": ratio >= feature_ratio_threshold,
        "thresholds": {
            "robust_shift": shift_threshold,
            "feature_ratio": feature_ratio_threshold,
        },
        "features": shifts,
    }


def run_stress_test(*, windows: int = 10_000, seed: int = 101) -> dict[str, Any]:
    if windows <= 0:
        raise ValueError("windows must be positive")
    started_at = datetime.now(tz=timezone.utc)
    tracemalloc.start()
    started = time.perf_counter()
    metrics = generate_normal_samples(count=windows, seed=seed)
    events = generate_security_events(metrics, seed=seed + 1)
    combined = build_combined_samples(metrics, events)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    completed_at = datetime.now(tz=timezone.utc)
    return {
        "generated_at": completed_at.isoformat().replace("+00:00", "Z"),
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
        "baseline_exclusion_recommended": True,
        "windows_requested": windows,
        "metric_rows": len(metrics),
        "event_rows": len(events),
        "combined_rows": len(combined),
        "elapsed_seconds": elapsed,
        "windows_per_second": windows / elapsed if elapsed else 0.0,
        "peak_memory_bytes": peak,
    }
