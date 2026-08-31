from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .autoencoder import NeuralAutoencoder, Score
from .features import FEATURE_NAMES
from .storage import jsonl_dataset_paths, read_jsonl_dataset, write_jsonl


EVENT_COUNT_FEATURES = {
    "process_started": "event_process_started_count",
    "process_stopped": "event_process_stopped_count",
    "authentication_success": "event_authentication_success_count",
    "authentication_failure": "event_authentication_failure_count",
    "session_started": "event_session_started_count",
    "session_ended": "event_session_ended_count",
    "privilege_elevation": "event_privilege_elevation_count",
    "package_installed": "event_package_installed_count",
    "package_removed": "event_package_removed_count",
    "package_updated": "event_package_updated_count",
    "collector_error": "event_collector_error_count",
}
EVENT_FEATURE_NAMES = [
    *EVENT_COUNT_FEATURES.values(),
    "event_unique_processes",
    "event_unique_users",
    "event_unique_remote_sources",
    "event_total_count",
]
COMBINED_FEATURE_NAMES = [*FEATURE_NAMES, *EVENT_FEATURE_NAMES]
DEFAULT_RULE_THRESHOLDS = {
    "authentication_failure_burst": 5,
    "package_change_burst": 3,
    "process_start_burst": 20,
    "privilege_elevation_burst": 3,
}


def evaluate_security_rules(
    sample: dict[str, Any],
    thresholds: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    configured = {**DEFAULT_RULE_THRESHOLDS, **(thresholds or {})}
    findings: list[dict[str, Any]] = []
    failures = int(sample.get("event_authentication_failure_count", 0) or 0)
    successes = int(sample.get("event_authentication_success_count", 0) or 0)
    package_changes = sum(
        int(sample.get(name, 0) or 0)
        for name in (
            "event_package_installed_count",
            "event_package_removed_count",
            "event_package_updated_count",
        )
    )
    process_starts = int(sample.get("event_process_started_count", 0) or 0)
    elevations = int(sample.get("event_privilege_elevation_count", 0) or 0)

    auth_threshold = max(1, int(configured["authentication_failure_burst"]))
    package_threshold = max(1, int(configured["package_change_burst"]))
    process_threshold = max(1, int(configured["process_start_burst"]))
    elevation_threshold = max(1, int(configured["privilege_elevation_burst"]))

    if failures >= auth_threshold:
        findings.append(
            {
                "rule_id": "authentication_failure_burst",
                "severity": "high" if successes else "medium",
                "ratio_floor": 2.5 if successes else 1.0,
                "description": f"{failures} failed logins occurred in one window"
                + (" before or alongside a successful login" if successes else ""),
            }
        )
    if package_changes >= package_threshold:
        findings.append(
            {
                "rule_id": "package_change_burst",
                "severity": "medium",
                "ratio_floor": 1.0,
                "description": f"{package_changes} package changes occurred in one window",
            }
        )
    if process_starts >= process_threshold:
        findings.append(
            {
                "rule_id": "process_start_burst",
                "severity": "high",
                "ratio_floor": 2.5,
                "description": f"{process_starts} processes started in one window",
            }
        )
    if elevations >= elevation_threshold:
        findings.append(
            {
                "rule_id": "privilege_elevation_burst",
                "severity": "medium",
                "ratio_floor": 1.0,
                "description": f"{elevations} privilege elevations occurred in one window",
            }
        )
    return findings


def score_combined_sample(
    model: NeuralAutoencoder,
    sample: dict[str, Any],
    *,
    rule_thresholds: dict[str, int] | None = None,
) -> tuple[Score, list[dict[str, Any]], float]:
    model_score = model.score(sample)
    rules = evaluate_security_rules(sample, rule_thresholds)
    final_ratio = max([model_score.ratio, *(float(rule["ratio_floor"]) for rule in rules)])
    if final_ratio >= 5.0:
        severity = "critical"
    elif final_ratio >= 2.5:
        severity = "high"
    elif final_ratio >= 1.0:
        severity = "medium"
    else:
        severity = "normal"
    return (
        Score(
            error=model_score.error,
            threshold=model_score.threshold,
            ratio=final_ratio,
            is_anomaly=final_ratio >= 1.0,
            severity=severity,
            top_features=model_score.top_features,
        ),
        rules,
        model_score.ratio,
    )


def parse_timestamp(value: object) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Missing timestamp")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _window_key(row: dict[str, Any], window_seconds: int) -> tuple[str, int]:
    host = str(row.get("host") or "unknown")
    timestamp = int(parse_timestamp(row.get("timestamp")))
    return host, timestamp - (timestamp % window_seconds)


def _nested(data: dict[str, Any], *path: str) -> Any:
    value: Any = data
    for name in path:
        if not isinstance(value, dict):
            return None
        value = value.get(name)
    return value


def _new_event_bucket() -> dict[str, Any]:
    return {
        "counts": Counter(),
        "processes": set(),
        "users": set(),
        "remote_sources": set(),
    }


def build_combined_samples(
    metrics: list[dict[str, Any]],
    events: list[dict[str, Any]],
    *,
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    metric_windows: dict[tuple[str, int], dict[str, Any]] = {}
    scenarios: dict[tuple[str, int], Counter[str]] = {}
    for sample in metrics:
        try:
            key = _window_key(sample, window_seconds)
        except (TypeError, ValueError, OverflowError):
            continue
        bucket = metric_windows.setdefault(
            key,
            {"count": 0, "totals": {name: 0.0 for name in FEATURE_NAMES}},
        )
        bucket["count"] += 1
        for name in FEATURE_NAMES:
            try:
                bucket["totals"][name] += float(sample.get(name, 0.0) or 0.0)
            except (TypeError, ValueError):
                continue
        if sample.get("scenario"):
            scenarios.setdefault(key, Counter())[str(sample["scenario"])] += 1

    event_windows: dict[tuple[str, int], dict[str, Any]] = {}
    for event in events:
        event_type = str(event.get("event_type") or "")
        feature = EVENT_COUNT_FEATURES.get(event_type)
        if feature is None:
            continue
        try:
            key = _window_key(event, window_seconds)
        except (TypeError, ValueError, OverflowError):
            continue
        bucket = event_windows.setdefault(key, _new_event_bucket())
        bucket["counts"][feature] += 1

        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        process_name = _nested(data, "process", "name")
        username = _nested(data, "actor", "user", "name")
        remote = _nested(data, "source_endpoint", "ip") or _nested(
            data, "source_endpoint", "hostname"
        )
        if process_name and process_name != "unknown":
            bucket["processes"].add(str(process_name))
        if username and username != "unknown":
            bucket["users"].add(str(username))
        if remote and remote not in {"unknown", "local"}:
            bucket["remote_sources"].add(str(remote))

    combined: list[dict[str, Any]] = []
    for (host, window_start), metric_bucket in sorted(metric_windows.items(), key=lambda item: item[0]):
        count = int(metric_bucket["count"])
        row: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(window_start, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "host": host,
            "window_seconds": window_seconds,
            "metric_sample_count": count,
        }
        row.update({name: metric_bucket["totals"][name] / count for name in FEATURE_NAMES})

        event_bucket = event_windows.get((host, window_start), _new_event_bucket())
        for name in EVENT_COUNT_FEATURES.values():
            row[name] = int(event_bucket["counts"].get(name, 0))
        row["event_unique_processes"] = len(event_bucket["processes"])
        row["event_unique_users"] = len(event_bucket["users"])
        row["event_unique_remote_sources"] = len(event_bucket["remote_sources"])
        row["event_total_count"] = sum(int(row[name]) for name in EVENT_COUNT_FEATURES.values())
        row["event_record_count"] = row["event_total_count"]
        if scenarios.get((host, window_start)):
            row["scenario"] = scenarios[(host, window_start)].most_common(1)[0][0]
        combined.append(row)
    return combined


def build_combined_file(
    metrics_path: str | Path,
    events_path: str | Path,
    output_path: str | Path,
    *,
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    metrics = read_jsonl_dataset(metrics_path)
    events = read_jsonl_dataset(events_path) if jsonl_dataset_paths(events_path) else []
    rows = build_combined_samples(metrics, events, window_seconds=window_seconds)
    write_jsonl(output_path, rows)
    return rows
