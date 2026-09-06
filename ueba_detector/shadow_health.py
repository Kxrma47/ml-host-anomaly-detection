from __future__ import annotations

import json
import math
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .combined import parse_timestamp
from .storage import jsonl_dataset_paths, read_jsonl_dataset


def _optional_rows(path: str | Path) -> list[dict[str, Any]]:
    return read_jsonl_dataset(path) if jsonl_dataset_paths(path) else []


def _quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, round((len(ordered) - 1) * q)))]


def build_shadow_health_report(
    *,
    metrics_path: str | Path,
    events_path: str | Path,
    scores_path: str | Path,
    alerts_path: str | Path,
    expected_interval: float = 60.0,
    stale_after: float = 180.0,
    now_epoch: float | None = None,
) -> dict[str, Any]:
    metrics = _optional_rows(metrics_path)
    events = _optional_rows(events_path)
    scores = _optional_rows(scores_path)
    alerts = _optional_rows(alerts_path)
    now = now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp()
    metric_times = sorted(parse_timestamp(row.get("timestamp")) for row in metrics)
    gaps = [b - a for a, b in zip(metric_times, metric_times[1:])]
    expected = (
        max(1, math.floor((metric_times[-1] - metric_times[0]) / expected_interval) + 1)
        if metric_times else 0
    )
    coverage = min(1.0, len(metric_times) / expected) if expected else 0.0
    latest_epoch = metric_times[-1] if metric_times else None
    latest_age = max(0.0, now - latest_epoch) if latest_epoch is not None else None
    collector_errors = sum(row.get("event_type") == "collector_error" for row in events)
    ratios = [float(row.get("ratio", 0.0) or 0.0) for row in scores]
    severity = Counter(str(row.get("severity") or "unknown") for row in alerts)
    rule_counts = Counter(
        str(rule.get("rule_id") or "unknown")
        for row in scores for rule in row.get("rules", []) if isinstance(rule, dict)
    )
    reasons: list[str] = []
    if not metrics or not scores:
        reasons.append("no completed monitoring evidence")
    if latest_age is not None and latest_age > stale_after:
        reasons.append("latest metric is stale")
    if collector_errors:
        reasons.append("collector errors were recorded")
    if coverage < 0.98 and len(metrics) > 2:
        reasons.append("metric coverage is below 98 percent")
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "state": "healthy" if not reasons else "degraded",
        "reasons": reasons,
        "metrics": {
            "records": len(metrics),
            "coverage_ratio": coverage,
            "gap_count": sum(gap > expected_interval * 1.5 for gap in gaps),
            "largest_gap_seconds": max(gaps, default=0.0),
            "latest_age_seconds": latest_age,
        },
        "events": {
            "records": len(events),
            "collector_errors": collector_errors,
            "heartbeats": sum(row.get("event_type") == "agent_heartbeat" for row in events),
        },
        "scores": {
            "windows": len(scores),
            "anomalies": sum(bool(row.get("is_anomaly")) for row in scores),
            "ratio_p50": _quantile(ratios, 0.50),
            "ratio_p95": _quantile(ratios, 0.95),
            "ratio_max": max(ratios, default=None),
            "rule_triggers": dict(sorted(rule_counts.items())),
        },
        "alerts": {"records": len(alerts), "severity": dict(sorted(severity.items()))},
        "privacy": "Aggregate health only; hostnames and raw event fields are omitted.",
    }


def write_shadow_health_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
