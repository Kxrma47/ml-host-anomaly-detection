from __future__ import annotations

import csv
import hashlib
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any


REVIEW_LABELS = {"unreviewed", "benign", "suspicious", "confirmed_attack"}


def alert_id(alert: dict[str, Any]) -> str:
    rules = sorted(
        str(item.get("rule_id", ""))
        for item in alert.get("detection_rules", [])
        if isinstance(item, dict)
    )
    features = [
        str(item.get("feature", ""))
        for item in alert.get("top_features", [])
        if isinstance(item, dict)
    ]
    identity = {
        "timestamp": alert.get("event_timestamp"),
        "host": alert.get("host"),
        "category": alert.get("category"),
        "rules": rules,
        "features": features,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"hwa-{digest[:16]}"


def build_review_rows(alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for alert in alerts:
        rules = [
            str(item.get("rule_id", ""))
            for item in alert.get("detection_rules", [])
            if isinstance(item, dict) and item.get("rule_id")
        ]
        features = [
            str(item.get("feature", ""))
            for item in alert.get("top_features", [])
            if isinstance(item, dict) and item.get("feature")
        ]
        rows.append(
            {
                "alert_id": alert_id(alert),
                "event_timestamp": str(alert.get("event_timestamp") or ""),
                "severity": str(alert.get("severity") or "unknown"),
                "category": str(alert.get("category") or "unknown"),
                "ratio": f"{float(alert.get('ratio', 0.0)):.6f}",
                "model_ratio": f"{float(alert.get('model_ratio', alert.get('ratio', 0.0))):.6f}",
                "rules": ";".join(rules),
                "top_features": ";".join(features),
                "label": "unreviewed",
                "analyst_note": "",
            }
        )
    return rows


def write_review_csv(path: str | Path, rows: list[dict[str, str]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else [
        "alert_id", "event_timestamp", "severity", "category", "ratio", "model_ratio",
        "rules", "top_features", "label", "analyst_note",
    ]
    with target.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_review_html(path: str | Path, rows: list[dict[str, str]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    table_rows = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(row[name])}</td>" for name in (
            "alert_id", "event_timestamp", "severity", "category", "ratio", "rules",
            "top_features", "label", "analyst_note",
        )) + "</tr>"
        for row in rows
    )
    document = f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>HostWatch alert review</title>
<style>
body{{font:14px system-ui;margin:0;color:#17201d;background:#f5f7f6}}main{{padding:28px;max-width:1500px;margin:auto}}
h1{{font-size:24px}}p{{color:#50605a}}.table{{overflow:auto;border:1px solid #d8dfdc;background:white}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:9px 11px;border-bottom:1px solid #e6ebe9;text-align:left;white-space:nowrap}}
th{{position:sticky;top:0;background:#edf2f0}}td:nth-child(7),td:nth-child(9){{white-space:normal;min-width:240px}}
</style><main><h1>HostWatch alert review</h1>
<p>{len(rows)} alerts. Edit the CSV labels to benign, suspicious, or confirmed_attack; keep evidence in analyst_note.</p>
<div class="table"><table><thead><tr><th>ID</th><th>Time</th><th>Severity</th><th>Category</th><th>Ratio</th><th>Rules</th><th>Top features</th><th>Label</th><th>Analyst note</th></tr></thead>
<tbody>{table_rows}</tbody></table></div></main></html>"""
    target.write_text(document, encoding="utf-8")


def summarize_review_csv(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    invalid = sorted({row.get("label", "") for row in rows if row.get("label", "") not in REVIEW_LABELS})
    if invalid:
        raise ValueError(f"Unsupported review labels: {', '.join(invalid)}")
    labels = Counter(row.get("label", "unreviewed") for row in rows)
    return {
        "total": len(rows),
        "labels": {label: labels.get(label, 0) for label in sorted(REVIEW_LABELS)},
        "reviewed": len(rows) - labels.get("unreviewed", 0),
    }


def load_review_labels(path: str | Path) -> dict[str, str]:
    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    labels: dict[str, str] = {}
    for row in rows:
        identifier = str(row.get("alert_id") or "").strip()
        label = str(row.get("label") or "").strip()
        if not identifier:
            raise ValueError("Review row is missing alert_id")
        if identifier in labels:
            raise ValueError(f"Duplicate alert_id in review: {identifier}")
        if label not in REVIEW_LABELS:
            raise ValueError(f"Unsupported review label: {label}")
        labels[identifier] = label
    return labels


def evaluate_reviewed_alerts(alerts: list[dict[str, Any]], labels: dict[str, str]) -> dict[str, Any]:
    known_ids = {alert_id(alert) for alert in alerts}
    unknown_ids = sorted(set(labels) - known_ids)
    if unknown_ids:
        raise ValueError(f"Review contains {len(unknown_ids)} alert IDs not present in the anomaly file")
    matched = [(alert, labels.get(alert_id(alert), "unreviewed")) for alert in alerts]
    counts = Counter(label for _, label in matched)
    reviewed = [(alert, label) for alert, label in matched if label != "unreviewed"]
    positive = sum(label in {"suspicious", "confirmed_attack"} for _, label in reviewed)
    benign = sum(label == "benign" for _, label in reviewed)
    return {
        "alerts": len(alerts),
        "matched_reviews": sum(alert_id(alert) in labels for alert in alerts),
        "reviewed": len(reviewed),
        "unreviewed": len(alerts) - len(reviewed),
        "labels": {label: counts.get(label, 0) for label in sorted(REVIEW_LABELS)},
        "alert_precision": positive / len(reviewed) if reviewed else None,
        "reviewed_true_alerts": positive,
        "reviewed_false_alerts": benign,
        "recall": None,
        "recall_note": "Alert review alone cannot reveal attacks the detector missed.",
    }


def select_reviewed_baseline(
    samples: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    labels: dict[str, str],
    *,
    maximum_unreviewed: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    evaluation = evaluate_reviewed_alerts(alerts, labels)
    if int(evaluation["unreviewed"]) > maximum_unreviewed:
        raise ValueError(
            f"Review gate failed: {evaluation['unreviewed']} alert(s) remain unreviewed; "
            f"maximum allowed is {maximum_unreviewed}"
        )
    excluded_windows = {
        (str(alert.get("host") or "unknown"), str(alert.get("event_timestamp") or ""))
        for alert in alerts
        if labels.get(alert_id(alert)) in {"suspicious", "confirmed_attack"}
    }
    selected = [
        sample for sample in samples
        if (str(sample.get("host") or "unknown"), str(sample.get("timestamp") or ""))
        not in excluded_windows
    ]
    if not selected:
        raise ValueError("No baseline windows remain after applying reviewed labels")
    return selected, {
        "input_windows": len(samples),
        "selected_windows": len(selected),
        "excluded_reviewed_alert_windows": len(samples) - len(selected),
        "review": evaluation,
    }
