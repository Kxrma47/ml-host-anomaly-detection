from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .autoencoder import Score
from .storage import read_jsonl


def classify_anomaly(top_features: list[dict[str, float]]) -> tuple[str, str]:
    groups = {
        "network_anomaly": {
            "features": {
                "tcp_syn_sent",
                "unique_remote_ports",
                "tcp_established",
                "tcp_listen",
                "tcp_close_wait",
                "net_bytes_sent_per_sec",
                "net_bytes_recv_per_sec",
                "net_packets_sent_per_sec",
                "net_packets_recv_per_sec",
                "net_errin_per_sec",
                "net_errout_per_sec",
                "net_dropin_per_sec",
                "net_dropout_per_sec",
            },
            "text": "Network connection profile differs from the learned baseline; possible scan, C2 beaconing, or unusual data transfer.",
        },
        "process_activity_anomaly": {
            "features": {"process_count", "thread_count", "user_process_count"},
            "text": "Process/thread profile differs from normal behavior; possible tool launch, automation, or suspicious workload.",
        },
        "storage_activity_anomaly": {
            "features": {"disk_read_bytes_per_sec", "disk_write_bytes_per_sec"},
            "text": "Disk I/O differs from normal behavior; possible bulk file access, staging, backup, or exfiltration preparation.",
        },
        "resource_usage_anomaly": {
            "features": {"cpu_percent", "memory_percent", "swap_percent", "loadavg_1m"},
            "text": "Host resource usage differs from normal behavior; possible crypto-mining, compression, or abnormal application activity.",
        },
    }
    scores = {name: 0.0 for name in groups}
    for item in top_features:
        feature = str(item.get("feature", ""))
        contribution = float(item.get("contribution", 0.0))
        for name, group in groups.items():
            if feature in group["features"]:
                scores[name] += contribution

    category = max(scores, key=scores.get)
    if scores[category] > 0:
        return category, str(groups[category]["text"])
    return ("generic_behavior_anomaly", "The sample has high reconstruction error compared with the normal host profile.")


def build_anomaly_event(sample: dict[str, Any], score: Score, *, model_path: str) -> dict[str, Any]:
    category, explanation = classify_anomaly(score.top_features)
    return {
        "detected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_timestamp": sample.get("timestamp"),
        "host": sample.get("host", "unknown"),
        "category": category,
        "severity": score.severity,
        "reconstruction_error": score.error,
        "threshold": score.threshold,
        "ratio": score.ratio,
        "top_features": score.top_features,
        "explanation": explanation,
        "model_path": model_path,
        "sample": sample,
    }


def write_text_summary(anomalies: list[dict[str, Any]], output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter(item.get("category", "unknown") for item in anomalies)
    lines = [
        "UEBA anomaly report",
        "",
        f"Total anomalies: {len(anomalies)}",
        "",
        "Categories",
        "",
    ]
    if counts:
        for category, count in counts.most_common():
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- No anomalies detected")

    lines.extend(["", "Events", ""])
    for idx, event in enumerate(anomalies, start=1):
        lines.extend(
            [
                f"Event {idx}",
                "",
                f"- Timestamp: {event.get('event_timestamp')}",
                f"- Host: {event.get('host')}",
                f"- Severity: {event.get('severity')}",
                f"- Category: {event.get('category')}",
                f"- Error ratio: {float(event.get('ratio', 0.0)):.2f}",
                f"- Explanation: {event.get('explanation')}",
                "- Top features: "
                + ", ".join(str(item.get("feature")) for item in event.get("top_features", [])),
                "",
            ]
        )
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def summarize_jsonl(input_path: str | Path, output_path: str | Path) -> None:
    write_text_summary(read_jsonl(input_path), output_path)
