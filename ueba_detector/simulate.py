from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any


def _normal_sample(rng: random.Random, timestamp: datetime) -> dict[str, Any]:
    return {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "host": "demo-host",
        "cpu_percent": max(0.0, rng.gauss(18, 6)),
        "memory_percent": rng.gauss(58, 4),
        "swap_percent": max(0.0, rng.gauss(2, 1)),
        "loadavg_1m": max(0.0, rng.gauss(1.2, 0.35)),
        "process_count": int(rng.gauss(260, 12)),
        "user_process_count": int(rng.gauss(150, 10)),
        "thread_count": int(rng.gauss(920, 70)),
        "net_bytes_sent_per_sec": max(0.0, rng.gauss(12_000, 5_000)),
        "net_bytes_recv_per_sec": max(0.0, rng.gauss(28_000, 8_000)),
        "net_packets_sent_per_sec": max(0.0, rng.gauss(45, 15)),
        "net_packets_recv_per_sec": max(0.0, rng.gauss(70, 20)),
        "net_errin_per_sec": 0.0,
        "net_errout_per_sec": 0.0,
        "net_dropin_per_sec": 0.0,
        "net_dropout_per_sec": 0.0,
        "disk_read_bytes_per_sec": max(0.0, rng.gauss(60_000, 30_000)),
        "disk_write_bytes_per_sec": max(0.0, rng.gauss(45_000, 25_000)),
        "tcp_established": int(rng.gauss(24, 5)),
        "tcp_listen": int(rng.gauss(9, 2)),
        "tcp_syn_sent": max(0, int(rng.gauss(1, 1))),
        "tcp_close_wait": max(0, int(rng.gauss(0, 1))),
        "unique_remote_ports": int(rng.gauss(7, 2)),
        "scenario": "normal",
    }


def generate_normal_samples(count: int = 360, seed: int = 7) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [_normal_sample(rng, start + timedelta(minutes=i)) for i in range(count)]


def generate_test_samples(count: int = 120, seed: int = 8) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    start = datetime(2026, 1, 2, tzinfo=timezone.utc)
    rows = [_normal_sample(rng, start + timedelta(minutes=i)) for i in range(count)]

    for idx in range(count // 4, count // 4 + 10):
        rows[idx]["scenario"] = "network_scan"
        rows[idx]["tcp_syn_sent"] = 70 + idx % 7
        rows[idx]["unique_remote_ports"] = 120 + idx
        rows[idx]["net_packets_sent_per_sec"] = 900 + idx * 3

    for idx in range(count // 2, count // 2 + 8):
        rows[idx]["scenario"] = "bulk_file_access"
        rows[idx]["disk_read_bytes_per_sec"] = 12_000_000 + idx * 1000
        rows[idx]["disk_write_bytes_per_sec"] = 8_000_000 + idx * 1000

    for idx in range(3 * count // 4, 3 * count // 4 + 8):
        rows[idx]["scenario"] = "suspicious_process_burst"
        rows[idx]["process_count"] = 520
        rows[idx]["thread_count"] = 2800
        rows[idx]["cpu_percent"] = 93

    return rows


def generate_security_events(
    samples: list[dict[str, Any]],
    *,
    seed: int = 9,
    inject_event_attacks: bool = False,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    events: list[dict[str, Any]] = []

    def add(sample: dict[str, Any], event_type: str, data: dict[str, Any]) -> None:
        events.append(
            {
                "timestamp": sample["timestamp"],
                "host": sample["host"],
                "event_type": event_type,
                "data": data,
            }
        )

    for idx, sample in enumerate(samples):
        starts = max(0, int(rng.gauss(2.0, 1.0)))
        stops = max(0, int(rng.gauss(1.8, 1.0)))
        for process_idx in range(starts):
            add(
                sample,
                "process_started",
                {
                    "actor": {"user": {"name": "demo-user"}},
                    "process": {"name": f"normal-app-{process_idx % 4}"},
                },
            )
        for process_idx in range(stops):
            add(
                sample,
                "process_stopped",
                {
                    "actor": {"user": {"name": "demo-user"}},
                    "process": {"name": f"normal-app-{process_idx % 4}"},
                },
            )
        if idx % 45 == 0:
            add(
                sample,
                "authentication_success",
                {
                    "actor": {"user": {"name": "demo-user"}},
                    "source_endpoint": {"ip": "10.0.0.5"},
                },
            )

        if sample.get("scenario") == "suspicious_process_burst":
            for process_idx in range(20):
                add(
                    sample,
                    "process_started",
                    {
                        "actor": {"user": {"name": "demo-user"}},
                        "process": {"name": f"burst-tool-{process_idx}"},
                    },
                )

        if inject_event_attacks and 10 <= idx < 16:
            sample["scenario"] = "authentication_bruteforce"
            for attempt in range(14):
                add(
                    sample,
                    "authentication_failure",
                    {
                        "actor": {"user": {"name": "target-user"}},
                        "source_endpoint": {"ip": f"203.0.113.{10 + attempt % 3}"},
                    },
                )

        if inject_event_attacks and 20 <= idx < 23:
            sample["scenario"] = "package_change_burst"
            for package_idx in range(7):
                add(
                    sample,
                    "package_installed",
                    {"package": {"name": f"unexpected-package-{package_idx}", "version": "1.0"}},
                )
    return events
