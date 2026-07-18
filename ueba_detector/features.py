from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from typing import Any


FEATURE_NAMES = [
    "cpu_percent",
    "memory_percent",
    "swap_percent",
    "loadavg_1m",
    "process_count",
    "user_process_count",
    "thread_count",
    "net_bytes_sent_per_sec",
    "net_bytes_recv_per_sec",
    "net_packets_sent_per_sec",
    "net_packets_recv_per_sec",
    "net_errin_per_sec",
    "net_errout_per_sec",
    "net_dropin_per_sec",
    "net_dropout_per_sec",
    "disk_read_bytes_per_sec",
    "disk_write_bytes_per_sec",
    "tcp_established",
    "tcp_listen",
    "tcp_syn_sent",
    "tcp_close_wait",
    "unique_remote_ports",
]


@dataclass(frozen=True)
class Scaler:
    feature_names: list[str]
    mean: list[float]
    std: list[float]

    def transform(self, sample: dict[str, Any]) -> list[float]:
        raw = sample_to_vector(sample, self.feature_names)
        return [(value - mu) / sigma for value, mu, sigma in zip(raw, self.mean, self.std)]


def _as_float(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def sample_to_vector(sample: dict[str, Any], feature_names: list[str] | None = None) -> list[float]:
    names = feature_names or FEATURE_NAMES
    return [_as_float(sample.get(name, 0.0)) for name in names]


def fit_scaler(samples: list[dict[str, Any]], feature_names: list[str] | None = None) -> Scaler:
    if not samples:
        raise ValueError("Need at least one sample to fit a scaler")

    names = list(feature_names or FEATURE_NAMES)
    matrix = [sample_to_vector(sample, names) for sample in samples]
    n = len(matrix)
    mean = [sum(row[i] for row in matrix) / n for i in range(len(names))]
    std: list[float] = []

    for i, mu in enumerate(mean):
        variance = sum((row[i] - mu) ** 2 for row in matrix) / n
        sigma = sqrt(variance)
        std.append(sigma if sigma >= 1e-9 else 1.0)

    return Scaler(feature_names=names, mean=mean, std=std)
