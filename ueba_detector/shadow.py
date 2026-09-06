from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .autoencoder import NeuralAutoencoder
from .combined import build_combined_samples, parse_timestamp, score_combined_sample
from .reporting import build_anomaly_event
from .storage import RotatingJsonlWriter


def pseudonymous_host_id(host: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}\0{host}".encode("utf-8")).hexdigest()
    return f"host-{digest[:16]}"


def load_or_create_salt(path: str | Path) -> str:
    target = Path(path)
    if target.exists():
        value = target.read_text(encoding="utf-8").strip()
        if len(value) < 32:
            raise ValueError("Host identity salt must contain at least 32 characters")
        return value
    target.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    target.write_text(value + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    return value


def read_ingest_key(path: str | Path | None) -> str | None:
    value = os.environ.get("HOSTWATCH_INGEST_KEY", "").strip()
    if not value and path:
        value = Path(path).read_text(encoding="utf-8").strip()
    if value and len(value) < 20:
        raise ValueError("Ingest key must contain at least 20 characters")
    return value or None


def validate_cloud_endpoint(endpoint: str) -> str:
    value = endpoint.rstrip("/")
    parsed = urlparse(value)
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if not parsed.hostname or (parsed.scheme != "https" and not (local and parsed.scheme == "http")):
        raise ValueError("Cloud endpoint must use HTTPS (HTTP is allowed only for localhost)")
    return value


def upload_snapshot(endpoint: str, key: str, snapshot: dict[str, Any], *, timeout: float = 10.0) -> str:
    request = urllib.request.Request(
        f"{validate_cloud_endpoint(endpoint)}/api/ingest",
        data=json.dumps(snapshot, separators=(",", ":")).encode("utf-8"),
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "HostWatch-Agent/0.6",
            "x-ingest-key": key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Cloud snapshot rejected with HTTP {exc.code}") from exc
    return str(result.get("id") or "accepted")


class ShadowMonitor:
    def __init__(
        self,
        *,
        model: NeuralAutoencoder,
        model_path: str,
        rule_thresholds: dict[str, int] | None,
        telemetry: Any,
        agent: Any,
        metrics_output: str | Path,
        scores_output: str | Path,
        alerts_output: str | Path,
        cloud_endpoint: str | None = None,
        ingest_key: str | None = None,
        cloud_host_id: str | None = None,
        upload_interval: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if cloud_endpoint and not ingest_key:
            raise ValueError("Cloud reporting requires an ingest key")
        self.model = model
        self.model_path = model_path
        self.rule_thresholds = rule_thresholds
        self.telemetry = telemetry
        self.agent = agent
        self.metric_writer = RotatingJsonlWriter(metrics_output, max_bytes=50 * 1024 * 1024, retention_days=14)
        self.score_writer = RotatingJsonlWriter(scores_output, max_bytes=50 * 1024 * 1024, retention_days=30)
        self.alert_writer = RotatingJsonlWriter(alerts_output, max_bytes=50 * 1024 * 1024, retention_days=90)
        self.cloud_endpoint = validate_cloud_endpoint(cloud_endpoint) if cloud_endpoint else None
        self.ingest_key = ingest_key
        self.cloud_host_id = cloud_host_id
        self.upload_interval = max(60.0, upload_interval)
        self.clock = clock
        self.started_at = clock()
        self.last_upload = 0.0
        self.windows = 0
        self.open_alerts = 0
        self.critical_alerts = 0

    def score_window(self, metric: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
        rows = build_combined_samples([metric], events)
        if not rows:
            raise ValueError("Metric sample did not produce a combined window")
        sample = rows[0]
        score, rules, model_ratio = score_combined_sample(
            self.model, sample, rule_thresholds=self.rule_thresholds
        )
        result = {
            "timestamp": sample["timestamp"],
            "host": sample.get("host", "unknown"),
            "model_ratio": model_ratio,
            "ratio": score.ratio,
            "is_anomaly": score.is_anomaly,
            "severity": score.severity,
            "top_features": score.top_features,
            "rules": rules,
        }
        self.score_writer.write(result)
        self.windows += 1
        if score.is_anomaly:
            alert = build_anomaly_event(sample, score, model_path=self.model_path)
            alert["model_ratio"] = model_ratio
            alert["detection_rules"] = rules
            self.alert_writer.write(alert)
            self.open_alerts += 1
            if score.severity == "critical":
                self.critical_alerts += 1
        self._maybe_upload(sample["timestamp"])
        return result

    def _maybe_upload(self, observed_at: str, *, force: bool = False) -> None:
        if not self.cloud_endpoint or not self.ingest_key or not self.cloud_host_id:
            return
        now = self.clock()
        if not force and now - self.last_upload < self.upload_interval:
            return
        elapsed_windows = max(1.0, (now - self.started_at) / 60.0)
        snapshot = {
            "schema_version": "1.0",
            "host": self.cloud_host_id,
            "observed_at": observed_at,
            "window_count": self.windows,
            "open_alerts": self.open_alerts,
            "critical_alerts": self.critical_alerts,
            "readiness_state": "shadow_monitoring",
            "coverage_ratio": min(1.0, self.windows / elapsed_windows),
        }
        try:
            upload_snapshot(self.cloud_endpoint, self.ingest_key, snapshot)
            self.last_upload = now
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"cloud snapshot failed: {exc}", flush=True)

    def run(self, *, event_interval: float = 2.0, metric_interval: float = 60.0, duration: float | None = None) -> None:
        event_interval = max(0.1, event_interval)
        metric_interval = max(1.0, metric_interval)
        started = time.monotonic()
        current_metric = self.telemetry.sample()
        self.metric_writer.write(current_metric)
        next_metric = time.monotonic() + metric_interval
        pending_events: list[dict[str, Any]] = []
        try:
            while True:
                pending_events.extend(self.agent.collect_once())
                now = time.monotonic()
                if now >= next_metric:
                    result = self.score_window(current_metric, pending_events)
                    completed_window = int(parse_timestamp(current_metric["timestamp"])) // 60
                    pending_events = [
                        event for event in pending_events
                        if int(parse_timestamp(event.get("timestamp"))) // 60 > completed_window
                    ]
                    print(
                        f"{result['timestamp']} shadow score {float(result['ratio']):.3f} "
                        f"({result['severity']})",
                        flush=True,
                    )
                    current_metric = self.telemetry.sample()
                    self.metric_writer.write(current_metric)
                    next_metric += metric_interval
                elapsed = time.monotonic() - started
                if duration is not None and elapsed >= duration:
                    break
                time.sleep(min(event_interval, max(0.1, next_metric - time.monotonic())))
        except KeyboardInterrupt:
            print("shadow monitoring stopped", flush=True)
        finally:
            if not duration or time.monotonic() - started >= min(duration, metric_interval * 0.25):
                result = self.score_window(current_metric, pending_events)
                print(
                    f"{result['timestamp']} final shadow score {float(result['ratio']):.3f} "
                    f"({result['severity']})",
                    flush=True,
                )
            observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self._maybe_upload(observed_at, force=True)


def default_cloud_host_id(salt_path: str | Path) -> str:
    return pseudonymous_host_id(socket.gethostname(), load_or_create_salt(salt_path))
