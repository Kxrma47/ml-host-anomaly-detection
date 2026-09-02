from __future__ import annotations

import os
import platform
import socket
import time
from pathlib import Path
from typing import Any

from . import __version__
from .event_collectors.base import EventCollector
from .events import SecurityEvent
from .redaction import redact_data, redact_text
from .state import JsonStateStore
from .storage import RotatingJsonlWriter


class SecurityAgent:
    def __init__(
        self,
        collectors: list[EventCollector],
        *,
        output: str | Path,
        state_path: str | Path,
        heartbeat_interval: float = 60.0,
        host: str | None = None,
        max_file_bytes: int = 0,
        retention_days: float | None = None,
        compress_rotated: bool = True,
    ) -> None:
        names = [collector.name for collector in collectors]
        if len(names) != len(set(names)):
            raise ValueError("Collector names must be unique")
        self.collectors = collectors
        self.output = Path(output)
        self.state_store = JsonStateStore(state_path)
        self.heartbeat_interval = max(1.0, heartbeat_interval)
        self.host = host or socket.gethostname()
        self.writer = RotatingJsonlWriter(
            self.output,
            max_bytes=max_file_bytes,
            retention_days=retention_days,
            compress=compress_rotated,
        )
        self._state: dict[str, Any] | None = None

    def _heartbeat(self) -> SecurityEvent:
        return SecurityEvent(
            host=self.host,
            category_name="System Activity",
            class_name="Device Config State",
            activity_name="Heartbeat",
            event_type="agent_heartbeat",
            source="ueba_detector.agent",
            status="success",
            data={
                "agent": {
                    "version": __version__,
                    "collectors": [collector.name for collector in self.collectors],
                    "python_version": platform.python_version(),
                    "platform": platform.platform(),
                }
            },
        )

    def _collector_error(self, collector: EventCollector, exc: Exception) -> SecurityEvent:
        return SecurityEvent(
            host=self.host,
            category_name="Findings",
            class_name="Security Finding",
            activity_name="Collector Error",
            event_type="collector_error",
            source="ueba_detector.agent",
            status="failure",
            severity="low",
            data={
                "collector": collector.name,
                "error_type": type(exc).__name__,
                "message": redact_text(exc),
            },
        )

    def collect_once(self, *, now_epoch: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now_epoch is None else now_epoch
        if self._state is None:
            self._state = self.state_store.load_or_recover()
        collector_states = self._state["collectors"]
        schedule = self._state["schedule"]
        events: list[SecurityEvent] = []

        for collector in self.collectors:
            last_attempt = float(schedule.get(collector.name, 0.0))
            if last_attempt and now - last_attempt < max(0.1, collector.interval_seconds):
                continue
            schedule[collector.name] = now
            try:
                result = collector.collect(collector_states.get(collector.name))
            except Exception as exc:  # A failed sensor must not stop the other sensors.
                events.append(self._collector_error(collector, exc))
                continue
            collector_states[collector.name] = result.state
            events.extend(result.events)

        last_heartbeat = float(schedule.get("agent_heartbeat", 0.0))
        if not last_heartbeat or now - last_heartbeat >= self.heartbeat_interval:
            schedule["agent_heartbeat"] = now
            events.append(self._heartbeat())

        rows = [redact_data(event.to_dict()) for event in events]
        if rows:
            self.writer.write_many(rows)
            try:
                os.chmod(self.output, 0o600)
            except OSError:
                pass

        agent_state = dict(self._state.get("agent") or {})
        agent_state.update(
            {
                "host": self.host,
                "last_cycle_epoch": now,
                "last_event_count": len(rows),
            }
        )
        self._state["agent"] = agent_state
        # State follows event persistence, giving at-least-once behavior after a crash.
        self.state_store.save(self._state)
        return rows

    def run(self, *, interval: float = 2.0, duration: float | None = None) -> None:
        poll_interval = max(0.1, interval)
        started = time.monotonic()
        while True:
            rows = self.collect_once()
            if rows:
                print(f"collected {len(rows)} security event(s) into {self.output}", flush=True)
            elapsed = time.monotonic() - started
            if duration is not None and elapsed >= duration:
                break
            sleep_for = poll_interval if duration is None else min(poll_interval, max(0.0, duration - elapsed))
            time.sleep(sleep_for)
