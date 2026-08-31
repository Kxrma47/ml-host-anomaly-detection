from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from ..collector import _psutil
from ..events import SecurityEvent, deterministic_event_id
from ..redaction import redact_command_line
from .base import CollectionResult


def _epoch_timestamp(value: object) -> str | None:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


class ProcessCollector:
    name = "processes"

    def __init__(
        self,
        *,
        interval_seconds: float = 2.0,
        emit_existing: bool = False,
        psutil_module: Any | None = None,
        host: str | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.emit_existing = emit_existing
        self.psutil = psutil_module or _psutil()
        self.host = host or socket.gethostname()

    @staticmethod
    def _identity(process: dict[str, Any]) -> str:
        created = process.get("created_at_epoch")
        return f"{process['pid']}:{created if created is not None else 'unknown'}"

    def _snapshot(self) -> dict[str, dict[str, Any]]:
        snapshot: dict[str, dict[str, Any]] = {}
        attributes = ["pid", "ppid", "name", "exe", "username", "cmdline", "create_time"]

        for proc in self.psutil.process_iter(attributes):
            try:
                info = proc.info
                pid = int(info.get("pid", getattr(proc, "pid", 0)) or 0)
                if pid <= 0:
                    continue
                created_raw = info.get("create_time")
                created_epoch = round(float(created_raw), 6) if created_raw is not None else None
                process = {
                    "pid": pid,
                    "parent_pid": int(info.get("ppid") or 0),
                    "name": str(info.get("name") or "unknown"),
                    "executable": str(info.get("exe") or ""),
                    "username": str(info.get("username") or "unknown"),
                    "command_line": redact_command_line(info.get("cmdline")),
                    "created_at": _epoch_timestamp(created_epoch),
                    "created_at_epoch": created_epoch,
                }
                snapshot[self._identity(process)] = process
            except (self.psutil.NoSuchProcess, self.psutil.AccessDenied, KeyError, TypeError, ValueError):
                continue
        return snapshot

    def _event(self, process: dict[str, Any], *, started: bool) -> SecurityEvent:
        activity = "Launch" if started else "Terminate"
        event_type = "process_started" if started else "process_stopped"
        timestamp = process.get("created_at") if started else None
        kwargs: dict[str, Any] = {"timestamp": timestamp} if timestamp else {}
        return SecurityEvent(
            host=self.host,
            category_name="System Activity",
            class_name="Process Activity",
            activity_name=activity,
            event_type=event_type,
            source="psutil.process_iter",
            status="success",
            event_id=deterministic_event_id(self.host, event_type, self._identity(process)),
            data={
                "actor": {"user": {"name": process.get("username", "unknown")}},
                "process": {key: value for key, value in process.items() if key != "created_at_epoch"},
            },
            **kwargs,
        )

    def collect(self, previous_state: dict[str, Any] | None) -> CollectionResult:
        current = self._snapshot()
        previous_state = previous_state or {}
        previous = previous_state.get("processes", {})
        initialized = bool(previous_state.get("initialized"))

        if not initialized and not self.emit_existing:
            events: list[SecurityEvent] = []
        else:
            started = sorted(set(current) - set(previous))
            stopped = sorted(set(previous) - set(current)) if initialized else []
            events = [self._event(current[key], started=True) for key in started]
            events.extend(self._event(previous[key], started=False) for key in stopped)

        return CollectionResult(events=events, state={"initialized": True, "processes": current})
