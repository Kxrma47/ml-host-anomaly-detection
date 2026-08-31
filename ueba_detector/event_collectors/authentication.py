from __future__ import annotations

import hashlib
import platform
import re
import socket
from pathlib import Path
from typing import Any

from ..collector import _psutil
from ..events import SecurityEvent, deterministic_event_id, utc_timestamp
from ..redaction import redact_text
from .base import CollectionResult


_SSH_SUCCESS = re.compile(
    r"sshd\[\d+\]: Accepted (?P<method>\S+) for (?P<user>\S+) from "
    r"(?P<address>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_SSH_FAILURE = re.compile(
    r"sshd\[\d+\]: Failed (?P<method>\S+) for (?:(?:invalid user) )?(?P<user>\S+) from "
    r"(?P<address>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_PAM_FAILURE = re.compile(
    r"authentication failure;.*?(?:rhost=(?P<address>\S*))?.*?user=(?P<user>\S+)",
    re.IGNORECASE,
)
_SESSION_OPEN = re.compile(r"session opened for user (?P<user>\S+)", re.IGNORECASE)
_SESSION_CLOSE = re.compile(r"session closed for user (?P<user>\S+)", re.IGNORECASE)
_SUDO = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?P<actor>[^: ]+)\s*:\s+.*?USER=(?P<target>[^ ;]+)\s*;\s*COMMAND=(?P<command>.*)$",
    re.IGNORECASE,
)


def discover_auth_log_paths() -> list[str]:
    system = platform.system().lower()
    candidates: list[str]
    if system == "linux":
        candidates = ["/var/log/auth.log", "/var/log/secure"]
    elif system == "darwin":
        candidates = ["/var/log/system.log"]
    else:
        candidates = []
    return [path for path in candidates if Path(path).is_file()]


def _message_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()


def parse_auth_log_line(
    line: str,
    *,
    host: str,
    source: str,
    timestamp: str | None = None,
) -> SecurityEvent | None:
    event_timestamp = timestamp or utc_timestamp()
    common = {
        "host": host,
        "category_name": "Identity & Access Management",
        "source": source,
        "timestamp": event_timestamp,
    }
    message_hash = _message_hash(line)

    def event_id(event_type: str) -> str:
        return deterministic_event_id(host, source, event_type, message_hash)

    match = _SSH_SUCCESS.search(line)
    if match:
        return SecurityEvent(
            class_name="Authentication",
            activity_name="Logon",
            event_type="authentication_success",
            event_id=event_id("authentication_success"),
            status="success",
            data={
                "actor": {"user": {"name": match.group("user")}},
                "authentication": {"protocol": "ssh", "method": match.group("method")},
                "source_endpoint": {
                    "ip": match.group("address"),
                    "port": int(match.group("port")),
                },
                "message_hash": message_hash,
            },
            **common,
        )

    match = _SSH_FAILURE.search(line)
    if match:
        return SecurityEvent(
            class_name="Authentication",
            activity_name="Logon",
            event_type="authentication_failure",
            event_id=event_id("authentication_failure"),
            status="failure",
            severity="low",
            data={
                "actor": {"user": {"name": match.group("user")}},
                "authentication": {"protocol": "ssh", "method": match.group("method")},
                "source_endpoint": {
                    "ip": match.group("address"),
                    "port": int(match.group("port")),
                },
                "message_hash": message_hash,
            },
            **common,
        )

    match = _PAM_FAILURE.search(line)
    if match:
        return SecurityEvent(
            class_name="Authentication",
            activity_name="Logon",
            event_type="authentication_failure",
            event_id=event_id("authentication_failure"),
            status="failure",
            severity="low",
            data={
                "actor": {"user": {"name": match.group("user")}},
                "authentication": {"protocol": "pam"},
                "source_endpoint": {"ip": match.group("address") or "unknown"},
                "message_hash": message_hash,
            },
            **common,
        )

    match = _SUDO.search(line)
    if match:
        return SecurityEvent(
            class_name="Authorize Session",
            activity_name="Elevate Privileges",
            event_type="privilege_elevation",
            event_id=event_id("privilege_elevation"),
            status="success",
            data={
                "actor": {"user": {"name": match.group("actor")}},
                "target": {"user": {"name": match.group("target")}},
                "command_line": redact_text(match.group("command")),
                "message_hash": message_hash,
            },
            **common,
        )

    for pattern, event_type, activity in (
        (_SESSION_OPEN, "session_started", "Logon"),
        (_SESSION_CLOSE, "session_ended", "Logoff"),
    ):
        match = pattern.search(line)
        if match:
            return SecurityEvent(
                class_name="Authentication",
                activity_name=activity,
                event_type=event_type,
                event_id=event_id(event_type),
                status="success",
                data={
                    "actor": {"user": {"name": match.group("user")}},
                    "authentication": {"protocol": "pam"},
                    "message_hash": message_hash,
                },
                **common,
            )
    return None


class SessionCollector:
    name = "sessions"

    def __init__(
        self,
        *,
        interval_seconds: float = 5.0,
        emit_existing: bool = False,
        psutil_module: Any | None = None,
        host: str | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.emit_existing = emit_existing
        self.psutil = psutil_module or _psutil()
        self.host = host or socket.gethostname()

    @staticmethod
    def _identity(session: dict[str, Any]) -> str:
        return "|".join(
            str(session.get(name, "")) for name in ("username", "terminal", "remote_host", "started", "pid")
        )

    def _snapshot(self) -> dict[str, dict[str, Any]]:
        sessions: dict[str, dict[str, Any]] = {}
        for item in self.psutil.users():
            session = {
                "username": str(getattr(item, "name", "unknown") or "unknown"),
                "terminal": str(getattr(item, "terminal", "") or ""),
                "remote_host": str(getattr(item, "host", "") or ""),
                "started": float(getattr(item, "started", 0.0) or 0.0),
                "pid": int(getattr(item, "pid", 0) or 0),
            }
            sessions[self._identity(session)] = session
        return sessions

    def _event(self, session: dict[str, Any], *, started: bool) -> SecurityEvent:
        return SecurityEvent(
            host=self.host,
            category_name="Identity & Access Management",
            class_name="Authentication",
            activity_name="Logon" if started else "Logoff",
            event_type="session_started" if started else "session_ended",
            source="psutil.users",
            status="success",
            event_id=deterministic_event_id(self.host, self._identity(session), started),
            data={
                "actor": {"user": {"name": session["username"]}},
                "session": {
                    "terminal": session["terminal"],
                    "started_epoch": session["started"],
                    "pid": session["pid"],
                },
                "source_endpoint": {"hostname": session["remote_host"] or "local"},
            },
        )

    def collect(self, previous_state: dict[str, Any] | None) -> CollectionResult:
        current = self._snapshot()
        previous_state = previous_state or {}
        previous = previous_state.get("sessions", {})
        initialized = bool(previous_state.get("initialized"))

        if not initialized and not self.emit_existing:
            events: list[SecurityEvent] = []
        else:
            started = sorted(set(current) - set(previous))
            ended = sorted(set(previous) - set(current)) if initialized else []
            events = [self._event(current[key], started=True) for key in started]
            events.extend(self._event(previous[key], started=False) for key in ended)
        return CollectionResult(events=events, state={"initialized": True, "sessions": current})


class AuthLogCollector:
    name = "auth_logs"

    def __init__(
        self,
        paths: list[str] | None = None,
        *,
        interval_seconds: float = 2.0,
        replay_existing: bool = False,
        host: str | None = None,
    ) -> None:
        self.paths = paths if paths is not None else discover_auth_log_paths()
        self.interval_seconds = interval_seconds
        self.replay_existing = replay_existing
        self.host = host or socket.gethostname()

    def collect(self, previous_state: dict[str, Any] | None) -> CollectionResult:
        previous_state = previous_state or {}
        old_files = previous_state.get("files", {})
        new_files: dict[str, dict[str, int]] = {}
        events: list[SecurityEvent] = []

        for raw_path in self.paths:
            path = Path(raw_path)
            try:
                stat = path.stat()
            except (FileNotFoundError, PermissionError, OSError):
                continue

            prior = old_files.get(str(path), {})
            prior_inode = int(prior.get("inode", -1))
            prior_offset = int(prior.get("offset", 0))
            first_seen = not bool(prior)
            rotated = prior_inode != int(stat.st_ino) or stat.st_size < prior_offset
            if first_seen:
                offset = 0 if self.replay_existing else int(stat.st_size)
            elif rotated:
                offset = 0
            else:
                offset = prior_offset

            try:
                with path.open("rb") as fh:
                    fh.seek(offset)
                    for raw_line in fh:
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        event = parse_auth_log_line(line, host=self.host, source=str(path))
                        if event is not None:
                            events.append(event)
                    new_offset = fh.tell()
            except (PermissionError, OSError):
                new_offset = offset
            new_files[str(path)] = {"inode": int(stat.st_ino), "offset": int(new_offset)}

        return CollectionResult(events=events, state={"files": new_files})
