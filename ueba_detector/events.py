from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from .ocsf import build_ocsf_event


SCHEMA_VERSION = "1.0.0"
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"unknown", "success", "failure"}


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def deterministic_event_id(*parts: object) -> str:
    fingerprint = "\x1f".join(str(part) for part in parts)
    return str(uuid5(NAMESPACE_URL, fingerprint))


@dataclass(frozen=True)
class SecurityEvent:
    """Normalized, OCSF-aligned security event used by every collector."""

    host: str
    category_name: str
    class_name: str
    activity_name: str
    event_type: str
    source: str
    status: str = "unknown"
    severity: str = "informational"
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_timestamp)
    event_id: str = field(default_factory=lambda: str(uuid4()))
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        required = {
            "host": self.host,
            "category_name": self.category_name,
            "class_name": self.class_name,
            "activity_name": self.activity_name,
            "event_type": self.event_type,
            "source": self.source,
        }
        missing = [name for name, value in required.items() if not str(value).strip()]
        if missing:
            raise ValueError(f"Security event fields cannot be empty: {', '.join(missing)}")
        if self.status not in STATUSES:
            raise ValueError(f"Unsupported event status: {self.status}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unsupported event severity: {self.severity}")

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["ocsf"] = build_ocsf_event(row)
        return row
