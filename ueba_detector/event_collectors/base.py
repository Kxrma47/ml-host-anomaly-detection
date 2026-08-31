from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..events import SecurityEvent


@dataclass(frozen=True)
class CollectionResult:
    events: list[SecurityEvent]
    state: dict[str, Any]


class EventCollector(Protocol):
    name: str
    interval_seconds: float

    def collect(self, previous_state: dict[str, Any] | None) -> CollectionResult:
        ...
