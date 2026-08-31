from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class JsonStateStore:
    """Private, atomic state storage for restart-safe event collectors."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"state_version": 1, "collectors": {}, "schedule": {}, "agent": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read agent state from {self.path}: {exc}") from exc
        if not isinstance(value, dict) or value.get("state_version") != 1:
            raise ValueError(f"Unsupported agent state format in {self.path}")
        value.setdefault("collectors", {})
        value.setdefault("schedule", {})
        value.setdefault("agent", {})
        return value

    def save(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            delete=False,
        )
        temporary = Path(handle.name)
        try:
            with handle:
                json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()
