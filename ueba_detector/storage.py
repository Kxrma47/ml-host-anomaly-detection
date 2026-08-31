from __future__ import annotations

import json
import gzip
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def append_jsonl(path: str | Path, row: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def append_jsonl_many(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
    return rows


def jsonl_dataset_paths(path: str | Path) -> list[Path]:
    target = Path(path)
    prefix = f"{target.stem}."
    segments = sorted(
        item
        for item in target.parent.glob(f"{target.stem}.*{target.suffix}*")
        if item.name.startswith(prefix)
        and (item.name.endswith(target.suffix) or item.name.endswith(target.suffix + ".gz"))
    )
    if target.exists():
        segments.append(target)
    return segments


def read_jsonl_dataset(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    segments = jsonl_dataset_paths(path)
    if not segments:
        raise FileNotFoundError(path)
    for segment in segments:
        opener = gzip.open if segment.suffix == ".gz" else Path.open
        with opener(segment, "rt", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSONL at {segment}:{line_no}: {exc}") from exc
                if not isinstance(value, dict):
                    raise ValueError(f"JSONL row at {segment}:{line_no} is not an object")
                rows.append(value)
    return rows


class RotatingJsonlWriter:
    def __init__(
        self,
        path: str | Path,
        *,
        max_bytes: int = 0,
        retention_days: float | None = None,
        compress: bool = True,
    ) -> None:
        if max_bytes < 0:
            raise ValueError("max_bytes must not be negative")
        if retention_days is not None and retention_days <= 0:
            raise ValueError("retention_days must be positive")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.retention_days = retention_days
        self.compress = compress
        self._sequence = 0
        self._last_cleanup = 0.0

    def _rotated_path(self) -> Path:
        self._sequence += 1
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        return self.path.with_name(
            f"{self.path.stem}.{timestamp}.{os.getpid()}.{self._sequence:04d}{self.path.suffix}"
        )

    def _rotate(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        rotated = self._rotated_path()
        os.replace(self.path, rotated)
        if self.compress:
            compressed = Path(str(rotated) + ".gz")
            with rotated.open("rb") as source, gzip.open(compressed, "wb") as destination:
                while chunk := source.read(1024 * 1024):
                    destination.write(chunk)
            try:
                os.chmod(compressed, 0o600)
            except OSError:
                pass
            rotated.unlink()

    def _cleanup(self, *, force: bool = False) -> None:
        if self.retention_days is None:
            return
        now = time.time()
        if not force and now - self._last_cleanup < 3600:
            return
        self._last_cleanup = now
        cutoff = now - self.retention_days * 86400.0
        for segment in jsonl_dataset_paths(self.path):
            if segment == self.path:
                continue
            try:
                if segment.stat().st_mtime < cutoff:
                    segment.unlink()
            except FileNotFoundError:
                continue

    def write_many(self, rows: Iterable[dict[str, Any]]) -> int:
        encoded = [
            (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            for row in rows
        ]
        if not encoded:
            return 0
        payload_size = sum(len(item) for item in encoded)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        current_size = self.path.stat().st_size if self.path.exists() else 0
        if self.max_bytes and current_size and current_size + payload_size > self.max_bytes:
            self._rotate()
        with self.path.open("ab") as stream:
            for item in encoded:
                stream.write(item)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._cleanup()
        return len(encoded)

    def write(self, row: dict[str, Any]) -> None:
        self.write_many([row])

    def enforce_retention(self) -> None:
        self._cleanup(force=True)
