from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .storage import jsonl_dataset_paths


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(directory: str | Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=directory,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def git_dirty(directory: str | Path | None = None) -> bool | None:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=directory,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return bool(result.stdout.strip())


def build_provenance(
    *,
    dataset_paths: Iterable[str | Path] = (),
    parameters: dict[str, Any] | None = None,
    working_directory: str | Path | None = None,
) -> dict[str, Any]:
    datasets = []
    for value in dataset_paths:
        path = Path(value)
        segments = jsonl_dataset_paths(path) or [path]
        for segment in segments:
            datasets.append(
                {
                    "path": str(segment),
                    "sha256": sha256_file(segment) if segment.exists() and segment.is_file() else None,
                    "bytes": segment.stat().st_size if segment.exists() and segment.is_file() else None,
                }
            )
    return {
        "schema_version": "1.0.0",
        "created_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "package_version": __version__,
        "git_revision": git_revision(working_directory),
        "git_dirty": git_dirty(working_directory),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "datasets": datasets,
        "parameters": parameters or {},
    }


def write_provenance(path: str | Path, provenance: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_provenance(provenance: dict[str, Any]) -> dict[str, Any]:
    """Verify that every recorded dataset still matches its size and SHA-256 digest."""
    results: list[dict[str, Any]] = []
    for item in provenance.get("datasets", []):
        if not isinstance(item, dict):
            results.append({"path": None, "valid": False, "reason": "invalid manifest entry"})
            continue
        path = Path(str(item.get("path") or ""))
        if not path.is_file():
            results.append({"path": str(path), "valid": False, "reason": "missing file"})
            continue
        actual_size = path.stat().st_size
        actual_hash = sha256_file(path)
        expected_size = item.get("bytes")
        expected_hash = item.get("sha256")
        valid = actual_size == expected_size and actual_hash == expected_hash
        results.append(
            {
                "path": str(path),
                "valid": valid,
                "reason": "match" if valid else "size or SHA-256 mismatch",
                "expected_bytes": expected_size,
                "actual_bytes": actual_size,
                "expected_sha256": expected_hash,
                "actual_sha256": actual_hash,
            }
        )
    return {
        "valid": bool(results) and all(item["valid"] for item in results),
        "datasets": len(results),
        "results": results,
    }
