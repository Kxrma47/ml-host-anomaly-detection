from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import adapt_optc
from .research_graph_build import build_provenance_graph


MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_EVENTS = 10_000
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PRIVATE_KEYS = ("path", "name", "line", "user", "sid", "ip", "token", "secret", "pass", "url", "domain", "hash")


def _check_private_values(row: dict[str, Any], event: dict[str, Any]) -> None:
    encoded = json.dumps(event, sort_keys=True)
    values = [row.get(key) for key in ("hostname", "principal", "actorID", "objectID", "id")]
    properties = row.get("properties")
    if isinstance(properties, dict):
        values.extend(
            value for key, value in properties.items()
            if any(marker in str(key).lower() for marker in _PRIVATE_KEYS)
        )
    for value in values:
        if isinstance(value, str) and len(value) >= 8 and value in encoded:
            raise ValueError("a raw source identity or sensitive property survived normalization")


def run_optc_prefix_pilot(
    path: str | Path, *, expected_sha256: str, salt: str, ingested_at: str,
    max_events: int = MAX_EVENTS, max_source_bytes: int = MAX_SOURCE_BYTES,
) -> dict[str, Any]:
    """Check one local compressed blob and report only aggregate first-record results.

    The blob may be a byte-range prefix. Its hash verifies those exact bytes, not
    the complete upstream archive or its labels.
    """
    digest = expected_sha256.lower()
    if not _SHA256.fullmatch(digest):
        raise ValueError("expected_sha256 must be a SHA-256 hex digest")
    if len(salt) < 16:
        raise ValueError("salt must contain at least 16 characters")
    if not 1 <= max_events <= MAX_EVENTS:
        raise ValueError("max_events must be between 1 and 10000")
    if max_source_bytes < 1:
        raise ValueError("max_source_bytes must be positive")

    with Path(path).open("rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= max_source_bytes:
            raise ValueError("source must be a nonempty regular file within the pilot size limit")
        hasher = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError("local source SHA-256 mismatch")
        source.seek(0)

        object_counts: Counter[str] = Counter()
        event_counts: Counter[str] = Counter()

        def normalized_events():
            with gzip.GzipFile(fileobj=source, mode="rb") as compressed:
                for index in range(max_events):
                    try:
                        line = compressed.readline(MAX_LINE_BYTES + 1)
                    except (EOFError, gzip.BadGzipFile, OSError) as exc:
                        raise ValueError("compressed source ended or failed inside the pilot sample") from exc
                    if not line:
                        break
                    if len(line) > MAX_LINE_BYTES:
                        raise ValueError("source record exceeds the pilot line limit")
                    if not line.endswith(b"\n"):
                        raise ValueError("source record is incomplete")
                    try:
                        row = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise ValueError("source record is not valid JSON") from exc
                    if not isinstance(row, dict):
                        raise ValueError("source record must be an object")
                    event = adapt_optc(row, index, salt=salt)
                    _check_private_values(row, event)
                    object_counts[event["data"]["native_object"]] += 1
                    event_counts[event["event_type"]] += 1
                    yield event

        graph, stats = build_provenance_graph(
            normalized_events(), dataset_id="optc_prefix_pilot",
            ingested_at=ingested_at, salt=salt, max_events=max_events,
        )

    return {
        "scope": "first_records_of_checksum_verified_local_blob",
        "full_dataset_verified": False,
        "labels_verified": False,
        "source_bytes": metadata.st_size,
        "source_sha256": digest,
        "max_events": max_events,
        "stats": stats,
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
        "object_counts": dict(sorted(object_counts.items())),
        "event_type_counts": dict(sorted(event_counts.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded, aggregate-only OpTC graph compatibility pilot")
    parser.add_argument("--input", required=True, help="local gzip file or byte-range prefix")
    parser.add_argument("--expected-sha256", required=True, help="SHA-256 of these exact local bytes")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS)
    args = parser.parse_args()
    salt = os.environ.get("HOSTWATCH_PILOT_SALT", "")
    if not salt:
        parser.error("HOSTWATCH_PILOT_SALT must be set to a private random value")
    report = run_optc_prefix_pilot(
        args.input, expected_sha256=args.expected_sha256, salt=salt,
        ingested_at=datetime.now(timezone.utc).isoformat(), max_events=args.max_events,
    )
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
