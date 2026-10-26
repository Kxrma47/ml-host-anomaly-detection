from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .adapters import adapt_tc_cdm_rows
from .research_graph_build import build_provenance_graph


MAX_COMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 16 * 1024 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_SOURCE_ROWS = 10_000
MAX_LINE_BYTES = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")


def run_tc_archive_pilot(
    path: str | Path, *, expected_sha256: str, salt: str, ingested_at: str,
    max_source_rows: int = MAX_SOURCE_ROWS,
    max_compressed_bytes: int = MAX_COMPRESSED_BYTES,
    max_expanded_bytes: int = MAX_EXPANDED_BYTES,
) -> dict[str, Any]:
    """Verify one complete tar.gz archive, then graph a bounded first-record sample."""
    digest = expected_sha256.lower()
    if not _SHA256.fullmatch(digest):
        raise ValueError("expected_sha256 must be a SHA-256 hex digest")
    if len(salt) < 16:
        raise ValueError("salt must contain at least 16 characters")
    if not 1 <= max_source_rows <= MAX_SOURCE_ROWS:
        raise ValueError("max_source_rows must be between 1 and 10000")
    if max_compressed_bytes < 1 or max_expanded_bytes < 1:
        raise ValueError("archive size limits must be positive")

    with Path(path).open("rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= max_compressed_bytes:
            raise ValueError("source must be a nonempty regular file within the compressed size limit")
        hasher = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError("complete archive SHA-256 mismatch")
        source.seek(0)

        source_rows: list[dict[str, Any]] = []
        member_count = 0
        regular_count = 0
        declared_bytes = 0
        seen: set[str] = set()
        try:
            with gzip.GzipFile(fileobj=source, mode="rb") as compressed:
                with tarfile.open(fileobj=compressed, mode="r|") as archive:
                    for member in archive:
                        member_count += 1
                        name = PurePosixPath(member.name)
                        if (member_count > MAX_MEMBERS or name.is_absolute() or ".." in name.parts
                                or member.name in seen or "\\" in member.name):
                            raise ValueError("archive has unsafe, duplicate, or excessive members")
                        seen.add(member.name)
                        if member.isdir():
                            continue
                        if not member.isfile() or member.size < 0:
                            raise ValueError("archive contains an unsupported member type")
                        regular_count += 1
                        declared_bytes += member.size
                        if declared_bytes > max_expanded_bytes:
                            raise ValueError("archive exceeds the expanded size limit")
                        if len(source_rows) >= max_source_rows:
                            continue
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise ValueError("archive member could not be read")
                        while len(source_rows) < max_source_rows:
                            line = stream.readline(MAX_LINE_BYTES + 1)
                            if not line:
                                break
                            if len(line) > MAX_LINE_BYTES:
                                raise ValueError("source record exceeds the line limit")
                            if not line.endswith(b"\n"):
                                raise ValueError("source record is incomplete")
                            try:
                                row = json.loads(line)
                            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                                raise ValueError("source record is not valid JSON") from exc
                            if not isinstance(row, dict):
                                raise ValueError("source record must be an object")
                            source_rows.append(row)
                for _ in iter(lambda: compressed.read(1024 * 1024), b""):
                    if compressed.tell() > max_expanded_bytes + MAX_MEMBERS * 1024:
                        raise ValueError("archive exceeds the expanded size limit")
        except (tarfile.TarError, gzip.BadGzipFile, EOFError, OSError) as exc:
            raise ValueError("archive is incomplete or unreadable") from exc

    if not regular_count or not source_rows:
        raise ValueError("archive has no readable JSON records")
    events = adapt_tc_cdm_rows(source_rows, salt=salt)
    graph, stats = build_provenance_graph(
        events, dataset_id="tc_archive_pilot", ingested_at=ingested_at,
        salt=salt, max_events=MAX_SOURCE_ROWS,
    )
    return {
        "scope": "first_records_of_complete_verified_archive",
        "full_archive_verified": True,
        "full_dataset_verified": False,
        "labels_verified": False,
        "archive_bytes": metadata.st_size,
        "archive_sha256": digest,
        "archive_member_count": member_count,
        "archive_regular_file_count": regular_count,
        "declared_uncompressed_bytes": declared_bytes,
        "sampled_source_rows": len(source_rows),
        "stats": stats,
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate-only TC archive compatibility pilot")
    parser.add_argument("--input", required=True, help="complete local TC JSON tar.gz archive")
    parser.add_argument("--expected-sha256", required=True, help="SHA-256 of the complete archive")
    parser.add_argument("--max-source-rows", type=int, default=MAX_SOURCE_ROWS)
    args = parser.parse_args()
    salt = os.environ.get("HOSTWATCH_PILOT_SALT", "")
    if not salt:
        parser.error("HOSTWATCH_PILOT_SALT must be set to a private random value")
    report = run_tc_archive_pilot(
        args.input, expected_sha256=args.expected_sha256, salt=salt,
        ingested_at=datetime.now(timezone.utc).isoformat(), max_source_rows=args.max_source_rows,
    )
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
