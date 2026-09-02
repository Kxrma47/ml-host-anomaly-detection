from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .events import SecurityEvent, deterministic_event_id
from .redaction import redact_data


DATASET_REGISTRY = {
    "lanl": {
        "source": "https://csr.lanl.gov/data/2017/",
        "license": "LANL dataset terms; review before redistribution",
        "track": "host_events",
    },
    "optc": {
        "source": "https://github.com/FiveDirections/OpTC-data",
        "license": "public domain; distribution unlimited",
        "track": "endpoint_graph",
    },
    "unsw": {
        "source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "license": "academic use; commercial use requires author agreement",
        "track": "network",
    },
    "loghub": {
        "source": "https://github.com/logpai/loghub",
        "license": "research/academic use with citation",
        "track": "log_sequence",
    },
}


def _timestamp(value: Any, index: int) -> str:
    if value not in (None, ""):
        try:
            if isinstance(value, (int, float)) or str(value).replace(".", "", 1).isdigit():
                return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            pass
    return datetime.fromtimestamp(index, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _pseudonym(value: Any, salt: str) -> str:
    return hashlib.sha256(f"{salt}\x1f{value}".encode("utf-8")).hexdigest()[:16]


def _event(
    *,
    dataset: str,
    index: int,
    timestamp: str,
    host: str,
    event_type: str,
    class_name: str,
    activity: str,
    status: str = "unknown",
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = SecurityEvent(
        event_id=deterministic_event_id(dataset, index, timestamp, host, event_type),
        timestamp=timestamp,
        host=host,
        category_name="Imported Dataset",
        class_name=class_name,
        activity_name=activity,
        event_type=event_type,
        source=f"dataset.{dataset}",
        status=status,
        data={"dataset": dataset, **(data or {})},
    )
    return redact_data(event.to_dict())


def adapt_lanl(row: dict[str, Any], index: int, *, salt: str) -> dict[str, Any]:
    event_id = int(row.get("EventID", 0) or 0)
    mapping = {
        4624: ("authentication_success", "Authentication", "Logon", "success"),
        4625: ("authentication_failure", "Authentication", "Logon", "failure"),
        4634: ("session_ended", "Logon Session", "End", "success"),
        4647: ("session_ended", "Logon Session", "End", "success"),
        4672: ("privilege_elevation", "Authentication", "Assign Privileges", "success"),
        4688: ("process_started", "Process Activity", "Launch", "success"),
        4689: ("process_stopped", "Process Activity", "Terminate", "success"),
    }
    event_type, class_name, activity, status = mapping.get(
        event_id, ("windows_event", "Application Log", "Observe", "unknown")
    )
    timestamp = _timestamp(row.get("Time"), index)
    host = _pseudonym(row.get("Computer") or row.get("LogHost") or "unknown", salt)
    data = {
        "native_event_id": event_id,
        "actor": {"user": {"name": _pseudonym(row.get("UserName") or "unknown", salt)}},
        "process": {
            "name": row.get("ProcessName") or "unknown",
            "parent_name": row.get("ParentProcessName") or "unknown",
        },
        "source_endpoint": {"hostname": _pseudonym(row.get("Source") or "unknown", salt)},
        "label": row.get("Label"),
    }
    return _event(
        dataset="lanl",
        index=index,
        timestamp=timestamp,
        host=host,
        event_type=event_type,
        class_name=class_name,
        activity=activity,
        status=status,
        data=data,
    )


def adapt_optc(row: dict[str, Any], index: int, *, salt: str) -> dict[str, Any]:
    action = str(row.get("action") or row.get("event_type") or row.get("type") or "observe").lower()
    if "process" in action and any(word in action for word in ("start", "create", "open")):
        event_type, class_name, activity = "process_started", "Process Activity", "Launch"
    elif "flow" in action or "network" in action:
        event_type, class_name, activity = "network_activity", "Network Activity", "Open"
    elif "file" in action:
        event_type, class_name, activity = "file_activity", "File System Activity", "Observe"
    else:
        event_type, class_name, activity = "endpoint_activity", "Application Log", "Observe"
    timestamp = _timestamp(row.get("timestamp") or row.get("time"), index)
    host = _pseudonym(row.get("host") or row.get("hostname") or row.get("device") or "unknown", salt)
    return _event(
        dataset="optc",
        index=index,
        timestamp=timestamp,
        host=host,
        event_type=event_type,
        class_name=class_name,
        activity=activity,
        data={
            "native_action": action,
            "label": row.get("label") or row.get("scenario"),
            "file": {"path": row.get("path") or row.get("file") or "unknown"},
        },
    )


def adapt_unsw(row: dict[str, Any], index: int, *, salt: str) -> dict[str, Any]:
    timestamp = _timestamp(row.get("stime") or row.get("timestamp"), index)
    host = _pseudonym(row.get("srcip") or row.get("src_ip") or "unknown", salt)
    label = row.get("attack_cat") or row.get("label")
    return _event(
        dataset="unsw",
        index=index,
        timestamp=timestamp,
        host=host,
        event_type="network_activity",
        class_name="Network Activity",
        activity="Traffic",
        status="failure" if str(label).lower() not in {"", "0", "normal", "none"} else "success",
        data={
            "source_endpoint": {"ip_hash": host, "port": row.get("sport")},
            "destination_endpoint": {
                "ip_hash": _pseudonym(row.get("dstip") or row.get("dst_ip") or "unknown", salt),
                "port": row.get("dsport"),
            },
            "protocol": row.get("proto"),
            "bytes_in": row.get("dbytes"),
            "bytes_out": row.get("sbytes"),
            "label": label,
        },
    )


def adapt_loghub(row: dict[str, Any], index: int, *, salt: str) -> dict[str, Any]:
    content = str(row.get("Content") or row.get("content") or row.get("message") or "")
    timestamp = _timestamp(row.get("timestamp") or row.get("Time"), index)
    host = _pseudonym(row.get("host") or row.get("Node") or "log-source", salt)
    return _event(
        dataset="loghub",
        index=index,
        timestamp=timestamp,
        host=host,
        event_type="application_log",
        class_name="Application Log",
        activity="Observe",
        data={
            "template_id": row.get("EventId") or row.get("event_id"),
            "component": row.get("Component") or row.get("component"),
            "message": content,
            "label": row.get("Label") or row.get("label"),
        },
    )


ADAPTERS = {"lanl": adapt_lanl, "optc": adapt_optc, "unsw": adapt_unsw, "loghub": adapt_loghub}


def adapt_rows(dataset: str, rows: Iterable[dict[str, Any]], *, salt: str = "ueba-dataset") -> list[dict[str, Any]]:
    if dataset not in ADAPTERS:
        raise ValueError(f"unsupported dataset: {dataset}")
    adapter = ADAPTERS[dataset]
    return [adapter(row, index, salt=salt) for index, row in enumerate(rows)]


def read_source_rows(path: str | Path, *, fmt: str = "auto") -> list[dict[str, Any]]:
    target = Path(path)
    selected = target.suffix.lower().lstrip(".") if fmt == "auto" else fmt
    if selected == "csv":
        with target.open("r", encoding="utf-8", newline="") as stream:
            return [dict(row) for row in csv.DictReader(stream)]
    if selected == "json":
        value = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list) and all(isinstance(row, dict) for row in value):
            return value
        raise ValueError("JSON source must be an object or an array of objects")
    if selected == "jsonl":
        rows: list[dict[str, Any]] = []
        with target.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"source row {line_number} is not an object")
                rows.append(value)
        return rows
    with target.open("r", encoding="utf-8", errors="replace") as stream:
        return [{"message": line.rstrip("\n")} for line in stream if line.strip()]
