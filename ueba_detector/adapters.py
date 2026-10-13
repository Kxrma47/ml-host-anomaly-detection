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
    "tc_cdm": {
        "source": "https://github.com/darpa-i2o/Transparent-Computing",
        "license": "public domain; released as-is by DARPA",
        "track": "endpoint_provenance",
    },
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


def _union_value(value: Any) -> Any:
    """Unwrap the single-key objects used by Avro's JSON union encoding."""
    while isinstance(value, dict) and len(value) == 1:
        value = next(iter(value.values()))
    return value


def _cdm_datum(row: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    datum = row.get("datum", row)
    if not isinstance(datum, dict) or len(datum) != 1:
        return None
    qualified_name, payload = next(iter(datum.items()))
    if not isinstance(payload, dict):
        return None
    return qualified_name.rsplit(".", 1)[-1], payload


def _cdm_uuid(value: Any) -> str | None:
    unwrapped = _union_value(value)
    if unwrapped in (None, ""):
        return None
    return str(unwrapped)


def _cdm_timestamp(value: Any, index: int) -> str:
    try:
        nanos = int(_union_value(value))
        return _timestamp(nanos / 1_000_000_000, index)
    except (TypeError, ValueError, OverflowError):
        return _timestamp(None, index)


def _cdm_event_semantics(native_type: str) -> tuple[str, str, str]:
    action = native_type.upper().removeprefix("EVENT_")
    if action in {"EXECUTE", "FORK", "CLONE", "CREATE_PROCESS"}:
        return "process_started", "Process Activity", "Launch"
    if action in {"EXIT", "TERMINATE", "END"}:
        return "process_stopped", "Process Activity", "Terminate"
    if action in {"CONNECT", "ACCEPT", "SENDMSG", "RECVMSG", "SENDTO", "RECVFROM"}:
        return "network_activity", "Network Activity", action.title()
    if action in {"OPEN", "CREATE_OBJECT", "READ", "WRITE", "RENAME", "UNLINK", "MODIFY_FILE_ATTRIBUTES"}:
        return "file_activity", "File System Activity", action.title().replace("_", " ")
    if "PRINCIPAL" in action or "LOGIN" in action:
        return "authentication_activity", "Authentication", action.title().replace("_", " ")
    return "endpoint_activity", "Application Log", action.title().replace("_", " ")


def adapt_tc_cdm_rows(rows: Iterable[dict[str, Any]], *, salt: str) -> list[dict[str, Any]]:
    """Normalize DARPA TC CDM18/CDM20 JSON envelopes without retaining raw identities."""
    materialized = list(rows)
    objects: dict[str, dict[str, Any]] = {}
    for row in materialized:
        datum = _cdm_datum(row)
        if datum is None:
            continue
        kind, payload = datum
        uuid = _cdm_uuid(payload.get("uuid"))
        if not uuid or kind not in {"Subject", "FileObject", "NetFlowObject"}:
            continue
        metadata: dict[str, Any] = {"kind": kind}
        host_id = _cdm_uuid(payload.get("hostId"))
        if host_id:
            metadata["host_id"] = host_id
        objects[uuid] = metadata

    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(materialized):
        datum = _cdm_datum(row)
        if datum is None or datum[0] != "Event":
            continue
        payload = datum[1]
        native_type = str(_union_value(payload.get("type")) or "EVENT_UNKNOWN")
        event_type, class_name, activity = _cdm_event_semantics(native_type)
        subject_uuid = _cdm_uuid(payload.get("subject"))
        object_uuid = _cdm_uuid(payload.get("predicateObject"))
        subject = objects.get(subject_uuid or "", {"kind": "Subject"})
        target = objects.get(object_uuid or "", {"kind": "Unknown"})
        host_native = _cdm_uuid(payload.get("hostId")) or subject.get("host_id") or "dataset-host"
        data: dict[str, Any] = {
            "native_type": native_type,
            "subject": {
                "id": _pseudonym(subject_uuid or "unknown", salt),
                "kind": subject.get("kind", "Subject"),
            },
            "object": {
                "id": _pseudonym(object_uuid or "unknown", salt),
                "kind": target.get("kind", "Unknown"),
            },
        }
        normalized.append(
            _event(
                dataset="tc_cdm",
                index=index,
                timestamp=_cdm_timestamp(payload.get("timestampNanos"), index),
                host=_pseudonym(host_native, salt),
                event_type=event_type,
                class_name=class_name,
                activity=activity,
                status="success",
                data=data,
            )
        )
    return normalized


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
    native_object = str(row.get("object") or row.get("object_type") or "endpoint").upper()
    native_action = str(row.get("action") or row.get("event_type") or row.get("type") or "observe").upper()
    semantic_action = f"{native_object}_{native_action}".lower()
    if native_object == "PROCESS" and native_action in {"CREATE", "START", "OPEN"}:
        event_type, class_name, activity = "process_started", "Process Activity", "Launch"
    elif native_object == "PROCESS" and native_action in {"TERMINATE", "STOP", "EXIT"}:
        event_type, class_name, activity = "process_stopped", "Process Activity", "Terminate"
    elif native_object in {"FLOW", "NETWORK", "SOCKET"}:
        event_type, class_name, activity = "network_activity", "Network Activity", "Open"
    elif native_object == "FILE":
        event_type, class_name, activity = "file_activity", "File System Activity", "Observe"
    else:
        event_type, class_name, activity = "endpoint_activity", "Application Log", "Observe"

    timestamp_value = row.get("timestamp_ms") or row.get("timestamp") or row.get("time")
    try:
        numeric_timestamp = float(timestamp_value)
        if numeric_timestamp >= 100_000_000_000:
            numeric_timestamp /= 1000.0
        timestamp = _timestamp(numeric_timestamp, index)
    except (TypeError, ValueError):
        timestamp = _timestamp(timestamp_value, index)

    host_native = row.get("host") or row.get("hostname") or row.get("device") or "unknown"
    host = _pseudonym(host_native, salt)
    properties = row.get("properties") if isinstance(row.get("properties"), dict) else {}
    principal = row.get("principal") or properties.get("user")
    actor_id = row.get("actorID") or row.get("actor_id")
    object_id = row.get("objectID") or row.get("object_id") or row.get("id")
    path_value = properties.get("file_path") or properties.get("image_path") or properties.get("path")
    suffix = Path(str(path_value).replace("\\", "/")).suffix.lower() if path_value else ""
    path_category = "executable" if suffix in {".exe", ".dll", ".com", ".bat", ".ps1"} else (
        "document" if suffix in {".txt", ".doc", ".docx", ".pdf", ".csv"} else "other"
    )
    return _event(
        dataset="optc",
        index=index,
        timestamp=timestamp,
        host=host,
        event_type=event_type,
        class_name=class_name,
        activity=activity,
        data={
            "native_object": native_object.lower(),
            "native_action": native_action.lower(),
            "semantic_action": semantic_action,
            "label": row.get("label") or row.get("scenario"),
            "actor": {
                "id": _pseudonym(actor_id, salt) if actor_id not in (None, "") else None,
                "principal": _pseudonym(principal, salt) if principal not in (None, "") else None,
            },
            "object": {
                "id": _pseudonym(object_id, salt) if object_id not in (None, "") else None,
                "kind": native_object.title(),
            },
            "process": {
                "pid_present": row.get("pid") not in (None, -1, "-1"),
                "parent_pid_present": row.get("ppid") not in (None, -1, "-1"),
            },
            "path_category": path_category,
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
    if dataset == "tc_cdm":
        return adapt_tc_cdm_rows(rows, salt=salt)
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
