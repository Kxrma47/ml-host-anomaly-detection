from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from . import __version__


OCSF_VERSION = "1.8.0"

# OCSF class UIDs are category UID * 1000 + class-local UID.
CLASSIFICATIONS: dict[str, tuple[int, str, int, str]] = {
    "Process Activity": (1, "System Activity", 1007, "Process Activity"),
    "File System Activity": (1, "System Activity", 1001, "File System Activity"),
    "Authentication": (3, "Identity & Access Management", 3002, "Authentication"),
    "Logon Session": (3, "Identity & Access Management", 3002, "Authentication"),
    "Network Activity": (4, "Network Activity", 4001, "Network Activity"),
    "Software Inventory Info": (5, "Discovery", 5020, "Software Inventory Info"),
    "Device Config State": (5, "Discovery", 5001, "Device Inventory Info"),
    "Device Inventory Info": (5, "Discovery", 5001, "Device Inventory Info"),
    "Security Finding": (2, "Findings", 2004, "Detection Finding"),
    "Detection Finding": (2, "Findings", 2004, "Detection Finding"),
}

SEVERITY_IDS = {
    "unknown": 0,
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
    "fatal": 6,
}
STATUS_IDS = {"unknown": 0, "success": 1, "failure": 2}


def _epoch_milliseconds(value: Any) -> int:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except (TypeError, ValueError, OverflowError, OSError):
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _classification(row: dict[str, Any]) -> tuple[int, str, int, str]:
    return CLASSIFICATIONS.get(
        str(row.get("class_name") or ""),
        (0, "Uncategorized", 0, "Base Event"),
    )


def _activity(row: dict[str, Any], class_uid: int) -> tuple[int, str]:
    name = str(row.get("activity_name") or "Other")
    normalized = name.lower()
    mappings = {
        1007: {"launch": 1, "terminate": 2, "open": 3, "inject": 4, "set user id": 5},
        3002: {"logon": 1, "logoff": 2, "end": 2},
        4001: {
            "open": 1,
            "close": 2,
            "reset": 3,
            "fail": 4,
            "refuse": 5,
            "traffic": 6,
            "listen": 7,
        },
    }
    captions = {
        1007: {1: "Launch", 2: "Terminate", 3: "Open", 4: "Inject", 5: "Set User ID"},
        3002: {1: "Logon", 2: "Logoff"},
        4001: {1: "Open", 2: "Close", 3: "Reset", 4: "Fail", 5: "Refuse", 6: "Traffic", 7: "Listen"},
    }
    if class_uid in {5001, 5020}:
        return 2, "Collect"
    if class_uid == 2004:
        return 1, "Create"
    activity_id = mappings.get(class_uid, {}).get(normalized, 99)
    return activity_id, captions.get(class_uid, {}).get(activity_id, name)


def _process_object(data: dict[str, Any]) -> dict[str, Any]:
    source = data.get("process") if isinstance(data.get("process"), dict) else {}
    process: dict[str, Any] = {
        "name": str(source.get("name") or "unknown"),
    }
    if source.get("pid") is not None:
        process["pid"] = source["pid"]
    if source.get("parent_pid") is not None:
        process["parent_process"] = {"pid": source["parent_pid"]}
    if source.get("executable"):
        process["file"] = {"path": source["executable"]}
    command_line = source.get("command_line")
    if isinstance(command_line, list):
        process["cmd_line"] = " ".join(str(value) for value in command_line)
    elif command_line:
        process["cmd_line"] = str(command_line)
    return process


def _class_attributes(
    row: dict[str, Any],
    *,
    class_uid: int,
    event_time: int,
) -> dict[str, Any]:
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    host = str(row.get("host") or "unknown")
    if class_uid == 1007:
        attributes: dict[str, Any] = {"process": _process_object(data)}
        actor = data.get("actor")
        if isinstance(actor, dict):
            attributes["actor"] = deepcopy(actor)
        return attributes
    if class_uid == 1001:
        source = data.get("file") if isinstance(data.get("file"), dict) else {}
        path = source.get("path") or data.get("path") or "unknown"
        return {"file": {"path": str(path)}}
    if class_uid == 3002:
        actor = data.get("actor") if isinstance(data.get("actor"), dict) else {}
        user = data.get("user") if isinstance(data.get("user"), dict) else actor.get("user")
        if not isinstance(user, dict):
            user = {"name": "unknown"}
        destination = data.get("destination_endpoint") or data.get("dst_endpoint")
        if not isinstance(destination, dict):
            destination = {"hostname": host}
        return {"user": deepcopy(user), "dst_endpoint": deepcopy(destination)}
    if class_uid == 4001:
        attributes = {}
        source = data.get("source_endpoint") or data.get("src_endpoint")
        destination = data.get("destination_endpoint") or data.get("dst_endpoint")
        if isinstance(source, dict):
            attributes["src_endpoint"] = _network_endpoint(source)
        if isinstance(destination, dict):
            attributes["dst_endpoint"] = _network_endpoint(destination)
        if not attributes:
            attributes["src_endpoint"] = {"hostname": host}
        return attributes
    if class_uid == 5020:
        package = data.get("package") if isinstance(data.get("package"), dict) else data
        software: dict[str, Any] = {"name": str(package.get("name") or "unknown")}
        if package.get("version") not in (None, ""):
            software["version"] = str(package["version"])
        return {"device": {"hostname": host}, "package": software}
    if class_uid == 5001:
        return {"device": {"hostname": host}}
    if class_uid == 2004:
        return {
            "finding_info": {
                "uid": str(row.get("event_id") or "unknown"),
                "title": str(row.get("activity_name") or row.get("event_type") or "Finding"),
                "created_time": event_time,
            },
            "is_alert": True,
        }
    return {}


def _network_endpoint(source: dict[str, Any]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {}
    if source.get("ip"):
        endpoint["ip"] = str(source["ip"])
    if source.get("hostname"):
        endpoint["hostname"] = str(source["hostname"])
    elif source.get("ip_hash"):
        endpoint["hostname"] = str(source["ip_hash"])
    if source.get("port") not in (None, ""):
        try:
            endpoint["port"] = int(source["port"])
        except (TypeError, ValueError):
            pass
    return endpoint


def build_ocsf_event(row: dict[str, Any]) -> dict[str, Any]:
    """Build a normalized OCSF envelope while preserving the legacy record outside it."""
    category_uid, category_name, class_uid, class_name = _classification(row)
    activity_id, activity_name = _activity(row, class_uid)
    event_time = _epoch_milliseconds(row.get("timestamp"))
    status = str(row.get("status") or "unknown").lower()
    severity = str(row.get("severity") or "informational").lower()
    if class_uid == 2004:
        status_id, status_name = 1, "New"
    else:
        status_id, status_name = STATUS_IDS.get(status, 99), status.title()
    envelope: dict[str, Any] = {
        "activity_id": activity_id,
        "activity_name": activity_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "class_uid": class_uid,
        "class_name": class_name,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": str(row.get("event_id") or "unknown"),
            "logged_time": event_time,
            "product": {
                "name": "ueba-detector",
                "vendor_name": "Kxrma47",
                "version": __version__,
            },
        },
        "severity_id": SEVERITY_IDS.get(severity, 99),
        "severity": severity.title(),
        "status_id": status_id,
        "status": status_name,
        "time": event_time,
        "type_uid": class_uid * 100 + activity_id,
        "unmapped": {
            "legacy_category_name": row.get("category_name"),
            "legacy_class_name": row.get("class_name"),
            "legacy_event_type": row.get("event_type"),
            "legacy_source": row.get("source"),
        },
    }
    envelope.update(_class_attributes(row, class_uid=class_uid, event_time=event_time))
    return envelope


def upgrade_event_record(row: dict[str, Any]) -> dict[str, Any]:
    """Add an OCSF envelope to legacy data without mutating the input record."""
    upgraded = deepcopy(row)
    if not isinstance(upgraded.get("ocsf"), dict):
        upgraded["ocsf"] = build_ocsf_event(upgraded)
    return upgraded


def validate_ocsf_core(event: Any) -> list[str]:
    """Validate deterministic OCSF core invariants used by the release gate.

    This does not replace validation by the upstream OCSF schema compiler/toolkit.
    """
    if not isinstance(event, dict):
        return ["OCSF event must be an object"]
    issues: list[str] = []
    integer_fields = (
        "activity_id",
        "category_uid",
        "class_uid",
        "severity_id",
        "status_id",
        "time",
        "type_uid",
    )
    for field in integer_fields:
        if not isinstance(event.get(field), int):
            issues.append(f"{field} must be an integer")
    if isinstance(event.get("time"), int) and event["time"] <= 0:
        issues.append("time must be a positive UTC epoch millisecond value")
    for field in ("activity_name", "category_name", "class_name"):
        if not str(event.get(field) or "").strip():
            issues.append(f"{field} is required")
    metadata = event.get("metadata")
    if not isinstance(metadata, dict):
        issues.append("metadata must be an object")
    else:
        if metadata.get("version") != OCSF_VERSION:
            issues.append(f"metadata.version must be {OCSF_VERSION}")
        if not str(metadata.get("uid") or "").strip():
            issues.append("metadata.uid is required")
        if metadata.get("logged_time") != event.get("time"):
            issues.append("metadata.logged_time must equal time")
        product = metadata.get("product")
        if not isinstance(product, dict) or not str(product.get("name") or "").strip():
            issues.append("metadata.product.name is required")
    if isinstance(event.get("class_uid"), int) and isinstance(event.get("activity_id"), int):
        expected = event["class_uid"] * 100 + event["activity_id"]
        if event.get("type_uid") != expected:
            issues.append(f"type_uid must equal {expected}")
    known_classes = {
        1001: (1, "File System Activity"),
        1007: (1, "Process Activity"),
        2004: (2, "Detection Finding"),
        3002: (3, "Authentication"),
        4001: (4, "Network Activity"),
        5001: (5, "Device Inventory Info"),
        5020: (5, "Software Inventory Info"),
    }
    expected_class = known_classes.get(event.get("class_uid"))
    if expected_class:
        expected_category, expected_name = expected_class
        if event.get("category_uid") != expected_category:
            issues.append(f"category_uid must be {expected_category} for class_uid {event.get('class_uid')}")
        if event.get("class_name") != expected_name:
            issues.append(f"class_name must be {expected_name} for class_uid {event.get('class_uid')}")
    required_by_class = {
        1001: "file",
        1007: "process",
        3002: "user",
        5001: "device",
        5020: "device",
        2004: "finding_info",
    }
    required = required_by_class.get(event.get("class_uid"))
    if required and not isinstance(event.get(required), dict):
        issues.append(f"{required} is required for class_uid {event.get('class_uid')}")
    if event.get("class_uid") == 3002 and not any(
        isinstance(event.get(field), dict) for field in ("service", "dst_endpoint")
    ):
        issues.append("Authentication requires service or dst_endpoint")
    if event.get("class_uid") == 4001 and not any(
        isinstance(event.get(field), dict) for field in ("src_endpoint", "dst_endpoint")
    ):
        issues.append("Network Activity requires src_endpoint or dst_endpoint")
    return issues
