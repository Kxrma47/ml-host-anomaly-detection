from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import UUID

from .ocsf import OCSF_VERSION
from .research_graph import GRAPH_SCHEMA_VERSION, validate_provenance_graph


_TOKEN = re.compile(r"[0-9a-f]{16}")
_DATASET = re.compile(r"[A-Za-z0-9_-]{1,64}")
_SOURCES = {"dataset.tc_cdm", "dataset.optc"}
_PATH_CATEGORIES = {"executable", "document", "other"}
_EVENT_CLASSES = {
    "process_started": 1007,
    "process_stopped": 1007,
    "file_activity": 1001,
    "network_activity": 4001,
    "authentication_activity": 3002,
}


def _time(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("event time must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("event time must be a timezone-aware timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("event time must be a timezone-aware timestamp")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _token(value: Any) -> str | None:
    return value if isinstance(value, str) and _TOKEN.fullmatch(value) else None


def _id(salt: str, kind: str, *parts: str) -> str:
    message = "\x1f".join((kind, *parts)).encode("utf-8")
    return f"{kind}:{hmac.new(salt.encode('utf-8'), message, hashlib.sha256).hexdigest()[:32]}"


def _quality(*, missing: list[str] | None = None, reordered: bool = False) -> dict[str, Any]:
    return {
        "missing_fields": sorted(set(missing or [])),
        "delayed": False,
        "reordered": reordered,
        "duplicate": False,
        "collector_degraded": False,
    }


def _relation(event: dict[str, Any], event_id: str) -> tuple[str, str, str, str, str, list[str]] | None:
    data = event["data"]
    source = event["source"]
    subject = data.get("subject") if source == "dataset.tc_cdm" else data.get("actor")
    obj = data.get("object")
    subject = subject if isinstance(subject, dict) else {}
    obj = obj if isinstance(obj, dict) else {}
    actor = _token(subject.get("id"))
    target = _token(obj.get("id"))
    kind = str(obj.get("kind") or "").lower()
    action = str(data.get("native_type") or data.get("native_action") or "").upper()
    event_type = event["event_type"]
    missing: list[str] = []

    if event_type == "process_started":
        if source == "dataset.tc_cdm" and kind == "fileobject" and target:
            if not actor:
                missing.append("actor.id")
            return "executed", "process", actor or event_id, "executable", target, missing
        if actor and target and actor != target and kind in {"process", "subject"}:
            return "spawned", "process", actor, "process", target, missing
        if actor and target and actor == target:
            return "started", "host", "host", "process", actor, missing
        if not actor and not target:
            missing.extend(("actor.id", "object.id"))
        elif not target:
            missing.append("object.id")
        elif not actor:
            missing.append("actor.id")
        return "started", "host", "host", "process", actor or target or event_id, missing

    if event_type == "process_stopped":
        process = target if kind in {"process", "subject"} else actor
        if not process:
            missing.append("actor.id")
        return "stopped", "process", process or event_id, "host", "host", missing

    if event_type == "file_activity":
        operation = action.removeprefix("EVENT_")
        relation = {"READ": "read", "WRITE": "wrote", "RENAME": "renamed"}.get(operation)
        if relation is None:
            return None
        if not actor:
            missing.append("actor.id")
        if not target:
            missing.append("object.id")
        return relation, "process", actor or event_id, "file", target or event_id, missing

    if event_type == "network_activity":
        if not actor:
            missing.append("actor.id")
        if not target:
            missing.append("object.id")
        relation = "accepted" if action in {"EVENT_ACCEPT", "EVENT_RECVMSG", "EVENT_RECVFROM", "ACCEPT"} else "connected"
        return relation, "process", actor or event_id, "socket_endpoint", target or event_id, missing

    if event_type == "authentication_activity":
        principal = _token(subject.get("principal"))
        if not principal:
            missing.append("actor.principal")
        return "authenticated", "user", principal or event_id, "host", "host", missing

    return None


def build_provenance_graph(
    events: Iterable[dict[str, Any]], *, dataset_id: str, ingested_at: str, salt: str,
    max_events: int = 10_000,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Build a bounded pilot graph from normalized TC or OpTC events.

    The caller supplies a secret salt and a fixed ingest time. Unsupported event
    semantics are counted instead of being assigned a misleading relationship.
    """
    if not _DATASET.fullmatch(dataset_id):
        raise ValueError("dataset_id must be a short public identifier")
    if len(salt) < 16:
        raise ValueError("salt must contain at least 16 characters")
    if max_events < 1:
        raise ValueError("max_events must be positive")
    ingest_time = _time(ingested_at)
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    edge_by_event: dict[str, str] = {}
    seen: dict[str, str] = {}
    latest_by_host: dict[str, str] = {}
    stats = {"input_events": 0, "accepted_events": 0, "unsupported_events": 0, "duplicate_events": 0, "reordered_events": 0, "missing_identity_events": 0}

    def add_node(kind: str, host: str, identity: str, event_time: str) -> str:
        node_id = _id(salt, kind, dataset_id, host, identity)
        existing = nodes.get(node_id)
        if existing is None:
            nodes[node_id] = {
                "id": node_id,
                "type": kind,
                "identity_scope": "host",
                "first_seen": event_time,
                "last_seen": event_time,
                "attributes": {},
                "data_quality": _quality(),
            }
        else:
            existing["first_seen"] = min(existing["first_seen"], event_time)
            existing["last_seen"] = max(existing["last_seen"], event_time)
        return node_id

    for event in events:
        stats["input_events"] += 1
        if stats["input_events"] > max_events:
            raise ValueError("pilot graph event limit exceeded")
        if not isinstance(event, dict):
            raise ValueError("event must be a normalized object")
        event_id = event.get("event_id")
        try:
            UUID(str(event_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("event_id must be a UUID") from exc
        host = _token(event.get("host"))
        if not host:
            raise ValueError("host must be a pseudonymous token")
        if event.get("source") not in _SOURCES:
            raise ValueError("unsupported normalized source")
        if not isinstance(event.get("data"), dict):
            raise ValueError("event data must be an object")
        event_time = _time(event.get("timestamp"))
        ocsf = event.get("ocsf")
        if not isinstance(ocsf, dict) or not isinstance(ocsf.get("metadata"), dict):
            raise ValueError("OCSF metadata is required")
        if ocsf["metadata"].get("version") != OCSF_VERSION or ocsf["metadata"].get("uid") != event_id:
            raise ValueError("OCSF metadata does not match the normalized event")
        class_uid, activity_id, type_uid = (ocsf.get(name) for name in ("class_uid", "activity_id", "type_uid"))
        if any(type(value) is not int or value < 0 for value in (class_uid, activity_id, type_uid)) or type_uid != class_uid * 100 + activity_id:
            raise ValueError("OCSF class and activity identifiers are invalid")
        expected_class = _EVENT_CLASSES.get(event.get("event_type"))
        if expected_class is not None and class_uid != expected_class:
            raise ValueError("normalized event type disagrees with OCSF class")

        signature = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        previous = seen.get(event_id)
        if previous is not None:
            if previous != signature:
                raise ValueError("conflicting duplicate event_id")
            stats["duplicate_events"] += 1
            edge_id = edge_by_event.get(event_id)
            if edge_id is not None:
                edges[edge_id]["data_quality"]["duplicate"] = True
            continue
        seen[event_id] = signature

        relation = _relation(event, event_id)
        if relation is None:
            stats["unsupported_events"] += 1
            continue
        edge_type, source_kind, source_identity, target_kind, target_identity, missing = relation
        previous_time = latest_by_host.get(host)
        reordered = previous_time is not None and event_time < previous_time
        latest_by_host[host] = max(previous_time or event_time, event_time)
        if reordered:
            stats["reordered_events"] += 1
        if missing:
            stats["missing_identity_events"] += 1
        add_node("host", host, "host", event_time)
        source_node = add_node(source_kind, host, source_identity, event_time)
        target_node = add_node(target_kind, host, target_identity, event_time)
        edge_id = _id(salt, "edge", dataset_id, event_id, edge_type, source_node, target_node)
        edge_by_event[event_id] = edge_id
        attributes: dict[str, str] = {}
        if event.get("status") in {"unknown", "success", "failure"}:
            attributes["status"] = event["status"]
        path_category = event["data"].get("path_category")
        if edge_type in {"read", "wrote", "renamed"} and path_category in _PATH_CATEGORIES:
            attributes["path_category"] = path_category
        edges[edge_id] = {
            "id": edge_id,
            "type": edge_type,
            "source_node": source_node,
            "target_node": target_node,
            "event_time": event_time,
            "ingest_time": ingest_time,
            "ordering_confidence": 0.5 if missing or reordered else 1.0,
            "source_collector": event["source"],
            "source_event_id": _id(salt, "event", dataset_id, event_id),
            "ocsf": {"class_uid": class_uid, "activity_id": activity_id, "type_uid": type_uid},
            "data_quality": _quality(missing=missing, reordered=reordered),
            "attributes": attributes,
        }
        stats["accepted_events"] += 1

    graph = {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "ocsf_version": OCSF_VERSION,
        "dataset_id": dataset_id,
        "nodes": sorted(nodes.values(), key=lambda node: node["id"]),
        "edges": sorted(edges.values(), key=lambda edge: (edge["event_time"], edge["id"])),
    }
    validate_provenance_graph(graph)
    return graph, stats
