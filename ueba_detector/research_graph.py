from __future__ import annotations

from datetime import datetime
from typing import Any

from .ocsf import OCSF_VERSION


GRAPH_SCHEMA_VERSION = "1.0.0"
NODE_TYPES = {
    "process",
    "executable",
    "file",
    "path_class",
    "user",
    "session",
    "package",
    "service",
    "socket_endpoint",
    "host",
}
EDGE_TYPES = {
    "spawned",
    "executed",
    "read",
    "wrote",
    "renamed",
    "connected",
    "accepted",
    "authenticated",
    "elevated",
    "installed",
    "started",
    "stopped",
}
IDENTITY_SCOPES = {"dataset", "host", "session", "global"}
QUALITY_FLAGS = {
    "missing_fields",
    "delayed",
    "reordered",
    "duplicate",
    "collector_degraded",
}


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _nonempty(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    return text


def _timestamp(value: Any, field: str) -> str:
    text = _nonempty(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return text


def _validate_quality(value: Any, field: str) -> None:
    quality = _object(value, field)
    unknown = set(quality) - QUALITY_FLAGS
    if unknown:
        raise ValueError(f"{field} contains unsupported flags: {sorted(unknown)}")
    missing = quality.get("missing_fields")
    if not isinstance(missing, list) or any(not isinstance(item, str) for item in missing):
        raise ValueError(f"{field}.missing_fields must be a string array")
    for name in QUALITY_FLAGS - {"missing_fields"}:
        if not isinstance(quality.get(name), bool):
            raise ValueError(f"{field}.{name} must be boolean")


def validate_provenance_graph(payload: dict[str, Any]) -> None:
    """Validate the research graph contract without accepting raw telemetry fields."""
    if payload.get("schema_version") != GRAPH_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {GRAPH_SCHEMA_VERSION}")
    if payload.get("ocsf_version") != OCSF_VERSION:
        raise ValueError(f"ocsf_version must be {OCSF_VERSION}")
    _nonempty(payload.get("dataset_id"), "dataset_id")
    nodes = payload.get("nodes")
    edges = payload.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("nodes and edges must be arrays")

    node_ids: set[str] = set()
    for index, value in enumerate(nodes):
        node = _object(value, f"nodes[{index}]")
        node_id = _nonempty(node.get("id"), f"nodes[{index}].id")
        if node_id in node_ids:
            raise ValueError(f"duplicate node id: {node_id}")
        node_ids.add(node_id)
        if node.get("type") not in NODE_TYPES:
            raise ValueError(f"nodes[{index}].type is unsupported")
        if node.get("identity_scope") not in IDENTITY_SCOPES:
            raise ValueError(f"nodes[{index}].identity_scope is unsupported")
        _timestamp(node.get("first_seen"), f"nodes[{index}].first_seen")
        _timestamp(node.get("last_seen"), f"nodes[{index}].last_seen")
        _object(node.get("attributes"), f"nodes[{index}].attributes")
        _validate_quality(node.get("data_quality"), f"nodes[{index}].data_quality")

    edge_ids: set[str] = set()
    for index, value in enumerate(edges):
        edge = _object(value, f"edges[{index}]")
        edge_id = _nonempty(edge.get("id"), f"edges[{index}].id")
        if edge_id in edge_ids:
            raise ValueError(f"duplicate edge id: {edge_id}")
        edge_ids.add(edge_id)
        if edge.get("type") not in EDGE_TYPES:
            raise ValueError(f"edges[{index}].type is unsupported")
        source = _nonempty(edge.get("source_node"), f"edges[{index}].source_node")
        target = _nonempty(edge.get("target_node"), f"edges[{index}].target_node")
        if source not in node_ids or target not in node_ids:
            raise ValueError(f"edges[{index}] references an unknown node")
        _timestamp(edge.get("event_time"), f"edges[{index}].event_time")
        _timestamp(edge.get("ingest_time"), f"edges[{index}].ingest_time")
        confidence = edge.get("ordering_confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            raise ValueError(f"edges[{index}].ordering_confidence must be numeric")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError(f"edges[{index}].ordering_confidence must be between zero and one")
        _nonempty(edge.get("source_collector"), f"edges[{index}].source_collector")
        _nonempty(edge.get("source_event_id"), f"edges[{index}].source_event_id")
        ocsf = _object(edge.get("ocsf"), f"edges[{index}].ocsf")
        for field in ("class_uid", "activity_id", "type_uid"):
            if not isinstance(ocsf.get(field), int):
                raise ValueError(f"edges[{index}].ocsf.{field} must be an integer")
        _validate_quality(edge.get("data_quality"), f"edges[{index}].data_quality")
        _object(edge.get("attributes"), f"edges[{index}].attributes")
