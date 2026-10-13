import json
import unittest
from copy import deepcopy
from pathlib import Path

from ueba_detector.research_graph import validate_provenance_graph


def quality():
    return {
        "missing_fields": [],
        "delayed": False,
        "reordered": False,
        "duplicate": False,
        "collector_degraded": False,
    }


def fixture():
    return {
        "schema_version": "1.0.0",
        "ocsf_version": "1.8.0",
        "dataset_id": "tiny-public-fixture",
        "nodes": [
            {
                "id": "process:0123456789abcdef",
                "type": "process",
                "identity_scope": "host",
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-01-01T00:00:01Z",
                "attributes": {"role": "actor", "ocsf_class_uid": 1007},
                "data_quality": quality(),
            },
            {
                "id": "file:fedcba9876543210",
                "type": "file",
                "identity_scope": "host",
                "first_seen": "2026-01-01T00:00:01Z",
                "last_seen": "2026-01-01T00:00:01Z",
                "attributes": {"path_category": "document"},
                "data_quality": quality(),
            },
        ],
        "edges": [
            {
                "id": "edge:0011223344556677",
                "type": "wrote",
                "source_node": "process:0123456789abcdef",
                "target_node": "file:fedcba9876543210",
                "event_time": "2026-01-01T00:00:01Z",
                "ingest_time": "2026-01-01T00:00:02Z",
                "ordering_confidence": 1.0,
                "source_collector": "dataset.tc_cdm",
                "source_event_id": "event:0123456789abcdef",
                "ocsf": {"class_uid": 1001, "activity_id": 99, "type_uid": 100199},
                "data_quality": quality(),
                "attributes": {"status": "success", "path_category": "document"},
            }
        ],
    }


class ResearchGraphTests(unittest.TestCase):
    def test_schema_is_json_schema_2020_12(self):
        path = Path(__file__).parents[1] / "experiments" / "schemas" / "provenance-graph.schema.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("process", schema["$defs"]["node"]["properties"]["type"]["enum"])
        self.assertIn("connected", schema["$defs"]["edge"]["properties"]["type"]["enum"])

    def test_fixture_passes_runtime_contract(self):
        validate_provenance_graph(fixture())

    def test_unknown_node_reference_fails_closed(self):
        payload = fixture()
        payload["edges"][0]["target_node"] = "file:missing"
        with self.assertRaisesRegex(ValueError, "unknown node"):
            validate_provenance_graph(payload)

    def test_duplicate_identity_fails_closed(self):
        payload = fixture()
        payload["nodes"].append(deepcopy(payload["nodes"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate node id"):
            validate_provenance_graph(payload)

    def test_quality_and_ordering_are_mandatory(self):
        payload = fixture()
        payload["edges"][0]["ordering_confidence"] = 1.1
        with self.assertRaisesRegex(ValueError, "between zero and one"):
            validate_provenance_graph(payload)

        payload = fixture()
        payload["edges"][0]["data_quality"].pop("reordered")
        with self.assertRaisesRegex(ValueError, "reordered must be boolean"):
            validate_provenance_graph(payload)


if __name__ == "__main__":
    unittest.main()
