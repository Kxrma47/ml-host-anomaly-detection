import json
import unittest
from copy import deepcopy

from ueba_detector.adapters import adapt_rows
from ueba_detector.research_graph import validate_provenance_graph
from ueba_detector.research_graph_build import build_provenance_graph


SALT = "synthetic-test-salt-2026"
INGESTED_AT = "2026-10-13T10:00:00Z"


def tc_fixture():
    return [
        {"datum": {"com.bbn.tc.schema.avro.cdm18.Subject": {
            "uuid": "raw-subject", "hostId": "raw-host", "cmdLine": "--password test-canary"}}},
        {"datum": {"com.bbn.tc.schema.avro.cdm18.FileObject": {
            "uuid": "raw-file", "path": "/private/test-canary.txt"}}},
        {"datum": {"com.bbn.tc.schema.avro.cdm18.Event": {
            "uuid": "raw-event", "type": "EVENT_WRITE", "hostId": "raw-host",
            "timestampNanos": 1_760_000_000_000_000_000,
            "subject": "raw-subject", "predicateObject": "raw-file"}}},
    ]


def optc_fixture():
    return [
        {"timestamp": 1_760_000_000_000, "hostname": "raw-host", "object": "PROCESS",
         "action": "CREATE", "actorID": "raw-parent", "objectID": "raw-child",
         "properties": {"command_line": "--password test-canary"}},
        {"timestamp": 1_760_000_001_000, "hostname": "raw-host", "object": "FILE",
         "action": "WRITE", "actorID": "raw-child", "objectID": "raw-file",
         "properties": {"path": "/private/test-canary.txt"}},
        {"timestamp": 1_760_000_002_000, "hostname": "raw-host", "object": "FLOW",
         "action": "START", "actorID": "raw-child", "objectID": "raw-flow"},
    ]


class ResearchGraphBuildTests(unittest.TestCase):
    def build(self, dataset, rows):
        events = adapt_rows(dataset, rows, salt=SALT)
        return build_provenance_graph(events, dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT)

    def test_tc_fixture_creates_private_file_edge(self):
        graph, stats = self.build("tc_cdm", tc_fixture())
        validate_provenance_graph(graph)
        self.assertEqual(stats["accepted_events"], 1)
        self.assertEqual(graph["edges"][0]["type"], "wrote")
        encoded = json.dumps(graph)
        for value in ("raw-subject", "raw-file", "raw-host", "test-canary", "/private"):
            self.assertNotIn(value, encoded)

    def test_tc_execute_links_process_to_executable(self):
        rows = tc_fixture()
        rows[2]["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["type"] = "EVENT_EXECUTE"
        graph, stats = self.build("tc_cdm", rows)
        self.assertEqual(stats["accepted_events"], 1)
        self.assertEqual(graph["edges"][0]["type"], "executed")
        node_types = {node["id"]: node["type"] for node in graph["nodes"]}
        self.assertEqual(node_types[graph["edges"][0]["target_node"]], "executable")

    def test_optc_fixture_creates_process_file_and_flow_edges(self):
        graph, stats = self.build("optc", optc_fixture())
        self.assertEqual(stats["accepted_events"], 3)
        self.assertEqual({edge["type"] for edge in graph["edges"]}, {"spawned", "wrote", "connected"})
        self.assertEqual({node["type"] for node in graph["nodes"]}, {"host", "process", "file", "socket_endpoint"})
        self.assertNotIn("test-canary", json.dumps(graph))

    def test_same_inputs_have_stable_identifiers(self):
        first, _ = self.build("optc", optc_fixture())
        second, _ = self.build("optc", optc_fixture())
        self.assertEqual(first, second)
        changed, _ = build_provenance_graph(
            adapt_rows("optc", optc_fixture(), salt=SALT),
            dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt="another-synthetic-salt",
        )
        self.assertNotEqual(first["nodes"][0]["id"], changed["nodes"][0]["id"])
        self.assertNotIn(adapt_rows("optc", optc_fixture(), salt=SALT)[0]["event_id"], json.dumps(first))

    def test_duplicate_event_is_deduplicated_and_flagged(self):
        event = adapt_rows("tc_cdm", tc_fixture(), salt=SALT)[0]
        graph, stats = build_provenance_graph(
            [event, deepcopy(event)], dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT
        )
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(stats["duplicate_events"], 1)
        self.assertTrue(graph["edges"][0]["data_quality"]["duplicate"])
        changed = deepcopy(event)
        changed["status"] = "failure"
        with self.assertRaisesRegex(ValueError, "conflicting duplicate"):
            build_provenance_graph(
                [event, changed], dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT
            )

    def test_reordered_and_missing_identity_are_explicit(self):
        events = adapt_rows("optc", optc_fixture(), salt=SALT)
        events[1]["data"]["actor"]["id"] = None
        graph, stats = build_provenance_graph(
            [events[2], events[1], events[0]],
            dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT,
        )
        self.assertEqual(stats["reordered_events"], 2)
        self.assertEqual(stats["missing_identity_events"], 1)
        self.assertTrue(any(edge["data_quality"]["missing_fields"] for edge in graph["edges"]))
        self.assertEqual([edge["event_time"] for edge in graph["edges"]],
                         sorted(edge["event_time"] for edge in graph["edges"]))

    def test_raw_identity_and_bad_ocsf_fail_closed(self):
        event = adapt_rows("tc_cdm", tc_fixture(), salt=SALT)[0]
        raw = deepcopy(event)
        raw["host"] = "raw-host"
        with self.assertRaisesRegex(ValueError, "pseudonymous"):
            build_provenance_graph([raw], dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT)
        bad = deepcopy(event)
        bad["ocsf"]["type_uid"] += 1
        with self.assertRaisesRegex(ValueError, "OCSF class"):
            build_provenance_graph([bad], dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT)
        mismatch = deepcopy(event)
        mismatch["event_type"] = "process_started"
        with self.assertRaisesRegex(ValueError, "disagrees"):
            build_provenance_graph(
                [mismatch], dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT
            )

    def test_unsupported_semantics_are_counted(self):
        row = {"timestamp": 1_760_000_000_000, "hostname": "raw-host", "object": "FILE", "action": "OPEN"}
        graph, stats = self.build("optc", [row])
        self.assertEqual(stats["unsupported_events"], 1)
        self.assertEqual(graph["edges"], [])

    def test_host_scope_prevents_cross_host_merges(self):
        first, second = optc_fixture()[1:2] * 2
        second = deepcopy(second)
        second["hostname"] = "another-raw-host"
        events = adapt_rows("optc", [first, second], salt=SALT)
        graph, stats = build_provenance_graph(
            events, dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT
        )
        self.assertEqual(stats["accepted_events"], 2)
        self.assertEqual(sum(node["type"] == "host" for node in graph["nodes"]), 2)
        self.assertEqual(sum(node["type"] == "file" for node in graph["nodes"]), 2)

    def test_missing_identities_do_not_merge_unrelated_events(self):
        rows = [
            {"timestamp": 1_760_000_000_000 + i * 1000, "hostname": "raw-host",
             "object": "FILE", "action": "WRITE"}
            for i in range(2)
        ]
        graph, stats = self.build("optc", rows)
        self.assertEqual(stats["missing_identity_events"], 2)
        self.assertEqual(sum(node["type"] == "file" for node in graph["nodes"]), 2)
        self.assertEqual(sum(node["type"] == "process" for node in graph["nodes"]), 2)

    def test_invalid_salt_and_timestamps_fail_closed(self):
        event = adapt_rows("tc_cdm", tc_fixture(), salt=SALT)[0]
        with self.assertRaisesRegex(ValueError, "salt"):
            build_provenance_graph(
                [event], dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt="short"
            )
        event["timestamp"] = "2026-01-01T00:00:00"
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            build_provenance_graph(
                [event], dataset_id="synthetic_pilot", ingested_at=INGESTED_AT, salt=SALT
            )

    def test_imported_ocsf_uses_pseudonymous_required_objects(self):
        events = adapt_rows("tc_cdm", tc_fixture(), salt=SALT)
        events += adapt_rows("optc", optc_fixture(), salt=SALT)
        for event in events:
            with self.subTest(event_type=event["event_type"]):
                ocsf = event["ocsf"]
                if ocsf["class_uid"] in {1001, 1007}:
                    self.assertIn("uid", ocsf["actor"]["process"])
                    self.assertEqual(ocsf["device"]["type_id"], 0)
                    self.assertNotIn("id", ocsf["actor"])
                if ocsf["class_uid"] == 1001:
                    self.assertEqual(ocsf["file"]["name"], "unknown")
                    self.assertIsInstance(ocsf["file"]["type_id"], int)
                self.assertNotIn("test-canary", json.dumps(ocsf))

    def test_pilot_limit_prevents_unbounded_graph_growth(self):
        event = adapt_rows("tc_cdm", tc_fixture(), salt=SALT)[0]
        with self.assertRaisesRegex(ValueError, "event limit"):
            build_provenance_graph(
                [event, deepcopy(event)], dataset_id="synthetic_pilot",
                ingested_at=INGESTED_AT, salt=SALT, max_events=1,
            )


if __name__ == "__main__":
    unittest.main()
