import unittest
import json
import tempfile
from pathlib import Path

from ueba_detector.adapters import DATASET_REGISTRY, adapt_rows, read_source_rows
from ueba_detector.validation import find_secret_exposures


class AdapterTests(unittest.TestCase):
    def test_tc_cdm_builds_private_events_from_cdm18_objects(self):
        rows = [
            {
                "datum": {
                    "com.bbn.tc.schema.avro.cdm18.Subject": {
                        "uuid": "subject-raw-id",
                        "hostId": {"com.bbn.tc.schema.avro.cdm18.UUID": "subject-host-id"},
                        "cmdLine": {"string": "tool --password exposed-canary"},
                        "properties": {"map": {"path": "/usr/local/bin/private-user-tool"}},
                    }
                }
            },
            {
                "datum": {
                    "com.bbn.tc.schema.avro.cdm18.FileObject": {
                        "uuid": "file-raw-id",
                        "baseObject": {"properties": {"map": {"path": "/private/report.txt"}}},
                    }
                }
            },
            {
                "datum": {
                    "com.bbn.tc.schema.avro.cdm18.Event": {
                        "uuid": "event-raw-id",
                        "type": "EVENT_WRITE",
                        "timestampNanos": 1_700_000_000_000_000_000,
                        "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": "subject-raw-id"},
                        "predicateObject": {
                            "com.bbn.tc.schema.avro.cdm18.UUID": "file-raw-id"
                        },
                    }
                }
            },
        ]

        adapted = adapt_rows("tc_cdm", rows, salt="test")

        self.assertEqual(len(adapted), 1)
        event = adapted[0]
        self.assertEqual(event["event_type"], "file_activity")
        self.assertEqual(event["source"], "dataset.tc_cdm")
        self.assertNotIn("process", event["data"])
        self.assertEqual(event["data"]["object"]["kind"], "FileObject")
        serialized = json.dumps(event)
        for secret in ("subject-raw-id", "file-raw-id", "subject-host-id", "exposed-canary", "private-user-tool"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(find_secret_exposures(event), [])

    def test_tc_cdm_accepts_cdm20_and_is_deterministic(self):
        fixture = {
            "datum": {
                "com.bbn.tc.schema.avro.cdm20.Event": {
                    "uuid": "event-id",
                    "type": {"string": "EVENT_CONNECT"},
                    "timestampNanos": {"long": 1_700_000_000_000_000_000},
                    "subject": {"com.bbn.tc.schema.avro.cdm20.UUID": "subject-id"},
                    "predicateObject": {"com.bbn.tc.schema.avro.cdm20.UUID": "flow-id"},
                }
            }
        }
        first = adapt_rows("tc_cdm", [fixture], salt="test")
        second = adapt_rows("tc_cdm", [fixture], salt="test")

        self.assertEqual(first, second)
        self.assertEqual(first[0]["event_type"], "network_activity")
        self.assertEqual(first[0]["timestamp"], "2023-11-14T22:13:20Z")

    def test_lanl_maps_process_and_pseudonymizes_identity(self):
        rows = adapt_rows(
            "lanl",
            [
                {
                    "Time": 100,
                    "EventID": 4688,
                    "Computer": "workstation-1",
                    "UserName": "alice",
                    "ProcessName": "python.exe",
                }
            ],
            salt="test",
        )
        self.assertEqual(rows[0]["event_type"], "process_started")
        self.assertNotEqual(rows[0]["host"], "workstation-1")
        self.assertNotEqual(rows[0]["data"]["actor"]["user"]["name"], "alice")

    def test_optc_ecar_fixture_is_deterministic_and_private(self):
        fixture = {
            "timestamp": 1_539_120_748_904,
            "id": "event-native-id",
            "hostname": "private-workstation",
            "objectID": "process-native-id",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": "parent-native-id",
            "pid": 3648,
            "ppid": 6260,
            "principal": "private-domain\\private-user",
            "properties": {
                "command_line": "tool --password exposed-canary",
                "image_path": "C:\\private\\exposed-canary.exe",
                "user": "private-domain\\private-user",
            },
        }

        first = adapt_rows("optc", [fixture], salt="test")
        second = adapt_rows("optc", [fixture], salt="test")

        self.assertEqual(first, second)
        self.assertEqual(first[0]["timestamp"], "2018-10-09T21:32:28.904000Z")
        self.assertEqual(first[0]["event_type"], "process_started")
        self.assertEqual(first[0]["data"]["object"]["kind"], "Process")
        self.assertEqual(first[0]["data"]["path_category"], "executable")
        serialized = json.dumps(first[0])
        for secret in (
            "event-native-id", "private-workstation", "process-native-id",
            "parent-native-id", "private-user", "exposed-canary",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(find_secret_exposures(first[0]), [])

    def test_optc_ecar_maps_file_and_flow_semantics(self):
        rows = adapt_rows(
            "optc",
            [
                {"timestamp": 10, "hostname": "h", "object": "FILE", "action": "WRITE"},
                {"timestamp": 11, "hostname": "h", "object": "FLOW", "action": "START"},
            ],
            salt="test",
        )
        self.assertEqual(rows[0]["event_type"], "file_activity")
        self.assertEqual(rows[1]["event_type"], "network_activity")

    def test_all_adapters_emit_normalized_private_events(self):
        fixtures = {
            "optc": {"timestamp": "2026-01-01T00:00:00Z", "host": "h", "action": "FLOW-OPEN"},
            "unsw": {"stime": 10, "srcip": "10.0.0.1", "dstip": "10.0.0.2", "label": "Normal"},
            "loghub": {"Time": 20, "Node": "n", "Content": "password=fake-password"},
        }
        for dataset, fixture in fixtures.items():
            with self.subTest(dataset=dataset):
                row = adapt_rows(dataset, [fixture], salt="test")[0]
                self.assertEqual(row["source"], f"dataset.{dataset}")
                self.assertEqual(find_secret_exposures(row), [])
        self.assertEqual(set(DATASET_REGISTRY), {"tc_cdm", "lanl", "optc", "unsw", "loghub"})

    def test_reads_json_array_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            path.write_text(json.dumps([{"EventID": 4688}]), encoding="utf-8")
            rows = read_source_rows(path)
        self.assertEqual(rows, [{"EventID": 4688}])


if __name__ == "__main__":
    unittest.main()
