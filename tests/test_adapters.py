import unittest
import json
import tempfile
from pathlib import Path

from ueba_detector.adapters import DATASET_REGISTRY, adapt_rows, read_source_rows
from ueba_detector.validation import find_secret_exposures


class AdapterTests(unittest.TestCase):
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
        self.assertEqual(set(DATASET_REGISTRY), {"lanl", "optc", "unsw", "loghub"})

    def test_reads_json_array_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            path.write_text(json.dumps([{"EventID": 4688}]), encoding="utf-8")
            rows = read_source_rows(path)
        self.assertEqual(rows, [{"EventID": 4688}])


if __name__ == "__main__":
    unittest.main()
