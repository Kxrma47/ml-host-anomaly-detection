import unittest
import tempfile
from pathlib import Path

from ueba_detector.redaction import redact_data
from ueba_detector.simulate import generate_normal_samples
from ueba_detector.validation import find_secret_exposures, validate_dataset, validate_records


class ValidationTests(unittest.TestCase):
    def test_detects_persisted_secrets_and_invalid_metric_values(self):
        row = generate_normal_samples(count=1, seed=201)[0]
        row["cpu_percent"] = 120
        row["note"] = "Authorization: Bearer fake-token"
        report = validate_records([row], kind="metrics")

        self.assertFalse(report["valid"])
        self.assertEqual(report["errors"]["secret_exposure"], 1)
        self.assertEqual(report["warnings"]["percent_out_of_range"], 1)

    def test_redacted_nested_values_have_no_exposures(self):
        value = redact_data(
            {
                "password": "fake-password",
                "command": "tool --token=fake-token",
                "url": "https://user:fake@example.test/path",
            }
        )
        self.assertEqual(find_secret_exposures(value), [])

    def test_event_validation_finds_duplicates_and_ordering(self):
        rows = [
            {
                "event_id": "same",
                "timestamp": "2026-01-01T00:01:00Z",
                "host": "h",
                "event_type": "test",
                "source": "test",
            },
            {
                "event_id": "same",
                "timestamp": "2026-01-01T00:00:00Z",
                "host": "h",
                "event_type": "test",
                "source": "test",
            },
        ]
        report = validate_records(rows, kind="events")
        self.assertTrue(report["valid"])
        self.assertEqual(report["warnings"]["duplicate_identity"], 1)
        self.assertEqual(report["warnings"]["out_of_order"], 1)
        self.assertEqual(report["quality_score"], 75.0)

    def test_dataset_validation_reports_malformed_complete_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("not-json\n", encoding="utf-8")
            report = validate_dataset(path, kind="events")
        self.assertFalse(report["valid"])
        self.assertEqual(report["errors"]["structural_file_rows"], 1)


if __name__ == "__main__":
    unittest.main()
