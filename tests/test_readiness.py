import json
import tempfile
import unittest
from pathlib import Path

from ueba_detector.readiness import audit_training_data, write_readiness_report
from ueba_detector.simulate import generate_normal_samples


def _write_rows(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


class ReadinessTests(unittest.TestCase):
    def test_audit_reports_gaps_rules_splits_and_trailing_partial_write(self):
        metrics = generate_normal_samples(count=7, seed=31)
        metrics.pop(2)
        attack_timestamp = metrics[2]["timestamp"]
        events = [
            {
                "event_id": f"process-{index}",
                "timestamp": attack_timestamp,
                "host": metrics[2]["host"],
                "event_type": "process_started",
                "data": {"process": {"name": f"tool-{index}"}},
            }
            for index in range(20)
        ]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metrics_path = root / "metrics.jsonl"
            events_path = root / "events.jsonl"
            report_path = root / "readiness.json"
            _write_rows(metrics_path, metrics)
            _write_rows(events_path, events)
            with events_path.open("ab") as stream:
                stream.write(b'{"timestamp":')

            report = audit_training_data(
                metrics_path,
                events_path,
                minimum_windows=4,
                recommended_windows=7,
            )
            strict_report = audit_training_data(
                metrics_path,
                events_path,
                minimum_windows=4,
                recommended_windows=7,
                max_rule_exclusion_ratio=0.5,
            )
            write_readiness_report(report_path, report)
            persisted = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["coverage"]["observed_windows"], 6)
        self.assertEqual(report["coverage"]["missing_windows"], 1)
        self.assertEqual(report["coverage"]["gap_count"], 1)
        self.assertEqual(report["events"]["jsonl"]["trailing_partial_rows"], 1)
        self.assertEqual(report["combined"]["flagged_windows"], 1)
        self.assertEqual(report["combined"]["excluded_windows"], 0)
        self.assertEqual(report["combined"]["clean_windows"], 6)
        self.assertEqual(report["combined"]["rule_counts"]["process_start_burst"], 1)
        self.assertIn("process_start_burst", report["combined"]["noisy_rules"])
        self.assertEqual(strict_report["combined"]["excluded_windows"], 1)
        self.assertEqual(strict_report["combined"]["clean_windows"], 5)
        self.assertEqual(report["readiness"]["state"], "preliminary")
        split_total = sum(
            report["proposed_splits"][name]["windows"]
            for name in ("train", "validation", "test")
        )
        self.assertEqual(split_total, 6)
        self.assertEqual(persisted["readiness"]["state"], "preliminary")

    def test_complete_malformed_rows_and_feature_errors_block_training(self):
        metric = generate_normal_samples(count=1, seed=32)[0]
        metric.pop("cpu_percent")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metrics_path = root / "metrics.jsonl"
            events_path = root / "events.jsonl"
            metrics_path.write_text(json.dumps(metric) + "\nnot-json\n", encoding="utf-8")
            events_path.write_text("", encoding="utf-8")

            report = audit_training_data(
                metrics_path,
                events_path,
                minimum_windows=1,
                recommended_windows=1,
            )

        self.assertEqual(report["metrics"]["jsonl"]["malformed_rows"], 1)
        self.assertEqual(report["metrics"]["features"]["rows_with_feature_issues"], 1)
        self.assertEqual(report["readiness"]["state"], "invalid")
        self.assertFalse(report["readiness"]["ready_for_preliminary_training"])

    def test_rejects_inconsistent_window_targets(self):
        with self.assertRaises(ValueError):
            audit_training_data("metrics", "events", minimum_windows=10, recommended_windows=9)
        with self.assertRaises(ValueError):
            audit_training_data("metrics", "events", max_rule_exclusion_ratio=1.1)


if __name__ == "__main__":
    unittest.main()
