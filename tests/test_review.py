import csv
import tempfile
import unittest
from pathlib import Path

from ueba_detector.review import (
    alert_id,
    build_review_rows,
    evaluate_reviewed_alerts,
    load_review_labels,
    select_reviewed_baseline,
    summarize_review_csv,
    write_review_csv,
)


class ReviewTests(unittest.TestCase):
    def test_stable_id_and_safe_review_fields(self):
        alert = {
            "event_timestamp": "2026-09-01T12:00:00Z", "host": "mac",
            "category": "network_anomaly", "severity": "high", "ratio": 2.8,
            "top_features": [{"feature": "tcp_syn_sent", "contribution": 2.0}],
            "detection_rules": [], "sample": {"secret": "must not appear"},
        }
        self.assertEqual(alert_id(alert), alert_id(dict(alert)))
        rows = build_review_rows([alert])
        self.assertEqual(rows[0]["label"], "unreviewed")
        self.assertNotIn("secret", str(rows[0]))

    def test_summary_validates_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.csv"
            write_review_csv(path, build_review_rows([{"event_timestamp": "x"}]))
            with path.open("r", encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            rows[0]["label"] = "benign"
            write_review_csv(path, rows)
            self.assertEqual(summarize_review_csv(path)["reviewed"], 1)
            labels = load_review_labels(path)
            report = evaluate_reviewed_alerts([{"event_timestamp": "x"}], labels)
            self.assertEqual(report["reviewed_false_alerts"], 1)
            self.assertIsNone(report["recall"])

    def test_training_gate_blocks_unreviewed_and_excludes_positive_labels(self):
        alert = {"event_timestamp": "t1", "host": "h"}
        samples = [{"timestamp": "t1", "host": "h"}, {"timestamp": "t2", "host": "h"}]
        identifier = alert_id(alert)
        with self.assertRaisesRegex(ValueError, "remain unreviewed"):
            select_reviewed_baseline(samples, [alert], {identifier: "unreviewed"})
        selected, report = select_reviewed_baseline(
            samples, [alert], {identifier: "confirmed_attack"}
        )
        self.assertEqual(selected, [samples[1]])
        self.assertEqual(report["excluded_reviewed_alert_windows"], 1)


if __name__ == "__main__":
    unittest.main()
