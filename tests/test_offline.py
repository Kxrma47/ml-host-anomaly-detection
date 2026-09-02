import unittest

from ueba_detector.offline import (
    compare_drift,
    correlate_incidents,
    group_alerts,
    replay_records,
    run_stress_test,
)
from ueba_detector.simulate import generate_normal_samples


class ReplayTests(unittest.TestCase):
    def test_replay_sorts_and_deduplicates_without_sleeping(self):
        rows = [
            {"event_id": "b", "timestamp": "2026-01-01T00:01:00Z"},
            {"event_id": "a", "timestamp": "2026-01-01T00:00:00Z"},
            {"event_id": "a", "timestamp": "2026-01-01T00:00:00Z"},
        ]
        outputs, report = replay_records(rows)
        self.assertEqual([row["event_id"] for row in outputs], ["a", "b"])
        self.assertEqual(report["duplicates_skipped"], 1)
        self.assertEqual(report["out_of_order_input"], 1)

    def test_replay_isolates_handler_failure(self):
        rows = [
            {"event_id": "a", "timestamp": "2026-01-01T00:00:00Z"},
            {"event_id": "b", "timestamp": "2026-01-01T00:01:00Z"},
        ]

        def handler(row):
            if row["event_id"] == "a":
                raise RuntimeError("synthetic failure")
            return row

        outputs, report = replay_records(rows, handler)
        self.assertEqual([row["event_id"] for row in outputs], ["b"])
        self.assertEqual(report["handler_errors"], 1)


class IncidentTests(unittest.TestCase):
    def test_groups_repeated_alerts_and_builds_timeline(self):
        alerts = [
            {
                "timestamp": f"2026-01-01T00:0{minute}:00Z",
                "host": "host-1",
                "severity": "high" if minute == 1 else "medium",
                "event_type": "authentication_failure",
                "rules": [{"rule_id": "authentication_failure_burst"}],
            }
            for minute in range(3)
        ]
        groups = group_alerts(alerts, cooldown_seconds=300)
        incidents = correlate_incidents(alerts, max_gap_seconds=900)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 3)
        self.assertEqual(groups[0]["severity"], "high")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["signal_count"], 3)

    def test_accepts_legacy_anomaly_event_timestamp(self):
        alerts = [
            {
                "event_timestamp": "2026-01-01T00:00:00Z",
                "detected_at": "2026-01-01T00:00:05Z",
                "host": "host-1",
                "category": "network_anomaly",
                "severity": "high",
                "explanation": "unusual network activity",
            }
        ]
        groups = group_alerts(alerts)
        incidents = correlate_incidents(alerts)
        self.assertEqual(groups[0]["first_timestamp"], alerts[0]["event_timestamp"])
        self.assertEqual(incidents[0]["timeline"][0]["summary"], "unusual network activity")


class DriftAndStressTests(unittest.TestCase):
    def test_detects_large_multifeature_shift(self):
        reference = generate_normal_samples(count=30, seed=202)
        current = [{**row, "cpu_percent": row["cpu_percent"] + 100, "memory_percent": 99} for row in reference]
        report = compare_drift(
            reference,
            current,
            shift_threshold=3,
            feature_ratio_threshold=0.05,
        )
        self.assertTrue(report["drift_detected"])
        self.assertTrue(report["features"]["cpu_percent"]["drifted"])

    def test_stress_harness_reports_bounded_pipeline_measurements(self):
        report = run_stress_test(windows=30, seed=203)
        self.assertEqual(report["combined_rows"], 30)
        self.assertGreater(report["windows_per_second"], 0)
        self.assertGreater(report["peak_memory_bytes"], 0)
        self.assertTrue(report["baseline_exclusion_recommended"])
        self.assertLessEqual(report["started_at"], report["completed_at"])


if __name__ == "__main__":
    unittest.main()
