import tempfile
import unittest
from pathlib import Path

from ueba_detector.autoencoder import NeuralAutoencoder
from ueba_detector.combined import (
    COMBINED_FEATURE_NAMES,
    build_combined_samples,
    evaluate_security_rules,
    score_combined_sample,
)
from ueba_detector.simulate import generate_normal_samples, generate_security_events


class CombinedFeatureTests(unittest.TestCase):
    def test_joins_metrics_and_events_by_host_and_window(self):
        metrics = generate_normal_samples(count=1, seed=1)
        second = dict(metrics[0])
        second["timestamp"] = second["timestamp"].replace("00:00Z", "00:30Z")
        metrics[0]["cpu_percent"] = 10.0
        second["cpu_percent"] = 30.0
        timestamp = metrics[0]["timestamp"]
        host = metrics[0]["host"]
        events = [
            {
                "timestamp": timestamp,
                "host": host,
                "event_type": "process_started",
                "data": {
                    "actor": {"user": {"name": "alice"}},
                    "process": {"name": "tool"},
                },
            },
            {
                "timestamp": timestamp,
                "host": host,
                "event_type": "authentication_failure",
                "data": {
                    "actor": {"user": {"name": "alice"}},
                    "source_endpoint": {"ip": "10.0.0.5"},
                },
            },
            {
                "timestamp": timestamp,
                "host": "another-host",
                "event_type": "process_started",
                "data": {"process": {"name": "ignored"}},
            },
            {"timestamp": timestamp, "host": host, "event_type": "package_observed", "data": {}},
        ]
        rows = build_combined_samples([metrics[0], second], events)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["metric_sample_count"], 2)
        self.assertEqual(rows[0]["cpu_percent"], 20.0)
        self.assertEqual(rows[0]["event_process_started_count"], 1)
        self.assertEqual(rows[0]["event_authentication_failure_count"], 1)
        self.assertEqual(rows[0]["event_unique_processes"], 1)
        self.assertEqual(rows[0]["event_unique_users"], 1)
        self.assertEqual(rows[0]["event_unique_remote_sources"], 1)

    def test_security_rules_are_explainable(self):
        sample = {
            "event_authentication_failure_count": 7,
            "event_authentication_success_count": 1,
            "event_package_installed_count": 3,
            "event_process_started_count": 25,
        }
        rules = evaluate_security_rules(sample)
        self.assertEqual(
            {rule["rule_id"] for rule in rules},
            {"authentication_failure_burst", "package_change_burst", "process_start_burst"},
        )
        self.assertTrue(all(rule["description"] for rule in rules))

    def test_combined_model_saves_feature_schema_and_rule_floor(self):
        metrics = generate_normal_samples(count=40, seed=3)
        events = generate_security_events(metrics, seed=4)
        rows = build_combined_samples(metrics, events)
        model = NeuralAutoencoder.fit(
            rows,
            feature_names=COMBINED_FEATURE_NAMES,
            epochs=5,
            seed=5,
        )
        attack = dict(rows[0])
        attack["event_authentication_failure_count"] = 8
        attack["event_authentication_success_count"] = 1
        score, rules, model_ratio = score_combined_sample(model, attack)
        self.assertGreaterEqual(score.ratio, 2.5)
        self.assertTrue(score.is_anomaly)
        self.assertTrue(rules)
        self.assertGreaterEqual(model_ratio, 0.0)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "combined.json"
            model.save(path)
            loaded = NeuralAutoencoder.load(path)
            self.assertEqual(loaded.scaler.feature_names, COMBINED_FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
