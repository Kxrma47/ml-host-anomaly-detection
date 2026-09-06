import tempfile
import unittest
from pathlib import Path

from ueba_detector.autoencoder import NeuralAutoencoder
from ueba_detector.combined import COMBINED_FEATURE_NAMES, build_combined_samples
from ueba_detector.shadow import (
    pseudonymous_host_id,
    signed_request_headers,
    validate_cloud_endpoint,
    ShadowMonitor,
)
from ueba_detector.simulate import generate_normal_samples


class ShadowTests(unittest.TestCase):
    def test_host_identifier_is_stable_and_not_hostname(self):
        value = pseudonymous_host_id("personal-mac", "a" * 32)
        self.assertEqual(value, pseudonymous_host_id("personal-mac", "a" * 32))
        self.assertNotIn("personal-mac", value)

    def test_rejects_insecure_remote_endpoint(self):
        with self.assertRaises(ValueError):
            validate_cloud_endpoint("http://example.com")
        self.assertEqual(validate_cloud_endpoint("http://127.0.0.1:8788"), "http://127.0.0.1:8788")

    def test_request_signature_is_deterministic_and_body_bound(self):
        first = signed_request_headers("k" * 32, b'{"a":1}', timestamp=10, nonce="abc")
        second = signed_request_headers("k" * 32, b'{"a":2}', timestamp=10, nonce="abc")
        self.assertEqual(first["x-hostwatch-timestamp"], "10")
        self.assertEqual(first["x-hostwatch-nonce"], "abc")
        self.assertNotEqual(first["x-hostwatch-signature"], second["x-hostwatch-signature"])

    def test_scores_and_persists_a_window(self):
        metrics = generate_normal_samples(count=20, seed=12)
        rows = build_combined_samples(metrics, [])
        model = NeuralAutoencoder.fit(rows, feature_names=COMBINED_FEATURE_NAMES, epochs=2, seed=3)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            monitor = ShadowMonitor(
                model=model, model_path="model.json", rule_thresholds=None,
                telemetry=None, agent=None, metrics_output=root / "metrics.jsonl",
                scores_output=root / "scores.jsonl", alerts_output=root / "alerts.jsonl",
            )
            result = monitor.score_window(metrics[-1], [])
            self.assertIn("ratio", result)
            self.assertTrue((root / "scores.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
