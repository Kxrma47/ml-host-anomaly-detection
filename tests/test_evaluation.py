import tempfile
import unittest
from pathlib import Path

from ueba_detector.combined import build_combined_samples
from ueba_detector.evaluation import (
    calibrate_rule_thresholds,
    evaluate_combined_dataset,
    load_rule_thresholds,
    save_rule_configuration,
)
from ueba_detector.simulate import generate_security_events, generate_test_samples


class EvaluationTests(unittest.TestCase):
    def test_rule_calibration_raises_a_saturated_process_threshold(self):
        rows = [{"event_process_started_count": 25} for _ in range(100)]
        configuration = calibrate_rule_thresholds(rows, quantile=0.99)
        self.assertEqual(configuration["thresholds"]["process_start_burst"], 26)
        self.assertEqual(
            configuration["statistics"]["process_start_burst"]["calibrated_exceedance_ratio"],
            0.0,
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            save_rule_configuration(path, configuration)
            loaded = load_rule_thresholds(path)
        self.assertEqual(loaded["process_start_burst"], 26)

    def test_chronological_evaluation_compares_all_detection_methods(self):
        metrics = generate_test_samples(count=120, seed=41)
        events = generate_security_events(metrics, seed=42, inject_event_attacks=True)
        rows = build_combined_samples(metrics, events)
        report, scores, model, rules = evaluate_combined_dataset(rows, epochs=5, seed=43)

        self.assertEqual(report["dataset"]["windows"], 120)
        self.assertEqual(report["dataset"]["test_windows"], len(scores))
        self.assertEqual(set(report["methods"]), {"ml", "rules", "combined"})
        self.assertTrue(report["dataset"]["labeled"])
        self.assertGreater(model.threshold, 0.0)
        self.assertIn("process_start_burst", rules["thresholds"])
        self.assertTrue(all("combined_is_anomaly" in row for row in scores))

    def test_rejects_too_few_windows(self):
        with self.assertRaises(ValueError):
            evaluate_combined_dataset([{"timestamp": "2026-01-01T00:00:00Z"}], epochs=1)


if __name__ == "__main__":
    unittest.main()
