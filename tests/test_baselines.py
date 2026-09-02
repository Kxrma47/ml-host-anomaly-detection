import unittest

from ueba_detector.baselines import (
    EWMADetector,
    RobustZScoreDetector,
    compare_detectors,
    select_clean_training_rows,
)
from ueba_detector.simulate import generate_normal_samples, generate_test_samples


class BaselineTests(unittest.TestCase):
    def test_statistical_detectors_calibrate_and_score(self):
        train = generate_normal_samples(count=40, seed=204)
        robust = RobustZScoreDetector.fit(train)
        ewma = EWMADetector.fit(train)
        self.assertGreater(robust.calibrate(train), 0)
        self.assertGreater(ewma.calibrate(train), 0)
        self.assertIsInstance(robust.predict(train[0]), bool)
        self.assertIsInstance(ewma.predict_then_update(train[0]), bool)

    def test_chronological_comparison_runs_all_models(self):
        rows = generate_test_samples(count=90, seed=205)
        report = compare_detectors(rows, epochs=3, threshold_quantile=0.95, seed=206)
        self.assertEqual(set(report["methods"]), {"autoencoder", "robust_zscore", "ewma"})
        self.assertEqual(report["split"]["test"], 14)
        self.assertTrue(all(method["windows"] == 14 for method in report["methods"].values()))

    def test_external_holdout_keeps_labeled_attacks_out_of_training(self):
        training = generate_normal_samples(count=90, seed=208)
        evaluation = generate_test_samples(count=90, seed=209)
        report = compare_detectors(
            training,
            evaluation_rows=evaluation,
            epochs=3,
            threshold_quantile=0.95,
            seed=210,
        )
        self.assertEqual(report["split"]["strategy"], "external_holdout")
        self.assertGreater(report["methods"]["autoencoder"]["positive_windows"], 0)
        self.assertIsNotNone(report["methods"]["autoencoder"]["recall"])

    def test_poisoning_guard_excludes_explicit_attack_labels(self):
        rows = generate_normal_samples(count=20, seed=211)
        rows[3]["scenario"] = "process_burst"
        rows[8]["scenario"] = "network_scan"
        selected, report = select_clean_training_rows(rows)

        self.assertEqual(len(selected), 18)
        self.assertTrue(all(row["scenario"] == "normal" for row in selected))
        self.assertEqual(report["excluded_labeled_attacks"], 2)


if __name__ == "__main__":
    unittest.main()
