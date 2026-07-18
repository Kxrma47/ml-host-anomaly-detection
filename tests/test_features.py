import unittest

from ueba_detector.features import FEATURE_NAMES, fit_scaler, sample_to_vector


class FeatureTests(unittest.TestCase):
    def test_vector_has_expected_length(self):
        sample = {name: 1 for name in FEATURE_NAMES}
        self.assertEqual(len(sample_to_vector(sample)), len(FEATURE_NAMES))

    def test_scaler_handles_constant_columns(self):
        scaler = fit_scaler([{"cpu_percent": 10}, {"cpu_percent": 10}])
        row = scaler.transform({"cpu_percent": 10})
        self.assertEqual(len(row), len(FEATURE_NAMES))
        self.assertTrue(all(abs(value) < 1e-9 for value in row))


if __name__ == "__main__":
    unittest.main()
