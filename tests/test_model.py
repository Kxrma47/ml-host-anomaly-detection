import tempfile
import unittest
from pathlib import Path

from ueba_detector.autoencoder import NeuralAutoencoder
from ueba_detector.simulate import generate_normal_samples


class ModelTests(unittest.TestCase):
    def test_model_train_save_load_and_score(self):
        samples = generate_normal_samples(count=40, seed=1)
        model = NeuralAutoencoder.fit(samples, epochs=10, seed=1)
        score = model.score(samples[0])
        self.assertGreaterEqual(score.error, 0)
        self.assertGreater(model.threshold, 0)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model.json"
            model.save(path)
            loaded = NeuralAutoencoder.load(path)
            self.assertEqual(loaded.hidden_dim, model.hidden_dim)
            self.assertEqual(loaded.scaler.feature_names, model.scaler.feature_names)


if __name__ == "__main__":
    unittest.main()
