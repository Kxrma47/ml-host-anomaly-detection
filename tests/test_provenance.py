import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from ueba_detector.autoencoder import NeuralAutoencoder
from ueba_detector.provenance import build_provenance, verify_provenance
from ueba_detector.simulate import generate_normal_samples


class ProvenanceTests(unittest.TestCase):
    def test_dataset_hash_and_model_artifact_metadata_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "data.jsonl"
            dataset.write_bytes(b'{"value": 1}\n')
            provenance = build_provenance(dataset_paths=[dataset], parameters={"epochs": 2})
            model = NeuralAutoencoder.fit(generate_normal_samples(count=20, seed=207), epochs=2)
            model_path = root / "model.json"
            model.save(model_path, provenance=provenance)
            payload = json.loads(model_path.read_text(encoding="utf-8"))

        self.assertEqual(
            provenance["datasets"][0]["sha256"],
            hashlib.sha256(b'{"value": 1}\n').hexdigest(),
        )
        self.assertEqual(payload["artifact"]["schema_version"], "1.0.0")
        self.assertEqual(payload["artifact"]["provenance"]["parameters"]["epochs"], 2)

    def test_verification_detects_dataset_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "data.jsonl"
            dataset.write_text('{"value": 1}\n', encoding="utf-8")
            provenance = build_provenance(dataset_paths=[dataset])
            self.assertTrue(verify_provenance(provenance)["valid"])

            dataset.write_text('{"value": 2}\n', encoding="utf-8")
            report = verify_provenance(provenance)

        self.assertFalse(report["valid"])
        self.assertEqual(report["results"][0]["reason"], "size or SHA-256 mismatch")


if __name__ == "__main__":
    unittest.main()
