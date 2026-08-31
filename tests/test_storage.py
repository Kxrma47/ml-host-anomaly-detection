import os
import tempfile
import time
import unittest
from pathlib import Path

from ueba_detector.storage import RotatingJsonlWriter, jsonl_dataset_paths, read_jsonl_dataset


class StorageTests(unittest.TestCase):
    def test_rotation_compression_and_transparent_dataset_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            writer = RotatingJsonlWriter(path, max_bytes=90, compress=True)
            rows = [{"index": index, "message": "x" * 30} for index in range(6)]
            for row in rows:
                writer.write(row)

            segments = jsonl_dataset_paths(path)
            loaded = read_jsonl_dataset(path)
            modes = [segment.stat().st_mode & 0o777 for segment in segments]

        self.assertTrue(any(segment.name.endswith(".jsonl.gz") for segment in segments))
        self.assertEqual(loaded, rows)
        self.assertEqual(set(modes), {0o600})

    def test_retention_removes_only_expired_rotated_segments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.jsonl"
            writer = RotatingJsonlWriter(path, max_bytes=70, retention_days=1, compress=True)
            for index in range(4):
                writer.write({"index": index, "value": "y" * 30})
            rotated = [item for item in jsonl_dataset_paths(path) if item != path]
            self.assertTrue(rotated)
            old = time.time() - 2 * 86400
            for segment in rotated:
                os.utime(segment, (old, old))

            writer.enforce_retention()

            self.assertTrue(path.exists())
            self.assertEqual(jsonl_dataset_paths(path), [path])


if __name__ == "__main__":
    unittest.main()
