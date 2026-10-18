import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ueba_detector.adapters import adapt_optc
from ueba_detector.research_pilot import run_optc_prefix_pilot


SALT = "synthetic-pilot-salt-2026"
INGESTED_AT = "2026-10-19T00:00:00Z"


def _row(index=0):
    return {
        "timestamp": 1_760_000_000_000 + index * 1000,
        "hostname": "private-test-host",
        "object": "FILE",
        "action": "WRITE",
        "actorID": "private-process-id",
        "objectID": f"private-file-id-{index}",
        "properties": {"path": "/private/test-canary.txt", "command_line": "--password test-canary"},
    }


class OptcPrefixPilotTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "sample.json.gz"

    def write(self, payload):
        self.path.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    def run_pilot(self, digest, **kwargs):
        return run_optc_prefix_pilot(
            self.path, expected_sha256=digest, salt=SALT, ingested_at=INGESTED_AT,
            **kwargs,
        )

    def test_checksum_gated_aggregate_report(self):
        rows = [_row(0), _row(1), _row(2)]
        payload = gzip.compress(b"".join(json.dumps(row).encode() + b"\n" for row in rows), mtime=0)
        digest = self.write(payload)
        report = self.run_pilot(digest, max_events=2)
        self.assertEqual(report["stats"]["input_events"], 2)
        self.assertEqual(report["edge_count"], 2)
        self.assertEqual(report["object_counts"], {"file": 2})
        self.assertFalse(report["full_dataset_verified"])
        self.assertFalse(report["labels_verified"])
        self.assertEqual(report["source_sha256"], digest)
        encoded = json.dumps(report)
        self.assertNotIn("private-test-host", encoded)
        self.assertNotIn("test-canary", encoded)

    def test_wrong_checksum_and_oversized_source_fail_before_parsing(self):
        digest = self.write(gzip.compress(json.dumps(_row()).encode() + b"\n", mtime=0))
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.run_pilot("0" * 64)
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.run_pilot(digest, max_source_bytes=10)
        with self.assertRaisesRegex(ValueError, "max_events"):
            self.run_pilot(digest, max_events=10_001)

    def test_truncated_gzip_and_invalid_records_fail_closed(self):
        payload = gzip.compress(json.dumps(_row()).encode() + b"\n", mtime=0)
        digest = self.write(payload[:-8])
        with self.assertRaisesRegex(ValueError, "compressed source ended"):
            self.run_pilot(digest)
        digest = self.write(gzip.compress(b"not-json\n", mtime=0))
        with self.assertRaisesRegex(ValueError, "not valid JSON"):
            self.run_pilot(digest)
        digest = self.write(gzip.compress(b"[]\n", mtime=0))
        with self.assertRaisesRegex(ValueError, "must be an object"):
            self.run_pilot(digest)
        digest = self.write(gzip.compress(b"x" * (64 * 1024 + 1) + b"\n", mtime=0))
        with self.assertRaisesRegex(ValueError, "line limit"):
            self.run_pilot(digest)

    def test_untrusted_free_text_categories_are_not_retained(self):
        row = _row()
        row.update({"object": "SECRET=private-test-canary", "action": "PASSWORD=private-test-canary",
                    "label": "token=private-test-canary", "scenario": "private-test-canary"})
        event = adapt_optc(row, 0, salt=SALT)
        self.assertEqual(event["data"]["native_object"], "unknown")
        self.assertEqual(event["data"]["native_action"], "unknown")
        self.assertIsNone(event["data"]["label"])
        self.assertNotIn("private-test-canary", json.dumps(event))
        digest = self.write(gzip.compress(json.dumps(row).encode() + b"\n", mtime=0))
        report = self.run_pilot(digest)
        self.assertEqual(report["stats"]["unsupported_events"], 1)
        self.assertNotIn("private-test-canary", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
