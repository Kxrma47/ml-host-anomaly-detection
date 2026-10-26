import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from ueba_detector.research_tc_archive import run_tc_archive_pilot


SALT = "synthetic-tc-archive-salt-2026"
INGESTED_AT = "2026-10-19T00:00:00Z"


def _records(include_file=True):
    rows = [{"datum": {"com.bbn.tc.schema.avro.cdm18.Subject": {
        "uuid": "raw-subject", "hostId": "raw-host", "cmdLine": "--password private-canary"}}}]
    if include_file:
        rows.append({"datum": {"com.bbn.tc.schema.avro.cdm18.FileObject": {
            "uuid": "raw-file", "path": "/private/private-canary.txt"}}})
    rows.append({"datum": {"com.bbn.tc.schema.avro.cdm18.Event": {
        "uuid": "raw-event", "type": "EVENT_WRITE", "hostId": "raw-host",
        "timestampNanos": 1_760_000_000_000_000_000,
        "subject": "raw-subject", "predicateObject": "raw-file"}}})
    return rows


def _archive(*members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, payload, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "outside"
                archive.addfile(info)
            else:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _jsonl(rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


class TcArchivePilotTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "source.tar.gz"

    def run_pilot(self, payload, **kwargs):
        self.path.write_bytes(payload)
        return run_tc_archive_pilot(
            self.path, expected_sha256=hashlib.sha256(payload).hexdigest(),
            salt=SALT, ingested_at=INGESTED_AT, **kwargs,
        )

    def test_complete_archive_is_hashed_audited_and_sampled(self):
        payload = _archive(("events.json", _jsonl(_records()), "file"),
                           ("other.json", _jsonl(_records()), "file"))
        report = self.run_pilot(payload, max_source_rows=3)
        self.assertTrue(report["full_archive_verified"])
        self.assertFalse(report["full_dataset_verified"])
        self.assertFalse(report["labels_verified"])
        self.assertEqual(report["archive_member_count"], 2)
        self.assertEqual(report["sampled_source_rows"], 3)
        self.assertEqual(report["edge_count"], 1)
        self.assertEqual(report["stats"]["unresolved_reference_events"], 0)
        self.assertNotIn("private-canary", json.dumps(report))

    def test_unresolved_reference_is_not_a_file_edge(self):
        payload = _archive(("events.json", _jsonl(_records(include_file=False)), "file"))
        report = self.run_pilot(payload)
        self.assertEqual(report["edge_count"], 0)
        self.assertEqual(report["stats"]["unresolved_reference_events"], 1)
        self.assertEqual(report["stats"]["unsupported_events"], 1)

    def test_unsafe_members_are_rejected_without_extraction(self):
        rows = _jsonl(_records())
        for members in (
            (("../escape.json", rows, "file"),),
            (("events.json", rows, "file"), ("events.json", rows, "file")),
            (("events.json", rows, "file"), ("link", b"", "symlink")),
        ):
            with self.subTest(members=members[-1][0]):
                with self.assertRaisesRegex(ValueError, "unsafe|unsupported"):
                    self.run_pilot(_archive(*members))

    def test_bad_hash_truncated_archive_and_size_limit_fail(self):
        payload = _archive(("events.json", _jsonl(_records()), "file"))
        self.path.write_bytes(payload)
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            run_tc_archive_pilot(
                self.path, expected_sha256="0" * 64, salt=SALT, ingested_at=INGESTED_AT,
            )
        with self.assertRaisesRegex(ValueError, "compressed size limit"):
            self.run_pilot(payload, max_compressed_bytes=10)
        with self.assertRaisesRegex(ValueError, "incomplete or unreadable"):
            self.run_pilot(payload[:-8])

    def test_invalid_record_and_expanded_limit_fail(self):
        payload = _archive(("events.json", b"not-json\n", "file"))
        with self.assertRaisesRegex(ValueError, "not valid JSON"):
            self.run_pilot(payload)
        payload = _archive(("events.json", _jsonl(_records()), "file"))
        with self.assertRaisesRegex(ValueError, "expanded size limit"):
            self.run_pilot(payload, max_expanded_bytes=10)


if __name__ == "__main__":
    unittest.main()
