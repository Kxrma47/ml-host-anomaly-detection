import json
import tempfile
import unittest
from pathlib import Path

from ueba_detector.events import SecurityEvent
from ueba_detector.ocsf import OCSF_VERSION, upgrade_event_record, validate_ocsf_core
from ueba_detector.standards import (
    EXTERNAL_REQUIRED,
    FAIL,
    PASS,
    audit_ocsf_events,
    build_standards_report,
    standards_markdown,
)


def passing_evidence():
    return {
        "readiness": {
            "coverage": {"coverage_ratio": 0.99, "missing_windows": 10, "gap_count": 1},
            "combined": {"clean_windows": 10_080},
        },
        "metrics_validation": {"valid": True, "quality_score": 100, "records": 10_080},
        "events_validation": {"valid": True, "quality_score": 99.9, "records": 25_000},
        "ocsf_audit": {"valid": True, "records": 25_000, "invalid_records": 0},
        "model_comparison": {
            "split": {"strategy": "external_holdout", "train": 1000, "test": 200},
            "methods": {
                "autoencoder": {
                    "recall": 0.96,
                    "false_positive_rate": 0.04,
                    "precision": 0.90,
                }
            },
        },
        "stress": {
            "combined_rows": 10_000,
            "windows_per_second": 5_000,
            "peak_memory_bytes": 96 * 1024 * 1024,
        },
        "unit_tests": {"passed": True, "summary": "OK"},
    }


class StandardsTests(unittest.TestCase):
    def test_security_event_has_valid_ocsf_envelope(self):
        row = SecurityEvent(
            host="host-1",
            category_name="System Activity",
            class_name="Process Activity",
            activity_name="Launch",
            event_type="process_started",
            source="test",
            status="success",
            data={"process": {"pid": 42, "name": "worker"}},
        ).to_dict()

        self.assertEqual(row["ocsf"]["metadata"]["version"], OCSF_VERSION)
        self.assertEqual(row["ocsf"]["category_uid"], 1)
        self.assertEqual(row["ocsf"]["class_uid"], 1007)
        self.assertEqual(row["ocsf"]["activity_id"], 1)
        self.assertEqual(row["ocsf"]["type_uid"], 100701)
        self.assertEqual(validate_ocsf_core(row["ocsf"]), [])

    def test_legacy_event_is_upgraded_without_mutation(self):
        legacy = {
            "event_id": "legacy-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "host-1",
            "category_name": "Findings",
            "class_name": "Security Finding",
            "activity_name": "Collector Error",
            "event_type": "collector_error",
            "source": "test",
            "status": "failure",
            "severity": "low",
        }
        upgraded = upgrade_event_record(legacy)

        self.assertNotIn("ocsf", legacy)
        self.assertEqual(upgraded["ocsf"]["class_uid"], 2004)
        self.assertEqual(upgraded["ocsf"]["activity_name"], "Create")
        self.assertEqual(upgraded["ocsf"]["status"], "New")
        self.assertEqual(validate_ocsf_core(upgraded["ocsf"]), [])

    def test_tampered_type_uid_fails_core_validation(self):
        row = SecurityEvent(
            host="host-1",
            category_name="System Activity",
            class_name="Process Activity",
            activity_name="Launch",
            event_type="process_started",
            source="test",
            data={"process": {"pid": 42}},
        ).to_dict()
        row["ocsf"]["type_uid"] = 1

        self.assertIn("type_uid must equal 100701", validate_ocsf_core(row["ocsf"]))

    def test_stream_audit_supports_native_and_legacy_events(self):
        native = SecurityEvent(
            host="host-1",
            category_name="Discovery",
            class_name="Software Inventory Info",
            activity_name="Inventory",
            event_type="package_observed",
            source="test",
            data={"name": "package", "version": "1"},
        ).to_dict()
        legacy = {key: value for key, value in native.items() if key != "ocsf"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(
                json.dumps(native) + "\n" + json.dumps(legacy) + "\n",
                encoding="utf-8",
            )
            report = audit_ocsf_events(path)

        self.assertTrue(report["valid"])
        self.assertEqual(report["native_envelopes"], 1)
        self.assertEqual(report["legacy_records_migrated"], 1)

    def test_all_automated_controls_pass_but_certification_is_not_claimed(self):
        report = build_standards_report(**passing_evidence())

        self.assertTrue(report["automated_release_ready"])
        self.assertEqual(report["certification_status"], "NOT_CERTIFIED")
        mandatory = [item for item in report["controls"] if item["mandatory_release_gate"]]
        external = [item for item in report["controls"] if not item["mandatory_release_gate"]]
        self.assertTrue(all(item["status"] == PASS for item in mandatory))
        self.assertTrue(all(item["status"] == EXTERNAL_REQUIRED for item in external))
        self.assertIn("Automated release gate: **PASS**", standards_markdown(report))

    def test_coverage_and_model_thresholds_block_release(self):
        evidence = passing_evidence()
        evidence["readiness"]["coverage"]["coverage_ratio"] = 0.70
        evidence["model_comparison"]["methods"]["autoencoder"]["recall"] = 0.40
        report = build_standards_report(**evidence)

        self.assertFalse(report["automated_release_ready"])
        failed = {item["id"] for item in report["controls"] if item["status"] == FAIL}
        self.assertEqual(failed, {"DQ-ISO5259-003", "ML-ISO23894-001"})


if __name__ == "__main__":
    unittest.main()
