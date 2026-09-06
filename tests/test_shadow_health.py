import os
import tempfile
import unittest
from pathlib import Path

from ueba_detector.shadow_health import build_shadow_health_report, write_shadow_health_report
from ueba_detector.storage import write_jsonl


class ShadowHealthTests(unittest.TestCase):
    def test_reports_aggregate_health_without_hostnames(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_jsonl(root / "metrics.jsonl", [
                {"timestamp": "2026-01-01T00:00:00Z", "host": "private-host"},
                {"timestamp": "2026-01-01T00:01:00Z", "host": "private-host"},
            ])
            write_jsonl(root / "events.jsonl", [
                {"timestamp": "2026-01-01T00:00:00Z", "event_type": "agent_heartbeat"},
            ])
            write_jsonl(root / "scores.jsonl", [
                {"timestamp": "2026-01-01T00:00:00Z", "ratio": 0.2, "is_anomaly": False, "rules": []},
            ])
            report = build_shadow_health_report(
                metrics_path=root / "metrics.jsonl", events_path=root / "events.jsonl",
                scores_path=root / "scores.jsonl", alerts_path=root / "missing.jsonl",
                now_epoch=1767225720.0,
            )
            self.assertEqual(report["state"], "healthy")
            self.assertEqual(report["metrics"]["coverage_ratio"], 1.0)
            self.assertNotIn("private-host", str(report))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are unavailable on Windows")
    def test_report_is_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            write_shadow_health_report(path, {"state": "healthy"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
