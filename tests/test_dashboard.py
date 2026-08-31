import tempfile
import unittest
from pathlib import Path

from ueba_detector.dashboard import generate_status_dashboard
from ueba_detector.readiness import audit_training_data, write_readiness_report
from ueba_detector.simulate import generate_normal_samples, generate_security_events
from ueba_detector.storage import write_jsonl


class DashboardTests(unittest.TestCase):
    def test_generates_self_contained_dashboard_from_audit(self):
        metrics = generate_normal_samples(count=20, seed=51)
        events = generate_security_events(metrics, seed=52)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metrics_path = root / "metrics.jsonl"
            events_path = root / "events.jsonl"
            readiness_path = root / "readiness.json"
            output_path = root / "dashboard.html"
            write_jsonl(metrics_path, metrics)
            write_jsonl(events_path, events)
            report = audit_training_data(
                metrics_path,
                events_path,
                minimum_windows=10,
                recommended_windows=30,
            )
            write_readiness_report(readiness_path, report)

            data = generate_status_dashboard(
                readiness_path=readiness_path,
                metrics_path=metrics_path,
                output_path=output_path,
            )
            html = output_path.read_text(encoding="utf-8")

        self.assertEqual(len(data["trends"]), 20)
        self.assertIn("Host Model Readiness", html)
        self.assertIn("process_started", html)
        self.assertNotIn("__DASHBOARD_DATA__", html)
        self.assertNotIn("https://", html)


if __name__ == "__main__":
    unittest.main()
