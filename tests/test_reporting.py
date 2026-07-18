import tempfile
import unittest
from pathlib import Path

from ueba_detector.autoencoder import Score
from ueba_detector.reporting import build_anomaly_event, write_text_summary


class ReportingTests(unittest.TestCase):
    def test_build_event_and_summary(self):
        score = Score(
            error=2.0,
            threshold=1.0,
            ratio=2.0,
            is_anomaly=True,
            severity="medium",
            top_features=[{"feature": "tcp_syn_sent", "contribution": 2.0}],
        )
        event = build_anomaly_event({"timestamp": "t", "host": "h"}, score, model_path="m.json")
        self.assertEqual(event["category"], "network_anomaly")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.txt"
            write_text_summary([event], path)
            self.assertIn("network_anomaly", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
