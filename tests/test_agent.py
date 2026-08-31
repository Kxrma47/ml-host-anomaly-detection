import os
import tempfile
import unittest
from pathlib import Path

from ueba_detector.agent import SecurityAgent
from ueba_detector.event_collectors.base import CollectionResult
from ueba_detector.events import SecurityEvent
from ueba_detector.state import JsonStateStore
from ueba_detector.storage import read_jsonl


class CountingCollector:
    name = "counting"
    interval_seconds = 10.0

    def __init__(self):
        self.calls = 0

    def collect(self, previous_state):
        self.calls += 1
        event = SecurityEvent(
            host="host-1",
            category_name="System Activity",
            class_name="Process Activity",
            activity_name="Launch",
            event_type="test_event",
            source="test",
            data={"token": "fake-token"},
        )
        return CollectionResult([event], {"calls": self.calls})


class FailingCollector:
    name = "failing"
    interval_seconds = 10.0

    def collect(self, previous_state):
        raise RuntimeError("token=fake-token")


class AgentTests(unittest.TestCase):
    def test_agent_isolates_failures_redacts_and_schedules(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "events.jsonl"
            state = Path(tmp) / "state.json"
            counting = CountingCollector()
            agent = SecurityAgent(
                [counting, FailingCollector()],
                output=output,
                state_path=state,
                heartbeat_interval=60,
                host="host-1",
            )
            first = agent.collect_once(now_epoch=100.0)
            second = agent.collect_once(now_epoch=101.0)

            self.assertEqual(counting.calls, 1)
            self.assertEqual(second, [])
            self.assertEqual(len(first), 3)
            self.assertEqual(first[0]["data"]["token"], "[REDACTED]")
            self.assertNotIn("fake-token", first[1]["data"]["message"])
            self.assertEqual(len(read_jsonl(output)), 3)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(state).st_mode & 0o777, 0o600)

    def test_state_store_rejects_corrupt_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(ValueError):
                JsonStateStore(path).load()


if __name__ == "__main__":
    unittest.main()
