import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
            if os.name == "posix":
                self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
                self.assertEqual(os.stat(state).st_mode & 0o777, 0o600)

    def test_state_store_rejects_corrupt_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(ValueError):
                JsonStateStore(path).load()

    def test_agent_quarantines_corrupt_state_and_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "events.jsonl"
            state = root / "state.json"
            state.write_text("not-json", encoding="utf-8")
            agent = SecurityAgent(
                [CountingCollector()],
                output=output,
                state_path=state,
                heartbeat_interval=60,
                host="host-1",
            )
            rows = agent.collect_once(now_epoch=100.0)

            self.assertEqual(len(rows), 2)
            self.assertTrue(state.exists())
            self.assertEqual(len(list(root.glob("state.json.corrupt.*"))), 1)
            persisted = JsonStateStore(state).load()
            self.assertIn("recovered_corrupt_state", persisted["agent"])

    def test_persistence_failure_does_not_advance_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "events.jsonl"
            state = root / "state.json"
            agent = SecurityAgent(
                [CountingCollector()],
                output=output,
                state_path=state,
                heartbeat_interval=60,
                host="host-1",
            )
            with patch.object(agent.writer, "write_many", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    agent.collect_once(now_epoch=100.0)
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
