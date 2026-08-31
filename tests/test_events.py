import unittest

from ueba_detector.events import SecurityEvent
from ueba_detector.redaction import REDACTED, redact_command_line, redact_data, redact_text


class EventTests(unittest.TestCase):
    def test_event_serializes_normalized_fields(self):
        event = SecurityEvent(
            host="host-1",
            category_name="System Activity",
            class_name="Process Activity",
            activity_name="Launch",
            event_type="process_started",
            source="test",
            status="success",
            data={"process": {"pid": 42}},
        )
        row = event.to_dict()
        self.assertEqual(row["schema_version"], "1.0.0")
        self.assertEqual(row["data"]["process"]["pid"], 42)
        self.assertTrue(row["event_id"])
        self.assertTrue(row["timestamp"].endswith("Z"))

    def test_event_rejects_invalid_severity(self):
        with self.assertRaises(ValueError):
            SecurityEvent(
                host="host-1",
                category_name="Findings",
                class_name="Security Finding",
                activity_name="Create",
                event_type="finding",
                source="test",
                severity="urgent",
            )

    def test_redacts_command_line_and_nested_data(self):
        command = redact_command_line(
            [
                "client",
                "--password",
                "not-a-real-password",
                "--api-key=fake-key",
                "https://user:fake-secret@example.test/path",
            ]
        )
        self.assertEqual(command[2], REDACTED)
        self.assertIn("[REDACTED]", command[3])
        self.assertNotIn("fake-secret", command[4])

        value = redact_data({"password": "fake", "nested": {"token": "fake-token"}})
        self.assertEqual(value["password"], REDACTED)
        self.assertEqual(value["nested"]["token"], REDACTED)
        self.assertNotIn("fake-token", redact_text("Authorization: Bearer fake-token"))


if __name__ == "__main__":
    unittest.main()
