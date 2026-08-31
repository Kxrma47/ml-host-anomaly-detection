import json
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path
from unittest.mock import patch

from ueba_detector.event_collectors.authentication import (
    AuthLogCollector,
    SessionCollector,
    parse_auth_log_line,
)
from ueba_detector.event_collectors.packages import (
    PackageCollector,
    collect_installed_packages,
    parse_brew_output,
    parse_dpkg_output,
    parse_windows_package_output,
)
from ueba_detector.event_collectors.processes import ProcessCollector


class FakeProcess:
    def __init__(self, info):
        self.info = info
        self.pid = info["pid"]


class FakePsutil:
    class NoSuchProcess(Exception):
        pass

    class AccessDenied(Exception):
        pass

    def __init__(self):
        self.processes = []
        self.sessions = []

    def process_iter(self, _attributes):
        return [FakeProcess(info) for info in self.processes]

    def users(self):
        return self.sessions


def process(pid, created, *, name="python", command=None):
    return {
        "pid": pid,
        "ppid": 1,
        "name": name,
        "exe": f"/usr/bin/{name}",
        "username": "tester",
        "cmdline": command or [name],
        "create_time": created,
    }


class ProcessCollectorTests(unittest.TestCase):
    def test_emits_process_start_stop_and_redacts_secret(self):
        fake = FakePsutil()
        fake.processes = [process(10, 100.0)]
        collector = ProcessCollector(psutil_module=fake, host="host-1")

        baseline = collector.collect(None)
        self.assertEqual(baseline.events, [])

        fake.processes = [
            process(10, 101.0, command=["client", "--token", "fake-token"]),
        ]
        changed = collector.collect(baseline.state)
        self.assertEqual([event.event_type for event in changed.events], ["process_started", "process_stopped"])
        started = changed.events[0].to_dict()
        self.assertEqual(started["data"]["process"]["command_line"][-1], "[REDACTED]")


class AuthenticationCollectorTests(unittest.TestCase):
    def test_parses_ssh_success_failure_and_sudo(self):
        success_line = "Jan 1 host sshd[12]: Accepted publickey for alice from 10.0.0.2 port 55000 ssh2"
        success = parse_auth_log_line(
            success_line,
            host="host-1",
            source="auth.log",
        )
        failure = parse_auth_log_line(
            "Jan 1 host sshd[13]: Failed password for invalid user bob from 10.0.0.3 port 55001 ssh2",
            host="host-1",
            source="auth.log",
        )
        sudo = parse_auth_log_line(
            "Jan 1 host sudo: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=tool --password=fake",
            host="host-1",
            source="auth.log",
        )
        self.assertEqual(success.event_type, "authentication_success")
        replay = parse_auth_log_line(success_line, host="host-1", source="auth.log")
        self.assertEqual(success.event_id, replay.event_id)
        self.assertEqual(failure.status, "failure")
        self.assertEqual(failure.data["actor"]["user"]["name"], "bob")
        self.assertNotIn("fake", sudo.data["command_line"])

    def test_auth_log_tailer_only_reads_new_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.log"
            path.write_text(
                "Jan 1 host sshd[12]: Accepted publickey for old from 10.0.0.2 port 5000 ssh2\n",
                encoding="utf-8",
            )
            collector = AuthLogCollector([str(path)], host="host-1")
            baseline = collector.collect(None)
            self.assertEqual(baseline.events, [])

            with path.open("a", encoding="utf-8") as fh:
                fh.write("Jan 1 host sshd[13]: Failed password for bob from 10.0.0.3 port 5001 ssh2\n")
            changed = collector.collect(baseline.state)
            self.assertEqual(len(changed.events), 1)
            self.assertEqual(changed.events[0].event_type, "authentication_failure")

            replacement = Path(tmp) / "auth.log.new"
            replacement.write_text(
                "Jan 1 host sshd[14]: Accepted publickey for alice from 10.0.0.4 port 5002 ssh2\n",
                encoding="utf-8",
            )
            replacement.replace(path)
            rotated = collector.collect(changed.state)
            self.assertEqual(len(rotated.events), 1)
            self.assertEqual(rotated.events[0].event_type, "authentication_success")

    def test_session_diff(self):
        Session = namedtuple("Session", "name terminal host started pid")
        fake = FakePsutil()
        fake.sessions = [Session("alice", "pts/1", "10.0.0.2", 100.0, 20)]
        collector = SessionCollector(psutil_module=fake, host="host-1")
        baseline = collector.collect(None)
        fake.sessions = [Session("bob", "pts/2", "10.0.0.3", 200.0, 21)]
        changed = collector.collect(baseline.state)
        self.assertEqual([event.event_type for event in changed.events], ["session_started", "session_ended"])


class PackageCollectorTests(unittest.TestCase):
    def test_package_parsers(self):
        self.assertEqual(parse_dpkg_output("curl\t8.0\tamd64\n")[0]["version"], "8.0")
        self.assertEqual(parse_brew_output("wget 1.0 1.1\n")[0]["version"], "1.0,1.1")
        windows = json.dumps({"Name": "Tool", "Version": "2", "ProviderName": "msi"})
        self.assertEqual(parse_windows_package_output(windows)[0]["manager"], "msi")

    def test_detects_install_remove_and_update(self):
        inventories = [
            [
                {"name": "alpha", "version": "1", "architecture": "x64", "manager": "test"},
                {"name": "old", "version": "1", "architecture": "x64", "manager": "test"},
            ],
            [
                {"name": "alpha", "version": "2", "architecture": "x64", "manager": "test"},
                {"name": "new", "version": "1", "architecture": "x64", "manager": "test"},
            ],
        ]
        collector = PackageCollector(
            inventory_provider=lambda: inventories.pop(0),
            emit_initial_inventory=False,
            host="host-1",
        )
        baseline = collector.collect(None)
        changed = collector.collect(baseline.state)
        self.assertEqual(
            sorted(event.event_type for event in changed.events),
            ["package_installed", "package_removed", "package_updated"],
        )

    @patch("ueba_detector.event_collectors.packages.platform.system", return_value="Darwin")
    @patch("ueba_detector.event_collectors.packages.shutil.which", side_effect=lambda name: f"/usr/bin/{name}")
    @patch("ueba_detector.event_collectors.packages._run")
    def test_package_inventory_falls_back_when_one_source_fails(self, run, _which, _system):
        run.side_effect = [RuntimeError("brew unavailable"), "com.example.system-package\n"]
        packages = collect_installed_packages()
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["manager"], "pkgutil")


if __name__ == "__main__":
    unittest.main()
