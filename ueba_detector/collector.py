from __future__ import annotations

import os
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from .storage import RotatingJsonlWriter


def parse_duration(value: str | None) -> float | None:
    if value is None:
        return None
    raw = value.strip().lower()
    if not raw:
        return None
    multiplier = 1.0
    if raw.endswith("ms"):
        multiplier = 0.001
        raw = raw[:-2]
    elif raw.endswith("s"):
        raw = raw[:-1]
    elif raw.endswith("m"):
        multiplier = 60.0
        raw = raw[:-1]
    elif raw.endswith("h"):
        multiplier = 3600.0
        raw = raw[:-1]
    return float(raw) * multiplier


def _psutil():
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError("Live collection requires psutil. Install it with: pip install -r requirements.txt") from exc
    return psutil


def _empty_tcp_stats() -> dict[str, int]:
    return {
        "tcp_established": 0,
        "tcp_listen": 0,
        "tcp_syn_sent": 0,
        "tcp_close_wait": 0,
        "unique_remote_ports": 0,
    }


def _remote_port(endpoint: str) -> int | None:
    if not endpoint or endpoint.startswith("*") or ":" not in endpoint:
        return None
    raw = endpoint.rsplit(":", 1)[-1]
    return int(raw) if raw.isdigit() else None


def tcp_stats_from_lsof_output(output: str) -> dict[str, int]:
    stats = _empty_tcp_stats()
    remote_ports: set[int] = set()
    seen_connections: set[tuple[str, str]] = set()

    for line in output.splitlines():
        if " TCP " not in line:
            continue
        name = line.split(" TCP ", 1)[1].strip()
        if "(" in name and name.endswith(")"):
            endpoint, status = name.rsplit("(", 1)
            status = status[:-1].strip().upper().replace("-", "_")
            endpoint = endpoint.strip()
        else:
            endpoint = name
            status = ""

        key = (endpoint, status)
        if key in seen_connections:
            continue
        seen_connections.add(key)

        if status == "ESTABLISHED":
            stats["tcp_established"] += 1
        elif status == "LISTEN":
            stats["tcp_listen"] += 1
        elif status == "SYN_SENT":
            stats["tcp_syn_sent"] += 1
        elif status == "CLOSE_WAIT":
            stats["tcp_close_wait"] += 1

        if "->" in endpoint:
            port = _remote_port(endpoint.split("->", 1)[1].strip())
            if port is not None:
                remote_ports.add(port)

    stats["unique_remote_ports"] = len(remote_ports)
    return stats


def tcp_stats_from_netstat_output(output: str) -> dict[str, int]:
    stats = _empty_tcp_stats()
    remote_ports: set[int] = set()
    states = {"ESTABLISHED", "LISTEN", "LISTENING", "SYN_SENT", "CLOSE_WAIT"}

    for line in output.splitlines():
        parts = line.split()
        if not parts or not parts[0].lower().startswith("tcp"):
            continue

        state_idx = -1
        state = ""
        for idx, part in enumerate(parts):
            value = part.upper().replace("-", "_")
            if value in states:
                state_idx = idx
                state = value
                break
        if state_idx < 0:
            continue

        if state == "ESTABLISHED":
            stats["tcp_established"] += 1
        elif state in {"LISTEN", "LISTENING"}:
            stats["tcp_listen"] += 1
        elif state == "SYN_SENT":
            stats["tcp_syn_sent"] += 1
        elif state == "CLOSE_WAIT":
            stats["tcp_close_wait"] += 1

        if state_idx >= 1:
            port = _remote_port(parts[state_idx - 1])
            if port is not None and port != 0:
                remote_ports.add(port)

    stats["unique_remote_ports"] = len(remote_ports)
    return stats


def _tcp_stats_from_lsof() -> dict[str, int] | None:
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-iTCP"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode not in (0, 1) or not result.stdout.strip():
        return None
    return tcp_stats_from_lsof_output(result.stdout)


def _tcp_stats_from_netstat() -> dict[str, int] | None:
    for command in (["netstat", "-ano", "-p", "tcp"], ["netstat", "-ant"]):
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=3.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout.strip():
            return tcp_stats_from_netstat_output(result.stdout)
    return None


def _tcp_stats_from_system_tools() -> dict[str, int] | None:
    return _tcp_stats_from_lsof() or _tcp_stats_from_netstat()


def process_stats_from_ps_output(output: str, current_user: str | None = None) -> dict[str, int]:
    process_count = 0
    user_process_count = 0
    thread_count = 0

    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        username = parts[0]
        try:
            threads = int(parts[-1])
        except ValueError:
            threads = 0
        process_count += 1
        thread_count += max(0, threads)
        if current_user and current_user in username:
            user_process_count += 1

    return {
        "process_count": process_count,
        "user_process_count": user_process_count,
        "thread_count": thread_count,
    }


def _process_stats_from_ps(current_user: str | None = None) -> dict[str, int] | None:
    for command in (["ps", "-axo", "user,pid,thcount"], ["ps", "-axo", "user,pid,nlwp"]):
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=3.0)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout.strip():
            return process_stats_from_ps_output(result.stdout, current_user=current_user)
    return None


class TelemetryCollector:
    def __init__(self) -> None:
        self.psutil = _psutil()
        self.host = socket.gethostname()
        self.prev_time: float | None = None
        self.prev_net: Any = None
        self.prev_disk: Any = None

    @staticmethod
    def _rate(current: float, previous: float | None, dt: float) -> float:
        if previous is None or dt <= 0:
            return 0.0
        return max(0.0, (current - previous) / dt)

    def sample(self) -> dict[str, Any]:
        psutil = self.psutil
        now = time.time()
        dt = max(1e-6, now - self.prev_time) if self.prev_time is not None else 0.0

        vm = psutil.virtual_memory()
        try:
            swap_percent = psutil.swap_memory().percent
        except (OSError, RuntimeError):
            swap_percent = 0.0

        try:
            net = psutil.net_io_counters()
        except (OSError, RuntimeError):
            net = None

        try:
            disk = psutil.disk_io_counters()
        except (OSError, RuntimeError):
            disk = None

        current_user = os.environ.get("USER") or os.environ.get("USERNAME")
        process_stats = {"process_count": 0, "user_process_count": 0, "thread_count": 0}
        try:
            for proc in psutil.process_iter(["username", "num_threads"]):
                try:
                    process_stats["process_count"] += 1
                    info = proc.info
                    process_stats["thread_count"] += int(info.get("num_threads") or 0)
                    if current_user and info.get("username") and current_user in str(info.get("username")):
                        process_stats["user_process_count"] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.AccessDenied, PermissionError, OSError):
            fallback_process_stats = _process_stats_from_ps(current_user)
            if fallback_process_stats is not None:
                process_stats = fallback_process_stats
        if process_stats["process_count"] == 0:
            fallback_process_stats = _process_stats_from_ps(current_user)
            if fallback_process_stats is not None:
                process_stats = fallback_process_stats

        tcp_stats = _empty_tcp_stats()
        remote_ports: set[int] = set()
        try:
            for conn in psutil.net_connections(kind="inet"):
                status = str(conn.status).upper()
                if status == "ESTABLISHED":
                    tcp_stats["tcp_established"] += 1
                elif status == "LISTEN":
                    tcp_stats["tcp_listen"] += 1
                elif status == "SYN_SENT":
                    tcp_stats["tcp_syn_sent"] += 1
                elif status == "CLOSE_WAIT":
                    tcp_stats["tcp_close_wait"] += 1
                if conn.raddr:
                    remote_ports.add(int(conn.raddr.port))
        except (psutil.AccessDenied, PermissionError):
            fallback_stats = _tcp_stats_from_system_tools()
            if fallback_stats is not None:
                tcp_stats = fallback_stats

        if remote_ports:
            tcp_stats["unique_remote_ports"] = len(remote_ports)
        elif sum(tcp_stats.values()) == 0:
            fallback_stats = _tcp_stats_from_system_tools()
            if fallback_stats is not None:
                tcp_stats = fallback_stats

        try:
            loadavg_1m = os.getloadavg()[0]
        except (AttributeError, OSError):
            loadavg_1m = 0.0

        sample = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "host": self.host,
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": vm.percent,
            "swap_percent": swap_percent,
            "loadavg_1m": loadavg_1m,
            "process_count": process_stats["process_count"],
            "user_process_count": process_stats["user_process_count"],
            "thread_count": process_stats["thread_count"],
            "net_bytes_sent_per_sec": self._rate(net.bytes_sent, getattr(self.prev_net, "bytes_sent", None), dt) if net else 0.0,
            "net_bytes_recv_per_sec": self._rate(net.bytes_recv, getattr(self.prev_net, "bytes_recv", None), dt) if net else 0.0,
            "net_packets_sent_per_sec": self._rate(net.packets_sent, getattr(self.prev_net, "packets_sent", None), dt) if net else 0.0,
            "net_packets_recv_per_sec": self._rate(net.packets_recv, getattr(self.prev_net, "packets_recv", None), dt) if net else 0.0,
            "net_errin_per_sec": self._rate(net.errin, getattr(self.prev_net, "errin", None), dt) if net else 0.0,
            "net_errout_per_sec": self._rate(net.errout, getattr(self.prev_net, "errout", None), dt) if net else 0.0,
            "net_dropin_per_sec": self._rate(net.dropin, getattr(self.prev_net, "dropin", None), dt) if net else 0.0,
            "net_dropout_per_sec": self._rate(net.dropout, getattr(self.prev_net, "dropout", None), dt) if net else 0.0,
            "disk_read_bytes_per_sec": self._rate(disk.read_bytes, getattr(self.prev_disk, "read_bytes", None), dt) if disk else 0.0,
            "disk_write_bytes_per_sec": self._rate(disk.write_bytes, getattr(self.prev_disk, "write_bytes", None), dt) if disk else 0.0,
            "tcp_established": tcp_stats["tcp_established"],
            "tcp_listen": tcp_stats["tcp_listen"],
            "tcp_syn_sent": tcp_stats["tcp_syn_sent"],
            "tcp_close_wait": tcp_stats["tcp_close_wait"],
            "unique_remote_ports": tcp_stats["unique_remote_ports"],
        }

        self.prev_time = now
        self.prev_net = net
        self.prev_disk = disk
        return sample


def collect_to_file(
    output: str,
    *,
    interval: float,
    duration: float | None,
    max_file_bytes: int = 0,
    retention_days: float | None = None,
    compress_rotated: bool = True,
) -> None:
    collector = TelemetryCollector()
    writer = RotatingJsonlWriter(
        output,
        max_bytes=max_file_bytes,
        retention_days=retention_days,
        compress=compress_rotated,
    )
    started = time.time()
    while True:
        sample = collector.sample()
        writer.write(sample)
        print(f"{sample['timestamp']} collected host sample", flush=True)
        if duration is not None and time.time() - started >= duration:
            break
        time.sleep(interval)
