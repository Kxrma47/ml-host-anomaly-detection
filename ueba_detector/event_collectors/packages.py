from __future__ import annotations

import json
import platform
import shutil
import socket
import subprocess
from collections.abc import Callable
from typing import Any

from ..events import SecurityEvent, deterministic_event_id
from .base import CollectionResult


Package = dict[str, str]
InventoryProvider = Callable[[], list[Package]]


def _run(command: list[str], *, timeout: float = 30.0) -> str:
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        message = result.stderr.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"Package inventory command failed ({command[0]}): {message}")
    return result.stdout


def parse_dpkg_output(output: str) -> list[Package]:
    packages: list[Package] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip():
            continue
        packages.append(
            {
                "name": parts[0].strip(),
                "version": parts[1].strip(),
                "architecture": parts[2].strip() if len(parts) > 2 else "unknown",
                "manager": "dpkg",
            }
        )
    return packages


def parse_rpm_output(output: str) -> list[Package]:
    packages: list[Package] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip():
            continue
        packages.append(
            {
                "name": parts[0].strip(),
                "version": parts[1].strip(),
                "architecture": parts[2].strip() if len(parts) > 2 else "unknown",
                "manager": "rpm",
            }
        )
    return packages


def parse_brew_output(output: str) -> list[Package]:
    packages: list[Package] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        packages.append(
            {
                "name": parts[0],
                "version": ",".join(parts[1:]) if len(parts) > 1 else "unknown",
                "architecture": platform.machine() or "unknown",
                "manager": "homebrew",
            }
        )
    return packages


def parse_pkgutil_output(output: str) -> list[Package]:
    return [
        {
            "name": line.strip(),
            "version": "unknown",
            "architecture": platform.machine() or "unknown",
            "manager": "pkgutil",
        }
        for line in output.splitlines()
        if line.strip()
    ]


def parse_windows_package_output(output: str) -> list[Package]:
    if not output.strip():
        return []
    payload = json.loads(output)
    rows = payload if isinstance(payload, list) else [payload]
    packages: list[Package] = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("Name"):
            continue
        packages.append(
            {
                "name": str(row["Name"]),
                "version": str(row.get("Version") or "unknown"),
                "architecture": "unknown",
                "manager": str(row.get("ProviderName") or "powershell"),
            }
        )
    return packages


def collect_installed_packages() -> list[Package]:
    system = platform.system().lower()
    packages: list[Package] = []
    errors: list[str] = []

    def attempt(command: list[str], parser: Callable[[str], list[Package]], *, timeout: float = 30.0) -> None:
        try:
            packages.extend(parser(_run(command, timeout=timeout)))
        except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            errors.append(f"{command[0]}: {exc}")

    if system == "linux":
        if shutil.which("dpkg-query"):
            attempt(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
                parse_dpkg_output,
            )
        if shutil.which("rpm"):
            attempt(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"], parse_rpm_output)
    elif system == "darwin":
        if shutil.which("brew"):
            attempt(["brew", "list", "--versions"], parse_brew_output)
        if shutil.which("pkgutil"):
            attempt(["pkgutil", "--pkgs"], parse_pkgutil_output)
    elif system == "windows":
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if powershell:
            script = "Get-Package | Select-Object Name,Version,ProviderName | ConvertTo-Json -Compress"
            attempt(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                parse_windows_package_output,
                timeout=60.0,
            )

    if not packages:
        detail = "; ".join(errors) if errors else "no supported package manager was found"
        raise RuntimeError(f"No package inventory available for {platform.system()}: {detail}")
    return packages


def _package_key(package: Package) -> str:
    return "|".join(
        package.get(name, "unknown") for name in ("manager", "name", "architecture")
    )


class PackageCollector:
    name = "packages"

    def __init__(
        self,
        *,
        interval_seconds: float = 300.0,
        emit_initial_inventory: bool = True,
        inventory_provider: InventoryProvider | None = None,
        host: str | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.emit_initial_inventory = emit_initial_inventory
        self.inventory_provider = inventory_provider or collect_installed_packages
        self.host = host or socket.gethostname()

    def _event(
        self,
        package: Package,
        *,
        event_type: str,
        activity_name: str,
        previous_version: str | None = None,
    ) -> SecurityEvent:
        data: dict[str, Any] = {"package": package}
        if previous_version is not None:
            data["previous_version"] = previous_version
        event_id = deterministic_event_id(
            self.host,
            event_type,
            _package_key(package),
            package.get("version", "unknown"),
            previous_version or "",
        )
        return SecurityEvent(
            host=self.host,
            category_name="Discovery",
            class_name="Software Inventory Info",
            activity_name=activity_name,
            event_type=event_type,
            source=package.get("manager", "package_inventory"),
            status="success",
            event_id=event_id,
            data=data,
        )

    def collect(self, previous_state: dict[str, Any] | None) -> CollectionResult:
        current = {_package_key(package): package for package in self.inventory_provider()}
        previous_state = previous_state or {}
        previous = previous_state.get("packages", {})
        initialized = bool(previous_state.get("initialized"))
        events: list[SecurityEvent] = []

        if not initialized:
            if self.emit_initial_inventory:
                events.extend(
                    self._event(package, event_type="package_observed", activity_name="Inventory")
                    for _, package in sorted(current.items())
                )
        else:
            for key in sorted(set(current) - set(previous)):
                events.append(self._event(current[key], event_type="package_installed", activity_name="Install"))
            for key in sorted(set(previous) - set(current)):
                events.append(self._event(previous[key], event_type="package_removed", activity_name="Remove"))
            for key in sorted(set(current) & set(previous)):
                old_version = previous[key].get("version", "unknown")
                if current[key].get("version", "unknown") != old_version:
                    events.append(
                        self._event(
                            current[key],
                            event_type="package_updated",
                            activity_name="Update",
                            previous_version=old_version,
                        )
                    )

        return CollectionResult(events=events, state={"initialized": True, "packages": current})
