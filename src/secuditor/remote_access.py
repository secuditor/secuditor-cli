# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform remote-access service and exposure diagnostics."""

from __future__ import annotations

import platform
import shutil
import socket
import subprocess
from typing import Any

__all__ = ["RemoteAccess"]

class RemoteAccessAudit:
    """Inspect common remote-access services and local TCP listeners.

    Results are structured data. This module does not print reports,
    start console animations, or require administrator privileges.

    A detected local listener does not prove that a service is reachable
    from another computer. Firewall and network-path checks are separate.
    """

    PORTS = {
        "SSH": (22,),
        "Telnet": (23,),
        "SMB": (445,),
        "NetBIOS": (139,),
        "RDP": (3389,),
        "VNC": (5900, 5901, 5902),
        "WinRM": (5985, 5986),
        "rsync": (873,),
    }

    def __init__(self, timeout: float = 1.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        self.timeout = timeout
        self.system = platform.system().lower()

    @staticmethod
    def _result(
        status: str,
        *,
        details: dict[str, Any] | None = None,
        risk: str = "Unknown",
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "risk": risk,
            "details": details or {},
            "reason": reason,
        }

    def _run(
        self,
        command: list[str],
        *,
        timeout: float = 5.0,
    ) -> tuple[bool, str]:
        """Run a command without a shell; report success and stdout."""

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False, ""

        return completed.returncode == 0, completed.stdout.strip()

    def _powershell(self, script: str) -> tuple[bool, str]:
        """Run a PowerShell script on Windows."""

        executable = shutil.which("powershell") or shutil.which("pwsh")
        if not executable:
            return False, ""

        return self._run(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ]
        )

    def _windows_registry_value(
        self,
        key_path: str,
        value_name: str,
    ) -> Any | None:
        """Read a Windows registry value; None means unavailable."""

        if self.system != "windows":
            return None

        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                return value
        except (OSError, ImportError):
            return None

    def _windows_service(self, name: str) -> dict[str, Any]:
        """Inspect a Windows service using sc.exe."""

        executable = shutil.which("sc.exe") or shutil.which("sc")
        if not executable:
            return self._result(
                "unknown",
                reason="Service control utility is unavailable.",
            )

        ok, output = self._run(
            [executable, "query", name],
            timeout=self.timeout + 2,
        )

        if not ok:
            return self._result(
                "unknown",
                reason=f"Unable to query service {name}.",
            )

        normalized = output.upper()

        if "STATE" in normalized and "RUNNING" in normalized:
            status = "running"
        elif "STATE" in normalized and "STOPPED" in normalized:
            status = "stopped"
        else:
            status = "unknown"

        return self._result(
            status,
            details={"service_name": name},
        )

    def _unix_service(self, name: str) -> dict[str, Any]:
        """Best-effort service status on Linux and macOS."""

        if self.system == "linux":
            systemctl = shutil.which("systemctl")
            if not systemctl:
                return self._result(
                    "unknown",
                    reason="systemctl is unavailable.",
                )

            ok, output = self._run(
                [systemctl, "is-active", name],
                timeout=self.timeout + 2,
            )

            if output == "active":
                status = "running"
            elif output in ("inactive", "failed"):
                status = "stopped"
            elif output == "unknown":
                status = "not_found"
            else:
                status = "unknown"

            return self._result(
                status,
                details={"service_name": name},
                reason=None if ok else "Service state could not be confirmed.",
            )

        if self.system == "darwin":
            launchctl = shutil.which("launchctl")
            if not launchctl:
                return self._result(
                    "unknown",
                    reason="launchctl is unavailable.",
                )

            ok, output = self._run(
                [launchctl, "list"],
                timeout=self.timeout + 2,
            )

            if not ok:
                return self._result(
                    "unknown",
                    reason="Unable to query launch services.",
                )

            matches = [
                line for line in output.splitlines()
                if name.lower() in line.lower()
            ]

            return self._result(
                "running" if matches else "unknown",
                details={"matching_services": matches},
                reason=(
                    None if matches
                    else "No matching launch service was identified."
                ),
            )

        return self._result(
            "unsupported",
            reason="Service inspection is not implemented for this OS.",
        )

    def _service(self, windows_name: str, unix_names: tuple[str, ...]) -> dict:
        if self.system == "windows":
            return self._windows_service(windows_name)

        for name in unix_names:
            result = self._unix_service(name)
            if result["status"] in ("running", "stopped"):
                return result

        return self._result(
            "unknown",
            reason="No service manager result could confirm this service.",
        )

    def _local_listeners(self, ports: tuple[int, ...]) -> list[int]:
        """Find TCP ports accepting connections on loopback."""

        listening = []

        for port in ports:
            try:
                with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                ) as sock:
                    sock.settimeout(self.timeout)
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        listening.append(port)
            except OSError:
                continue

        return listening

    def _audit_windows_rdp(self) -> dict[str, Any]:
        path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        enabled_value = self._windows_registry_value(
            path,
            "fDenyTSConnections",
        )

        if enabled_value is None:
            return self._result(
                "unknown",
                reason="RDP registry configuration is unavailable.",
            )

        enabled = enabled_value == 0
        details: dict[str, Any] = {"enabled": enabled}

        if not enabled:
            return self._result(
                "disabled",
                details=details,
                risk="Low",
            )

        security_path = (
            r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            r"\WinStations\RDP-Tcp"
        )
        nla = self._windows_registry_value(
            security_path,
            "UserAuthentication",
        )
        encryption = self._windows_registry_value(
            security_path,
            "MinEncryptionLevel",
        )

        details.update({
            "network_level_authentication": (
                nla == 1 if nla is not None else None
            ),
            "minimum_encryption_level": encryption,
            "local_listener_ports": self._local_listeners((3389,)),
        })

        if nla == 1 and encryption is not None and encryption >= 2:
            risk = "Lower"
        else:
            risk = "Elevated"

        return self._result(
            "enabled",
            details=details,
            risk=risk,
            reason=(
                "This is a configuration-based assessment, not a "
                "verification of remote reachability."
            ),
        )

    def _audit_windows_remote_assistance(self) -> dict[str, Any]:
        path = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"
        value = self._windows_registry_value(path, "fAllowToGetHelp")

        if value is None:
            return self._result(
                "unknown",
                reason="Remote Assistance configuration is unavailable.",
            )

        enabled = value == 1
        return self._result(
            "enabled" if enabled else "disabled",
            details={"enabled": enabled},
            risk="Review" if enabled else "Low",
        )

    def _audit_windows_winrm(self) -> dict[str, Any]:
        service = self._windows_service("WinRM")
        listeners_ok, listeners_output = self._powershell(
            "$ErrorActionPreference='Stop'; "
            "Get-ChildItem WSMan:\\localhost\\Listener | "
            "ForEach-Object { $_.Keys -join ';' }"
        )

        listeners = []
        if listeners_ok:
            text = listeners_output.lower()
            listeners = [
                transport
                for transport in ("http", "https")
                if transport in text
            ]

        ports = self._local_listeners((5985, 5986))
        basic = self._windows_registry_value(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion"
            r"\WSMAN\Service\Auth",
            "Basic",
        )
        allow_unencrypted = self._windows_registry_value(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service",
            "AllowUnencrypted",
        )

        details = {
            "service": service["status"],
            "listeners": listeners if listeners_ok else None,
            "local_listener_ports": ports,
            "basic_authentication_enabled": (
                bool(basic) if basic is not None else None
            ),
            "allow_unencrypted": (
                bool(allow_unencrypted)
                if allow_unencrypted is not None else None
            ),
        }

        if service["status"] != "running":
            risk = "Unknown" if service["status"] == "unknown" else "Low"
        elif basic:
            risk = "Elevated"
        elif allow_unencrypted:
            risk = "High"
        elif ports:
            risk = "Review"
        else:
            risk = "Unknown"

        return self._result(
            service["status"],
            details=details,
            risk=risk,
            reason=(
                "Local listener checks do not establish remote reachability. "
                "A complete WinRM assessment should also inspect firewall "
                "rules, authentication policy, and listener bindings."
            ),
        )

    def audit(self) -> dict[str, Any]:
        """Run available checks and return structured results."""

        checks: dict[str, Any] = {}

        if self.system == "windows":
            checks["remote_desktop"] = self._audit_windows_rdp()
            checks["remote_assistance"] = (
                self._audit_windows_remote_assistance()
            )
            checks["winrm"] = self._audit_windows_winrm()
            checks["dcom"] = self._result(
                "unknown",
                reason=(
                    "DCOM configuration assessment is not included "
                    "in this initial cross-platform implementation."
                ),
            )
            checks["smb"] = self._result(
                "unknown",
                details={"local_listener_ports": self._local_listeners((139, 445))},
                reason=(
                    "SMB protocol versions, signing, encryption, and share "
                    "permissions require a separate configuration audit."
                ),
            )
            checks["print_spooler"] = self._windows_service("Spooler")
            checks["upnp_host"] = self._windows_service("upnphost")
            checks["bluetooth_service"] = self._windows_service("bthserv")
            checks["telnet_service"] = self._windows_service("TlntSvr")
            checks["rsync_service"] = self._windows_service("rsync")

        elif self.system == "linux":
            checks["ssh"] = self._service(
                "sshd",
                ("ssh", "sshd"),
            )
            checks["telnet_service"] = self._service(
                "telnet",
                ("telnet.socket", "telnet"),
            )
            checks["rsync_service"] = self._service(
                "rsync",
                ("rsync", "rsyncd"),
            )

        elif self.system == "darwin":
            checks["ssh"] = self._service(
                "com.openssh.sshd",
                ("com.openssh.sshd",),
            )

        else:
            checks["platform_support"] = self._result(
                "unsupported",
                reason=f"Unsupported operating system: {platform.system()}",
            )

        for name, ports in self.PORTS.items():
            checks.setdefault(
                f"local_port_{name.lower()}",
                self._result(
                    "listening" if self._local_listeners(ports) else "not_detected",
                    details={
                        "ports": list(ports),
                        "scope": "loopback only",
                    },
                    reason=(
                        "A loopback probe does not determine whether the "
                        "service is bound to a LAN interface or reachable "
                        "through the firewall."
                    ),
                ),
            )

        return {
            "platform": platform.system(),
            "checks": checks,
        }
