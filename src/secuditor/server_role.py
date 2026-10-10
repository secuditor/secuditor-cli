
# Secuditor – Copyright (c) 2026 Menahem Levinski

"""Cross-platform server-role and service discovery."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from typing import Any


__all__ = ["ServerRoleAudit"]


# Windows service names and their user-facing role names.
WINDOWS_SERVICES = {
    "DHCP": ("DHCPServer",),
    "DNS": ("DNS",),
    "FTP": ("ftpsvc", "FileZilla Server"),
    "NTP": ("W32Time",),
    "WEB": ("W3SVC", "WAS"),
    "IAS": ("IAS",),
    "PKI": ("CertSvc",),
    "SSH": ("sshd", "MobaSSHD", "FreeSSHD"),
    "SNMP": ("SNMP", "SNMPTRAP"),
    "SMTP": ("SMTPSVC", "MSExchangeTransport"),
    "POP3": ("POP3Svc", "MSExchangePOP3"),
    "IMAP": ("IMAP4Svc", "MSExchangeIMAP4"),
    "DFSR": ("DFSR",),
    "LDAP": ("NTDS",),
    "MSMQ": ("MSMQ",),
    "RRAS": ("RemoteAccess",),
    "VMMS": ("VMMS",),
    "Telnet": ("TlntSvr",),
    "NPS": ("IAS",),
}

# Common service-name patterns for database engines.
WINDOWS_DATABASE_PATTERNS = {
    "Microsoft SQL Server": r"^MSSQLSERVER$|^MSSQL\$",
    "MySQL": r"^MySQL$|^MySQL\d",
    "MariaDB": r"^MariaDB$|^MariaDB\d",
    "PostgreSQL": r"^postgresql.*|^postgres$",
    "MongoDB": r"^MongoDB$|^MongoDB\d",
}

# Common systemd unit names. Presence varies by distribution and installation.
LINUX_SERVICES = {
    "DHCP": ("isc-dhcp-server", "dhcpd"),
    "DNS": ("named", "bind9", "dnsmasq", "unbound"),
    "FTP": ("vsftpd", "proftpd", "pure-ftpd"),
    "NTP": ("chronyd", "chrony", "ntp", "systemd-timesyncd"),
    "WEB": ("nginx", "apache2", "httpd", "caddy"),
    "PKI": ("pki-tomcatd", "step-ca"),
    "SSH": ("ssh", "sshd"),
    "SNMP": ("snmpd",),
    "SMTP": ("postfix", "exim4", "sendmail"),
    "POP3": ("dovecot", "courier-pop"),
    "IMAP": ("dovecot", "courier-imap"),
    "LDAP": ("slapd",),
    "MSMQ": (),
    "RRAS": ("NetworkManager", "strongswan", "openvpn"),
    "Telnet": ("telnet", "telnet.socket"),
    "SQLDB": (
        "mysql", "mariadb", "postgresql",
        "mongod", "redis-server",
    ),
    "VMMS": (
        "libvirtd", "virtqemud", "vmware",
        "vboxservice",
    ),
}

MACOS_SERVICES = {
    "SSH": ("com.openssh.sshd",),
    "WEB": ("org.apache.httpd",),
}


class ServerRoleAudit:
    """Discover server-related services on the current operating system.

    This module identifies service evidence; it does not establish that
    a host is providing a role to remote clients.

    Args:
        timeout: Maximum wait for an individual system command, in seconds.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        self.timeout = timeout
        self.system = platform.system().lower()

    def _run(self, command: list[str]) -> tuple[bool, str]:
        """Execute a command without a shell."""

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False, ""

        return result.returncode == 0, result.stdout.strip()

    @staticmethod
    def _result(
        status: str,
        *,
        service: str | None = None,
        details: dict[str, Any] | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "service": service,
            "details": details or {},
            "reason": reason,
        }

    def _windows_services(self) -> tuple[bool, list[dict[str, str]]]:
        """Enumerate Windows services and their states."""

        executable = shutil.which("sc.exe") or shutil.which("sc")
        if not executable:
            return False, []

        ok, output = self._run(
            [executable, "query", "state=", "all"]
        )

        if not ok:
            return False, []

        services = []
        current_name = None
        current_state = None

        for line in output.splitlines():
            name_match = re.match(
                r"\s*SERVICE_NAME:\s*(.+)",
                line,
                flags=re.IGNORECASE,
            )
            state_match = re.match(
                r"\s*STATE\s*:\s*\d+\s+(\w+)",
                line,
                flags=re.IGNORECASE,
            )

            if name_match:
                if current_name:
                    services.append({
                        "name": current_name,
                        "status": current_state or "unknown",
                    })

                current_name = name_match.group(1).strip()
                current_state = None

            elif state_match and current_name:
                current_state = state_match.group(1).lower()

        if current_name:
            services.append({
                "name": current_name,
                "status": current_state or "unknown",
            })

        return True, services

    def _linux_service(self, name: str) -> dict[str, Any]:
        """Inspect a Linux systemd unit."""

        systemctl = shutil.which("systemctl")
        if not systemctl:
            return self._result(
                "unknown",
                service=name,
                reason="systemctl is unavailable.",
            )

        ok, output = self._run(
            [systemctl, "show", name, "--property=LoadState,ActiveState"]
        )

        if not ok:
            return self._result(
                "unknown",
                service=name,
                reason="Unable to query the systemd unit.",
            )

        values = {}
        for line in output.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value

        load_state = values.get("LoadState", "")
        active_state = values.get("ActiveState", "")

        if load_state == "not-found":
            status = "not_found"
        elif active_state == "active":
            status = "running"
        elif active_state in ("inactive", "failed"):
            status = "stopped"
        else:
            status = "unknown"

        return self._result(
            status,
            service=name,
            details={
                "load_state": load_state or None,
                "active_state": active_state or None,
            },
        )

    def _macos_service(self, name: str) -> dict[str, Any]:
        """Best-effort launchd service lookup on macOS."""

        launchctl = shutil.which("launchctl")
        if not launchctl:
            return self._result(
                "unknown",
                service=name,
                reason="launchctl is unavailable.",
            )

        ok, output = self._run([launchctl, "list"])
        if not ok:
            return self._result(
                "unknown",
                service=name,
                reason="Unable to enumerate launchd services.",
            )

        matches = [
            line for line in output.splitlines()
            if name.lower() in line.lower()
        ]

        return self._result(
            "running" if matches else "unknown",
            service=name,
            details={"matching_entries": matches},
            reason=(
                None if matches
                else "No matching launchd entry was identified."
            ),
        )

    def _service_map(self) -> dict[str, str]:
        """Return service names mapped to normalized service states."""

        if self.system == "windows":
            ok, services = self._windows_services()
            if not ok:
                return {}

            return {
                item["name"].lower(): item["status"]
                for item in services
            }

        return {}

    def _detect_windows_role(
        self,
        role: str,
        service_names: tuple[str, ...],
        service_map: dict[str, str],
    ) -> dict[str, Any]:
        matches = [
            (name, service_map[name.lower()])
            for name in service_names
            if name.lower() in service_map
        ]

        if not matches:
            return self._result(
                "not_found",
                reason=(
                    "No matching Windows service was found. This does not "
                    "rule out an application installed under another name."
                ),
            )

        running = [
            name for name, status in matches
            if status == "running"
        ]
        stopped = [
            name for name, status in matches
            if status == "stopped"
        ]

        if running:
            status = "running"
        elif stopped:
            status = "stopped"
        else:
            status = "unknown"

        return self._result(
            status,
            service=", ".join(name for name, _ in matches),
            details={
                "role": role,
                "services": [
                    {"name": name, "status": state}
                    for name, state in matches
                ],
            },
        )

    def _detect_unix_role(
        self,
        role: str,
        service_names: tuple[str, ...],
    ) -> dict[str, Any]:
        if not service_names:
            return self._result(
                "not_applicable",
                reason=f"{role} is not mapped for this platform.",
            )

        candidates = []

        for name in service_names:
            if self.system == "linux":
                result = self._linux_service(name)
            elif self.system == "darwin":
                result = self._macos_service(name)
            else:
                return self._result(
                    "unsupported",
                    reason=f"Unsupported platform: {platform.system()}",
                )

            candidates.append(result)

        running = [
            item for item in candidates
            if item["status"] == "running"
        ]
        stopped = [
            item for item in candidates
            if item["status"] == "stopped"
        ]

        if running:
            status = "running"
            selected = running
        elif stopped:
            status = "stopped"
            selected = stopped
        elif all(item["status"] == "not_found" for item in candidates):
            status = "not_found"
            selected = candidates
        else:
            status = "unknown"
            selected = candidates

        return self._result(
            status,
            service=", ".join(
                item["service"]
                for item in selected
                if item.get("service")
            ) or None,
            details={
                "role": role,
                "candidates": candidates,
            },
        )

    def _detect_role(
        self,
        role: str,
        windows_services: tuple[str, ...],
        unix_services: tuple[str, ...] = (),
        macos_services: tuple[str, ...] = (),
        service_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if self.system == "windows":
            return self._detect_windows_role(
                role,
                windows_services,
                service_map or {},
            )

        if self.system == "linux":
            return self._detect_unix_role(role, unix_services)

        if self.system == "darwin":
            return self._detect_unix_role(
                role,
                macos_services or unix_services,
            )

        return self._result(
            "unsupported",
            reason=f"Unsupported operating system: {platform.system()}",
        )

    def audit(self) -> dict[str, Any]:
        """Inspect server-related services and return structured results."""

        checks: dict[str, Any] = {}

        if self.system == "windows":
            service_map = self._service_map()

            if not service_map:
                return {
                    "platform": platform.system(),
                    "checks": {},
                    "error": (
                        "Unable to enumerate Windows services. "
                        "Check the system command and permissions."
                    ),
                }

            for role, services in WINDOWS_SERVICES.items():
                checks[role] = self._detect_role(
                    role,
                    services,
                    service_map=service_map,
                )

            for engine, pattern in WINDOWS_DATABASE_PATTERNS.items():
                matches = [
                    item for item in service_map
                    if re.search(pattern, item, re.IGNORECASE)
                ]

                instances = [
                    {
                        "name": name,
                        "status": service_map[name],
                    }
                    for name in matches
                ]

                if not instances:
                    status = "not_found"
                elif any(
                    item["status"] == "running"
                    for item in instances
                ):
                    status = "running"
                elif any(
                    item["status"] == "stopped"
                    for item in instances
                ):
                    status = "stopped"
                else:
                    status = "unknown"

                checks[f"database:{engine}"] = self._result(
                    status,
                    service=", ".join(matches) or None,
                    details={"instances": instances},
                )

        elif self.system == "linux":
            for role, services in LINUX_SERVICES.items():
                checks[role] = self._detect_role(
                    role,
                    (),
                    unix_services=services,
                )

        elif self.system == "darwin":
            for role, services in MACOS_SERVICES.items():
                checks[role] = self._detect_role(
                    role,
                    (),
                    macos_services=services,
                )

        else:
            return {
                "platform": platform.system(),
                "checks": {},
                "error": (
                    f"Unsupported operating system: {platform.system()}"
                ),
            }

        return {
            "platform": platform.system(),
            "checks": checks,
            "notes": [
                "Service status is not proof of remote network exposure.",
                "not_found means no matching service was detected, "
                "not that the capability is impossible to provide.",
                "Windows role detection is based on service evidence, "
                "not authoritative Server Manager role inventory.",
            ],
        }
