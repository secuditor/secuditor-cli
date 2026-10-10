# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform system settings and hardware inventory."""

import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import socket

import psutil

__all__ = ["SystemSettings"]

class SystemSettingsAudit:
    """Collect system inventory and discover hardware where supported."""

    PNP_CLASSES = {
        "Printers": "Printer",
        "Cameras": "Camera",
        "Bluetooth Devices": "Bluetooth",
        "Biometric Devices": "Biometric",
    }

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        """Run a command without a shell; return stdout or None."""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None

    def get_system_settings(self):
        memory = psutil.virtual_memory()

        resources = {
            "Machine": platform.machine() or None,
            "Processor": platform.processor() or None,
            "Architecture": platform.architecture()[0],
            "Physical CPU Cores": psutil.cpu_count(logical=False),
            "Logical CPU Threads": psutil.cpu_count(logical=True),
            "RAM (GB)": round(memory.total / (1024 ** 3), 2),
        }

        disks = {}

        for partition in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(partition.mountpoint)
            except (PermissionError, FileNotFoundError, OSError):
                continue

            disks[partition.mountpoint] = {
                "Device": partition.device,
                "File System": partition.fstype or None,
                "Total (GB)": round(usage.total / (1024 ** 3), 2),
                "Used (GB)": round(usage.used / (1024 ** 3), 2),
                "Free (GB)": round(usage.free / (1024 ** 3), 2),
                "Usage (%)": usage.percent,
            }

        return {
            "hostname": socket.gethostname(),
            "platform": self.system,
            "OS": platform.platform(),
            "OS Release": platform.release(),
            "OS Version": platform.version(),
            "Resources": resources,
            "Disks": disks,
        }

    def scan_network_adapters(self):
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        adapters = []

        for name, entries in addresses.items():
            mac = None
            ips = []

            for entry in entries:
                if entry.family == getattr(psutil, "AF_LINK", object()):
                    if entry.address:
                        mac = entry.address
                elif entry.family == getattr(
                    __import__("socket"), "AF_INET"
                ):
                    ips.append({
                        "address": entry.address,
                        "family": "IPv4",
                        "netmask": entry.netmask,
                    })
                elif entry.family == getattr(
                    __import__("socket"), "AF_INET6"
                ):
                    ips.append({
                        "address": entry.address.split("%", 1)[0],
                        "family": "IPv6",
                        "netmask": entry.netmask,
                    })

            stat = stats.get(name)

            adapters.append({
                "name": name,
                "status": (
                    "up" if stat and stat.isup
                    else "down" if stat
                    else "unknown"
                ),
                "mac_address": mac,
                "addresses": ips,
            })

        return adapters

    def _windows_hardware(self):
        """Discover present hardware using PowerShell on Windows."""
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            return None

        categories = {}

        commands = {
            "Printers": (
                "Get-PnpDevice -PresentOnly -Class Printer "
                "| Select-Object -ExpandProperty FriendlyName"
            ),
            "Cameras": (
                "Get-PnpDevice -PresentOnly "
                "| Where-Object { $_.Class -in @('Camera','Image') } "
                "| Select-Object -ExpandProperty FriendlyName"
            ),
            "Bluetooth Devices": (
                "Get-PnpDevice -PresentOnly -Class Bluetooth "
                "| Select-Object -ExpandProperty FriendlyName"
            ),
            "USB Devices": (
                "Get-PnpDevice -PresentOnly "
                "| Where-Object { $_.InstanceId -like 'USB*' } "
                "| Select-Object -ExpandProperty FriendlyName"
            ),
            "Biometric Devices": (
                "Get-PnpDevice -PresentOnly -Class Biometric "
                "| Select-Object -ExpandProperty FriendlyName"
            ),
        }

        for category, command in commands.items():
            output = self._run([
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ])

            if output is None:
                categories[category] = {
                    "status": "unavailable",
                    "devices": [],
                }
            else:
                categories[category] = {
                    "status": "available",
                    "devices": [
                        line.strip()
                        for line in output.splitlines()
                        if line.strip()
                    ],
                }

        return categories

    def _linux_hardware(self):
        categories = {}

        # lsusb can enumerate USB devices when the utility is installed.
        output = self._run(["lsusb"]) if shutil.which("lsusb") else None
        categories["USB Devices"] = {
            "status": "available" if output is not None else "unavailable",
            "devices": output.splitlines() if output else [],
        }

        # lpstat lists configured printers when CUPS tools are installed.
        output = self._run(["lpstat", "-e"]) if shutil.which("lpstat") else None
        categories["Printers"] = {
            "status": "available" if output is not None else "unavailable",
            "devices": output.splitlines() if output else [],
        }

        # Bluetooth controller discovery via bluetoothctl.
        output = None
        if shutil.which("bluetoothctl"):
            output = self._run(["bluetoothctl", "list"])

        categories["Bluetooth Devices"] = {
            "status": "available" if output is not None else "unavailable",
            "devices": output.splitlines() if output else [],
        }

        # These categories do not have a reliable universal command.
        for category in ("Cameras", "Biometric Devices"):
            categories[category] = {
                "status": "unsupported",
                "devices": [],
            }

        return categories

    def _macos_hardware(self):
        output = self._run(["system_profiler", "SPUSBDataType", "-json"])
        categories = {}

        if output:
            try:
                data = json.loads(output)
                categories["USB Devices"] = {
                    "status": "available",
                    "devices": data.get("SPUSBDataType", []),
                }
            except json.JSONDecodeError:
                categories["USB Devices"] = {
                    "status": "error",
                    "devices": [],
                }
        else:
            categories["USB Devices"] = {
                "status": "unavailable",
                "devices": [],
            }

        for category, data_type in (
            ("Printers", "SPPrintersDataType"),
            ("Cameras", "SPCameraDataType"),
            ("Bluetooth Devices", "SPBluetoothDataType"),
        ):
            output = self._run([
                "system_profiler", data_type, "-json"
            ])

            if output:
                try:
                    data = json.loads(output)
                    categories[category] = {
                        "status": "available",
                        "devices": data.get(data_type, []),
                    }
                except json.JSONDecodeError:
                    categories[category] = {
                        "status": "error",
                        "devices": [],
                    }
            else:
                categories[category] = {
                    "status": "unavailable",
                    "devices": [],
                }

        categories["Biometric Devices"] = {
            "status": "unsupported",
            "devices": [],
        }

        return categories

    def get_hardware_report(self):
        if self.system == "Windows":
            hardware = self._windows_hardware()
        elif self.system == "Linux":
            hardware = self._linux_hardware()
        elif self.system == "Darwin":
            hardware = self._macos_hardware()
        else:
            hardware = None

        return {
            "Network Adapters": {
                "status": "available",
                "devices": self.scan_network_adapters(),
            },
            "Hardware": hardware or {
                "status": "unsupported",
                "devices": [],
            },
        }

    def audit(self):
        return {
            "system": self.get_system_settings(),
            "hardware": self.get_hardware_report(),
        }


if __name__ == "__main__":
    print(json.dumps(
        SystemSettingsAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
