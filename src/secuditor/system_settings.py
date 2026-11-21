# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform system settings and hardware inventory."""

import json
import os
import platform
import re
import shutil
import socket

import psutil

from ._utils import (
    find_powershell,
    read_registry_value,
    run_command,
    run_powershell,
)

__all__ = ["SystemSettings", "SystemSettingsAudit"]

class SystemSettingsAudit:
    """Collect system inventory and discover hardware where supported."""

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        """Run a command without a shell; return stdout or None."""
        return run_command(args, timeout=self.timeout)

    def _windows_os_name(self):
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        product = read_registry_value("HKLM", key_path, "ProductName")
        edition_id = read_registry_value("HKLM", key_path, "EditionID")
        display_ver = read_registry_value("HKLM", key_path, "DisplayVersion")
        build_raw = (
            read_registry_value("HKLM", key_path, "CurrentBuildNumber")
            or read_registry_value("HKLM", key_path, "CurrentBuild")
        )
        if not product or not build_raw:
            return None
        try:
            build = int(build_raw)
        except (TypeError, ValueError):
            return None

        if "server" in str(product).casefold():
            base = str(product)
        elif build >= 22000:
            editions = {
                "Core": "Home",
                "CoreN": "Home N",
                "CoreSingleLanguage": "Home Single Language",
                "Professional": "Pro",
                "ProfessionalN": "Pro N",
                "ProfessionalWorkstation": "Pro for Workstations",
                "Enterprise": "Enterprise",
                "EnterpriseN": "Enterprise N",
                "Education": "Education",
                "EducationN": "Education N",
            }
            ed = editions.get(edition_id, edition_id) if edition_id else ""
            base = f"Windows 11 {ed}".strip()
        else:
            base = str(product)

        return f"{base} ({display_ver})" if display_ver else base

    def _linux_os_name(self):
        try:
            with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return None

    def _macos_os_name(self):
        name = self._run(["sw_vers", "-productName"])
        ver = self._run(["sw_vers", "-productVersion"])
        if name and ver:
            return f"{name} {ver}"
        return None

    def _firmware_type(self):
        if self.system == "Windows":
            try:
                import ctypes

                firmware_type = ctypes.c_int()
                fn = ctypes.windll.kernel32.GetFirmwareType
                fn.argtypes = [ctypes.POINTER(ctypes.c_int)]
                fn.restype = ctypes.c_bool
                if fn(ctypes.byref(firmware_type)):
                    return {1: "BIOS", 2: "UEFI"}.get(
                        firmware_type.value, "Unknown"
                    )
            except (ImportError, AttributeError, OSError):
                pass
            return "Unknown"
        if self.system == "Linux":
            return "UEFI" if os.path.isdir("/sys/firmware/efi") else "BIOS"
        if self.system == "Darwin":
            return "UEFI/Apple Silicon" if platform.machine() == "arm64" else "UEFI"
        return "Unknown"

    def get_system_settings(self):
        memory = psutil.virtual_memory()
        try:
            cpu_freq = psutil.cpu_freq()
        except Exception:
            cpu_freq = None

        resources = {
            "Machine": platform.machine() or None,
            "Processor": platform.processor() or None,
            "Architecture": platform.architecture()[0],
            "Physical CPU Cores": psutil.cpu_count(logical=False),
            "Logical CPU Threads": psutil.cpu_count(logical=True),
            "CPU Frequency (MHz)": (
                round(cpu_freq.current)
                if cpu_freq and cpu_freq.current
                else None
            ),
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

        os_name = None
        if self.system == "Windows":
            os_name = self._windows_os_name()
        elif self.system == "Linux":
            os_name = self._linux_os_name()
        elif self.system == "Darwin":
            os_name = self._macos_os_name()

        return {
            "hostname": socket.gethostname(),
            "platform": self.system,
            "OS": os_name or platform.platform(),
            "OS Release": platform.release(),
            "OS Version": platform.version(),
            "Firmware": self._firmware_type(),
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
                        candidate = entry.address.strip().replace("-", ":").lower()
                        if (
                            re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", candidate)
                            and candidate not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
                        ):
                            mac = candidate
                elif entry.family == socket.AF_INET:
                    ips.append({
                        "address": entry.address,
                        "family": "IPv4",
                        "netmask": entry.netmask,
                    })
                elif entry.family == socket.AF_INET6:
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
        """Discover present hardware using a single PowerShell query on Windows."""
        if not find_powershell():
            return None

        script = (
            "$present = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue; "
            "$result = [ordered]@{ "
            "'Printers' = @($present | Where-Object { $_.Class -eq 'Printer' } "
            "| Select-Object -ExpandProperty FriendlyName); "
            "'Cameras' = @($present | Where-Object { $_.Class -in @('Camera','Image') } "
            "| Select-Object -ExpandProperty FriendlyName); "
            "'Bluetooth Devices' = @($present | Where-Object { $_.Class -eq 'Bluetooth' } "
            "| Select-Object -ExpandProperty FriendlyName); "
            "'USB Devices' = @($present | Where-Object { $_.InstanceId -like 'USB*' } "
            "| Select-Object -ExpandProperty FriendlyName); "
            "'Biometric Devices' = @($present | Where-Object { $_.Class -eq 'Biometric' } "
            "| Select-Object -ExpandProperty FriendlyName) "
            "}; "
            "$result | ConvertTo-Json -Compress"
        )

        data = run_powershell(script, timeout=self.timeout, parse_json=True)
        category_names = (
            "Printers",
            "Cameras",
            "Bluetooth Devices",
            "USB Devices",
            "Biometric Devices",
        )
        categories = {}

        if not isinstance(data, dict):
            for category in category_names:
                categories[category] = {
                    "status": "unavailable",
                    "devices": [],
                }
            return categories

        for category in category_names:
            raw = data.get(category)
            if raw is None:
                devices = []
            elif isinstance(raw, str):
                devices = [raw.strip()] if raw.strip() else []
            elif isinstance(raw, list):
                devices = [
                    str(item).strip()
                    for item in raw
                    if item is not None and str(item).strip()
                ]
            else:
                devices = []

            categories[category] = {
                "status": "available",
                "devices": list(dict.fromkeys(devices)),
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


SystemSettings = SystemSettingsAudit

if __name__ == "__main__":
    print(json.dumps(
        SystemSettingsAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
