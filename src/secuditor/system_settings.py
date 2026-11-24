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

    _SMBIOS_MEMORY_TYPES = {
        20: "DDR",
        21: "DDR2",
        22: "DDR2 FB-DIMM",
        24: "DDR3",
        26: "DDR4",
        27: "LPDDR",
        28: "LPDDR2",
        29: "LPDDR3",
        30: "LPDDR4",
        34: "DDR5",
        35: "LPDDR5",
        36: "LPDDR5X",
    }

    _VIRTUAL_GPU_MARKERS = (
        "microsoft basic display",
        "microsoft remote display",
        "citrix indirect",
        "parsec virtual",
        "idd sample",
        "luminoncore",
    )

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

    @classmethod
    def _parse_windows_hardware_cim(cls, payload):
        """Parse BIOS version, physical memory speed/type, and GPU details."""
        if not isinstance(payload, dict):
            payload = {}

        bios_raw = payload.get("bios")
        firmware_version = str(bios_raw).strip() if bios_raw else "Unknown"

        def _as_dict_list(val):
            if isinstance(val, dict):
                return [val]
            if isinstance(val, list):
                return [item for item in val if isinstance(item, dict)]
            return []

        speeds = []
        mem_types = []
        for dimm in _as_dict_list(payload.get("memory")):
            speed_val = None
            for skey in ("ConfiguredClockSpeed", "Speed"):
                raw_s = dimm.get(skey)
                try:
                    iv = int(raw_s)
                    if iv > 0:
                        speed_val = iv
                        break
                except (TypeError, ValueError):
                    continue
            if speed_val is not None:
                s_label = f"{speed_val} MHz"
                if s_label not in speeds:
                    speeds.append(s_label)

            m_label = None
            for tkey in ("SMBIOSMemoryType", "MemoryType"):
                raw_t = dimm.get(tkey)
                try:
                    tv = int(raw_t)
                    if tv in cls._SMBIOS_MEMORY_TYPES:
                        m_label = cls._SMBIOS_MEMORY_TYPES[tv]
                        break
                except (TypeError, ValueError):
                    continue
            if m_label and m_label not in mem_types:
                mem_types.append(m_label)

        raw_gpus = _as_dict_list(payload.get("gpus"))
        physical_gpus = []
        for gpu in raw_gpus:
            g_name = str(
                gpu.get("Name") or gpu.get("VideoProcessor") or ""
            ).strip().lower()
            if g_name and not any(
                marker in g_name for marker in cls._VIRTUAL_GPU_MARKERS
            ):
                physical_gpus.append(gpu)
        selected_gpus = physical_gpus if physical_gpus else raw_gpus

        gpu_makers = []
        gpu_models = []
        for gpu in selected_gpus:
            maker = str(gpu.get("AdapterCompatibility") or "").strip()
            model = str(
                gpu.get("Name") or gpu.get("VideoProcessor") or ""
            ).strip()
            if maker and maker not in gpu_makers:
                gpu_makers.append(maker)
            if model and model not in gpu_models:
                gpu_models.append(model)

        return {
            "firmware_version": firmware_version or "Unknown",
            "memory_type": ", ".join(mem_types) if mem_types else "Unknown",
            "memory_speed": ", ".join(speeds) if speeds else "Unknown",
            "gpu_manufacturer": ", ".join(gpu_makers) if gpu_makers else "Unknown",
            "gpu_model": ", ".join(gpu_models) if gpu_models else "Unknown",
        }

    def _hardware_details(self):
        """Collect firmware version, memory type/speed, and GPU details."""
        defaults = {
            "firmware_version": "Unknown",
            "memory_type": "Unknown",
            "memory_speed": "Unknown",
            "gpu_manufacturer": "Unknown",
            "gpu_model": "Unknown",
        }

        if self.system == "Windows":
            if not find_powershell():
                return defaults
            ps_cmd = (
                "@{ "
                "bios = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue "
                "| Select-Object -First 1 -ExpandProperty SMBIOSBIOSVersion); "
                "memory = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue "
                "| Select-Object ConfiguredClockSpeed,Speed,SMBIOSMemoryType,MemoryType); "
                "gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue "
                "| Select-Object AdapterCompatibility,Name,VideoProcessor) "
                "} | ConvertTo-Json -Compress -Depth 3"
            )
            payload = run_powershell(ps_cmd, timeout=self.timeout, parse_json=True)
            return self._parse_windows_hardware_cim(payload)

        if self.system == "Linux":
            details = dict(defaults)
            try:
                with open(
                    "/sys/class/dmi/id/bios_version",
                    encoding="utf-8",
                    errors="replace",
                ) as f:
                    ver = f.read().strip()
                    if ver:
                        details["firmware_version"] = ver
            except OSError:
                pass

            if shutil.which("lspci"):
                out = self._run(["lspci"])
                if out:
                    models = []
                    makers = []
                    for line in out.splitlines():
                        if not re.search(
                            r"\b(VGA compatible controller|3D controller|Display controller)\b",
                            line,
                            re.IGNORECASE,
                        ):
                            continue
                        parts = line.split(":", 2)
                        desc = parts[2].strip() if len(parts) >= 3 else line.strip()
                        if desc and desc not in models:
                            models.append(desc)
                            maker = desc.split()[0]
                            if maker and maker not in makers:
                                makers.append(maker)
                    if models:
                        details["gpu_model"] = ", ".join(models)
                    if makers:
                        details["gpu_manufacturer"] = ", ".join(makers)
            return details

        if self.system == "Darwin":
            details = dict(defaults)
            out = self._run([
                "system_profiler",
                "SPHardwareDataType",
                "SPDisplaysDataType",
                "SPMemoryDataType",
                "-json",
            ])
            if out:
                try:
                    data = json.loads(out)
                except json.JSONDecodeError:
                    return details

                hw_items = data.get("SPHardwareDataType") or []
                if isinstance(hw_items, list) and hw_items and isinstance(hw_items[0], dict):
                    fw = (
                        hw_items[0].get("system_firmware_version")
                        or hw_items[0].get("boot_rom_version")
                    )
                    if fw:
                        details["firmware_version"] = str(fw).strip()

                gpu_makers = []
                gpu_models = []
                for item in data.get("SPDisplaysDataType") or []:
                    if not isinstance(item, dict):
                        continue
                    maker = str(item.get("sppci_vendor") or "").strip()
                    model = str(item.get("sppci_model") or "").strip()
                    if maker and maker not in gpu_makers:
                        gpu_makers.append(maker)
                    if model and model not in gpu_models:
                        gpu_models.append(model)
                if gpu_makers:
                    details["gpu_manufacturer"] = ", ".join(gpu_makers)
                if gpu_models:
                    details["gpu_model"] = ", ".join(gpu_models)

                mem_types = []
                mem_speeds = []
                for block in data.get("SPMemoryDataType") or []:
                    if not isinstance(block, dict):
                        continue
                    entries = block.get("_items") if isinstance(block.get("_items"), list) else [block]
                    for dimm in entries:
                        if not isinstance(dimm, dict):
                            continue
                        mtype = str(dimm.get("dimm_type") or "").strip()
                        mspeed = str(dimm.get("dimm_speed") or "").strip()
                        if mtype and mtype.lower() != "empty" and mtype not in mem_types:
                            mem_types.append(mtype)
                        if mspeed and mspeed.lower() != "empty" and mspeed not in mem_speeds:
                            mem_speeds.append(mspeed)
                if mem_types:
                    details["memory_type"] = ", ".join(mem_types)
                if mem_speeds:
                    details["memory_speed"] = ", ".join(mem_speeds)
            return details

        return defaults

    def get_system_settings(self):
        memory = psutil.virtual_memory()
        try:
            cpu_freq = psutil.cpu_freq()
        except Exception:
            cpu_freq = None

        hw_details = self._hardware_details()

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
            "Memory Type": hw_details["memory_type"],
            "Memory Speed": hw_details["memory_speed"],
            "GPU Manufacturer": hw_details["gpu_manufacturer"],
            "GPU Model": hw_details["gpu_model"],
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
            "Firmware Version": hw_details["firmware_version"],
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
