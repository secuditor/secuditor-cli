
# Secuditor – Copyright (c) 2026 Menahem Levinski

"""Cross-platform endpoint security settings audit."""

import os
import platform
import subprocess
import json


__all__ = ["SecuritySettingsAudit"]


class SecuritySettingsAudit:
    """Collect endpoint security configuration and status."""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.system = platform.system().lower()

    @staticmethod
    def _result(status, details=None):
        return {"status": status, "details": details}

    def _run(self, command):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                check=False,
                shell=False,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None

    def _powershell(self, script):
        if self.system != "windows":
            return None
        return self._run([
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference = 'Stop'; " + script,
        ])

    @staticmethod
    def _parse_json(output):
        if not output:
            return None
        try:
            return json.loads(output)
        except (json.JSONDecodeError, TypeError):
            return None

    @staticmethod
    def _registry_value(root_name, path, name):
        if platform.system().lower() != "windows":
            return None

        try:
            import winreg

            root = {
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKCU": winreg.HKEY_CURRENT_USER,
            }[root_name]

            with winreg.OpenKey(root, path) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except (OSError, ImportError, KeyError):
            return None

    def _windows_audit(self):
        checks = {}

        # Windows Defender
        output = self._powershell(
            "Get-MpComputerStatus | "
            "Select-Object AMServiceEnabled,AntivirusEnabled,"
            "RealTimeProtectionEnabled,BehaviorMonitorEnabled,"
            "IoavProtectionEnabled | ConvertTo-Json -Compress"
        )
        data = self._parse_json(output)

        if isinstance(data, dict):
            checks["windows_defender"] = self._result("available", {
                "service_enabled": data.get("AMServiceEnabled"),
                "antivirus_enabled": data.get("AntivirusEnabled"),
                "real_time_protection": data.get(
                    "RealTimeProtectionEnabled"
                ),
                "behavior_monitor": data.get("BehaviorMonitorEnabled"),
                "downloaded_file_scanning": data.get(
                    "IoavProtectionEnabled"
                ),
            })
        else:
            checks["windows_defender"] = self._result(
                "unknown", "Defender status could not be queried."
            )

        # Registered antivirus products
        output = self._powershell(
            "Get-CimInstance -Namespace root/SecurityCenter2 "
            "-ClassName AntiVirusProduct | "
            "Select-Object displayName,productState | ConvertTo-Json -Compress"
        )
        data = self._parse_json(output)

        if isinstance(data, dict):
            data = [data]

        if isinstance(data, list):
            products = [
                {
                    "name": item.get("displayName"),
                    "product_state": item.get("productState"),
                }
                for item in data
                if isinstance(item, dict)
            ]
            checks["endpoint_protection"] = self._result(
                "available", products
            )
        else:
            checks["endpoint_protection"] = self._result(
                "unknown", "Antivirus inventory unavailable."
            )

        # Windows Firewall profiles
        output = self._powershell(
            "Get-NetFirewallProfile | "
            "Select-Object Name,Enabled,DefaultInboundAction,"
            "DefaultOutboundAction | ConvertTo-Json -Compress"
        )
        data = self._parse_json(output)

        if isinstance(data, dict):
            data = [data]

        if isinstance(data, list):
            profiles = {
                item["Name"]: {
                    "enabled": item.get("Enabled"),
                    "default_inbound_action": item.get(
                        "DefaultInboundAction"
                    ),
                    "default_outbound_action": item.get(
                        "DefaultOutboundAction"
                    ),
                }
                for item in data
                if isinstance(item, dict) and item.get("Name")
            }
            checks["host_firewall"] = self._result(
                "available" if profiles else "unknown", profiles
            )
        else:
            checks["host_firewall"] = self._result("unknown")

        # Automatic screen lock settings
        policy_path = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        )
        checks["auto_screen_lock"] = self._result("available", {
            "inactivity_timeout_seconds": self._registry_value(
                "HKLM", policy_path, "InactivityTimeoutSecs"
            ),
            "disable_lock_workstation": self._registry_value(
                "HKLM", policy_path, "DisableLockWorkstation"
            ),
            "secure_screen_saver": self._registry_value(
                "HKCU", r"Control Panel\Desktop", "ScreenSaverIsSecure"
            ),
            "screen_saver_timeout_seconds": self._registry_value(
                "HKCU", r"Control Panel\Desktop", "ScreenSaveTimeOut"
            ),
            "note": "Registry settings alone do not prove effective lock behavior.",
        })

        # Office macro policy (Word, current user)
        macro = self._registry_value(
            "HKCU",
            r"Software\Microsoft\Office\16.0\Word\Security",
            "VBAWarnings",
        )
        macro_descriptions = {
            1: "Enable all macros",
            2: "Disable macros with notification",
            3: "Disable macros except digitally signed macros",
            4: "Disable all macros without notification",
        }
        checks["office_macro_policy"] = self._result(
            "available" if macro is not None else "unknown",
            {
                "application": "Word",
                "vba_warnings": macro,
                "description": macro_descriptions.get(
                    macro, "Not configured or unrecognized"
                ),
            },
        )

        # Defender Attack Surface Reduction rules
        asr_path = (
            r"SOFTWARE\Microsoft\Windows Defender\Windows Defender "
            r"Exploit Guard\ASR\Rules"
        )
        rules = {}

        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, asr_path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    rules[name] = value
                    index += 1
        except (OSError, ImportError):
            pass

        if rules:
            checks["defender_asr"] = self._result("available", {
                "rule_count": len(rules),
                "block": sum(value == 1 for value in rules.values()),
                "audit": sum(value == 2 for value in rules.values()),
                "disabled": sum(value == 0 for value in rules.values()),
                "rules": rules,
            })
        else:
            checks["defender_asr"] = self._result(
                "unknown",
                "No ASR rule values found; configuration may be absent "
                "or managed elsewhere.",
            )

        # User Account Control
        uac_path = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        )
        enable_lua = self._registry_value("HKLM", uac_path, "EnableLUA")
        checks["uac"] = self._result(
            "available" if enable_lua is not None else "unknown",
            {
                "enabled": bool(enable_lua) if enable_lua is not None else None,
                "admin_consent_behavior": self._registry_value(
                    "HKLM", uac_path, "ConsentPromptBehaviorAdmin"
                ),
                "secure_desktop_prompt": self._registry_value(
                    "HKLM", uac_path, "PromptOnSecureDesktop"
                ),
            },
        )

        # Core Isolation / Memory Integrity
        hvc_path = (
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
            r"\HypervisorEnforcedCodeIntegrity"
        )
        hvc_enabled = self._registry_value("HKLM", hvc_path, "Enabled")
        output = self._powershell(
            "Get-CimInstance -ClassName Win32_DeviceGuard "
            "-ErrorAction SilentlyContinue | "
            "Select-Object VirtualizationBasedSecurityStatus,"
            "SecurityServicesConfigured,SecurityServicesRunning | "
            "ConvertTo-Json -Compress"
        )
        device_guard = self._parse_json(output)
        checks["core_isolation"] = self._result(
            "available" if (
                hvc_enabled is not None or isinstance(device_guard, dict)
            ) else "unknown",
            {
                "memory_integrity_registry_enabled": hvc_enabled,
                "device_guard": device_guard,
            },
        )

        # PowerShell execution policy
        output = self._powershell("Get-ExecutionPolicy")
        checks["powershell_execution_policy"] = self._result(
            "available" if output else "unknown", output
        )

        # BitLocker volume status
        output = self._powershell(
            "Get-BitLockerVolume | "
            "Select-Object MountPoint,VolumeStatus,ProtectionStatus,"
            "EncryptionPercentage,EncryptionMethod | ConvertTo-Json -Compress"
        )
        data = self._parse_json(output)

        if isinstance(data, dict):
            data = [data]

        checks["bitlocker"] = self._result(
            "available" if isinstance(data, list) else "unknown",
            data if isinstance(data, list) else (
                "BitLocker status could not be queried."
            ),
        )

        # UEFI Secure Boot
        secure_boot = self._registry_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        )
        status = (
            "enabled" if secure_boot == 1 else
            "disabled" if secure_boot == 0 else
            "unknown"
        )
        checks["secure_boot"] = self._result(
            status, {"registry_value": secure_boot}
        )

        # USB mass-storage driver configuration
        usbstor = self._registry_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\USBSTOR",
            "Start",
        )
        checks["removable_storage"] = self._result(
            "unknown" if usbstor is None else (
                "disabled" if usbstor == 4 else "configured"
            ),
            {"usbstor_start": usbstor},
        )

        # AutoRun policy
        autorun = self._registry_value(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
        )
        checks["usb_autorun"] = self._result(
            "unknown" if autorun is None else "available",
            {"no_drive_type_autorun": autorun},
        )

        # EFS file attribute scan: current user's home directory only.
        efs_files = []
        visited = 0
        complete = True
        max_files = 10000

        try:
            for root, dirs, files in os.walk(os.path.expanduser("~")):
                dirs[:] = [
                    name for name in dirs
                    if name not in {"AppData", "WindowsApps"}
                ]

                for filename in files:
                    visited += 1
                    if visited > max_files:
                        complete = False
                        break

                    path = os.path.join(root, filename)
                    try:
                        attrs = os.stat(
                            path, follow_symlinks=False
                        ).st_file_attributes
                        if attrs & 0x4000:
                            efs_files.append(path)
                            if len(efs_files) >= 100:
                                complete = False
                                break
                    except (OSError, AttributeError):
                        continue

                if visited > max_files or len(efs_files) >= 100:
                    break

            checks["efs"] = self._result("available", {
                "encrypted_files_found": len(efs_files),
                "sample_paths": efs_files,
                "scan_complete": complete,
                "scope": "Current user's home directory only",
            })
        except OSError:
            checks["efs"] = self._result("unknown")

        # System Restore configuration
        sr_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        )
        disable_sr = self._registry_value("HKLM", sr_path, "DisableSR")
        checks["system_restore"] = self._result(
            "unknown" if disable_sr is None else (
                "disabled" if disable_sr == 1 else "enabled"
            ),
            {
                "disable_sr_registry_value": disable_sr,
                "note": "This does not verify restore-point availability.",
            },
        )

        return checks

    def _linux_audit(self):
        checks = {}

        # Try common firewall utilities. Results are command output,
        # not a complete evaluation of the effective ruleset.
        firewall = None
        for command in (
            ["ufw", "status"],
            ["firewall-cmd", "--state"],
            ["nft", "list", "ruleset"],
        ):
            output = self._run(command)
            if output:
                firewall = {"command": command[0], "output": output[:12000]}
                break

        checks["host_firewall"] = self._result(
            "available" if firewall else "unknown", firewall
        )

        output = self._run(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS", "--json"])
        checks["disk_encryption"] = self._result(
            "available" if output else "unknown", output
        )

        output = self._run(["mokutil", "--sb-state"])
        checks["secure_boot"] = self._result(
            "available" if output else "unknown", output
        )

        for name in (
            "windows_defender",
            "endpoint_protection",
            "auto_screen_lock",
            "office_macro_policy",
            "defender_asr",
            "uac",
            "core_isolation",
            "powershell_execution_policy",
            "bitlocker",
            "removable_storage",
            "usb_autorun",
            "efs",
            "system_restore",
        ):
            checks[name] = self._result(
                "not_applicable", "Windows-specific check."
            )

        return checks

    def _macos_audit(self):
        checks = {}

        output = self._run([
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            "--getglobalstate",
        ])
        checks["host_firewall"] = self._result(
            "available" if output else "unknown", output
        )

        output = self._run(["fdesetup", "status"])
        checks["disk_encryption"] = self._result(
            "available" if output else "unknown", output
        )

        for name in (
            "windows_defender",
            "endpoint_protection",
            "auto_screen_lock",
            "office_macro_policy",
            "defender_asr",
            "uac",
            "core_isolation",
            "powershell_execution_policy",
            "bitlocker",
            "secure_boot",
            "removable_storage",
            "usb_autorun",
            "efs",
            "system_restore",
        ):
            checks[name] = self._result(
                "not_applicable", "Windows-specific check."
            )

        return checks

    def audit(self):
        """Return a structured security settings report."""
        if self.system == "windows":
            checks = self._windows_audit()
        elif self.system == "linux":
            checks = self._linux_audit()
        elif self.system == "darwin":
            checks = self._macos_audit()
        else:
            checks = {}

        return {
            "platform": platform.platform(),
            "hostname": platform.node(),
            "checks": checks,
            "notes": [
                "Unknown means the check could not be verified.",
                "Not applicable means the check is platform-specific.",
                "Some checks require elevated permissions.",
                "Configuration does not necessarily prove enforcement.",
            ],
        }
