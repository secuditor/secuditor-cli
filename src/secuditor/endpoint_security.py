# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform endpoint security settings audit."""

import glob
import json
import os
import platform
import shutil
import time

import psutil

from ._utils import (
    find_powershell,
    read_registry_value,
    run_command,
    run_command_result,
    run_powershell,
)

__all__ = ["SecurityAudit", "SecuritySettingsAudit", "EndpointSecurity"]


class SecuritySettingsAudit:
    """Collect endpoint security configuration and status across Windows, Linux, and macOS."""

    _KNOWN_FW_MANAGERS = (
        "AVG Antivirus",
        "Avast",
        "Kaspersky",
        "McAfee",
        "Bitdefender",
        "Norton",
        "Trend Micro",
        "Sophos",
    )

    _LINUX_EDR_PROCESSES = {
        "clamd": "ClamAV",
        "freshclam": "ClamAV",
        "falcon-sensor": "CrowdStrike Falcon",
        "mdatp": "Microsoft Defender for Endpoint",
        "wdavdaemon": "Microsoft Defender for Endpoint",
        "sentinelagent": "SentinelOne",
        "wazuh-agentd": "Wazuh Agent",
        "osqueryd": "osquery",
        "besclient": "BigFix",
    }

    _MACOS_EDR_PROCESSES = {
        "falcond": "CrowdStrike Falcon",
        "wdavdaemon": "Microsoft Defender for Endpoint",
        "sentineld": "SentinelOne",
        "osqueryd": "osquery",
        "Little Snitch Daemon": "Little Snitch",
    }

    def __init__(self, timeout=10.0):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, command):
        return run_command(command, timeout=self.timeout)

    def _run_result(self, command):
        return run_command_result(command, timeout=self.timeout)

    def _windows_ps_bundle(self):
        """Run a single batched PowerShell query for Windows endpoint security signals."""
        if not find_powershell():
            return {}

        script = (
            "$def = $null; "
            "try { $def = Get-MpComputerStatus -ErrorAction Stop "
            "| Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled } catch {}; "
            "$av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' "
            "-ClassName AntiVirusProduct -ErrorAction SilentlyContinue "
            "| Select-Object displayName,productState); "
            "$fw = @(Get-CimInstance -Namespace 'root/SecurityCenter2' "
            "-ClassName FirewallProduct -ErrorAction SilentlyContinue "
            "| Select-Object displayName,productState); "
            "$dep = $null; "
            "try { $dep = (Get-CimInstance Win32_OperatingSystem "
            "-ErrorAction SilentlyContinue).DataExecutionPrevention_SupportPolicy } catch {}; "
            "$dg_run = $null; "
            "try { $dg = Get-CimInstance -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' "
            "-ClassName Win32_DeviceGuard -ErrorAction Stop; "
            "if ($null -ne $dg) { $dg_run = @($dg.SecurityServicesRunning) } } catch {}; "
            "$ep = $null; "
            "try { $ep = [string](Get-ExecutionPolicy -ErrorAction SilentlyContinue) } catch {}; "
            "$bl = $null; "
            "try { "
            "$bl_vols = @(Get-BitLockerVolume -ErrorAction Stop "
            "| Select-Object -ExpandProperty ProtectionStatus); "
            "if ($bl_vols.Count -gt 0) { $bl = @{ source = 'cmdlet'; values = $bl_vols } } "
            "} catch {}; "
            "if ($null -eq $bl) { "
            "try { "
            "$s = New-Object -ComObject Shell.Application; "
            "$vals = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' "
            "-ErrorAction SilentlyContinue | ForEach-Object { "
            "$p = ($_.DeviceID + '\\'); "
            "$s.NameSpace($p).Self.ExtendedProperty('System.Volume.BitLockerProtection') }); "
            "$bl = @{ source = 'shell'; values = $vals } "
            "} catch {} }; "
            "$sb_wmi = $null; "
            "try { $sb_wmi = (Get-CimInstance -Namespace 'root\\Microsoft\\Windows\\HardwareManagement' "
            "-ClassName MS_SecureBoot -ErrorAction SilentlyContinue).SecureBootEnabled } catch {}; "
            "[PSCustomObject]@{ "
            "defender = $def; av = $av; fw = $fw; dep = $dep; dg_running = $dg_run; "
            "exec_policy = $ep; bitlocker = $bl; sb_wmi = $sb_wmi "
            "} | ConvertTo-Json -Depth 4 -Compress"
        )
        data = run_powershell(script, timeout=self.timeout, parse_json=True)
        return data if isinstance(data, dict) else {}

    def _windows_firewall_managed_by(self):
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info.get("name") or ""
                if pname:
                    for av in self._KNOWN_FW_MANAGERS:
                        if av.lower() in pname.lower():
                            return {"managed": True, "product_name": av}
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return {"managed": False, "product_name": None}

    @staticmethod
    def _parse_sc2_products(raw_items):
        """Decode SecurityCenter2 product entries into (display_name, is_active | None)."""
        if isinstance(raw_items, dict):
            items = [raw_items]
        elif isinstance(raw_items, list):
            items = raw_items
        else:
            return []

        parsed = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("displayName") or "").strip()
            if not name:
                continue
            try:
                state = int(item.get("productState"))
                # SecurityCenter2 state nibble (0xF000): 0x1000 = enabled/active
                active = (state & 0xF000) == 0x1000
            except (TypeError, ValueError):
                active = None
            parsed.append((name, active))
        return parsed

    def _windows_firewall_state(self):
        try:
            # Verify the Windows Defender Firewall service (mpssvc) is running.
            svc_out = (self._run(["sc.exe", "query", "mpssvc"]) or "").upper()
            if "STOPPED" in svc_out or "STOP_PENDING" in svc_out:
                return "Off"

            import winreg

            profiles = {"Domain": True, "Private": True, "Public": True}
            gpo_reg_path = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"
            reg_path = (
                r"SYSTEM\CurrentControlSet\Services\SharedAccess"
                r"\Parameters\FirewallPolicy"
            )
            profile_keys = {
                "Domain": "DomainProfile",
                "Private": "StandardProfile",
                "Public": "PublicProfile",
            }
            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, reg_path, 0, access
            ):
                pass

            for name, subkey in profile_keys.items():
                resolved = None
                for base_path in (gpo_reg_path, reg_path):
                    val = read_registry_value(
                        "HKLM", f"{base_path}\\{subkey}", "EnableFirewall"
                    )
                    if val is not None:
                        try:
                            resolved = bool(int(val))
                            break
                        except (TypeError, ValueError):
                            continue
                profiles[name] = True if resolved is None else resolved

            if all(profiles.values()):
                return "On"
            if any(profiles.values()):
                return "Partially"
            return "Off"
        except Exception:
            return "Unknown"

    @staticmethod
    def _windows_auto_screen_lock():
        try:
            inactivity = None
            lock_disabled_by_policy = False
            lock_on_sleep = True

            sys_pol_path = (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            )
            raw_inactivity = read_registry_value(
                "HKLM", sys_pol_path, "InactivityTimeoutSecs"
            )
            if raw_inactivity is not None:
                try:
                    inactivity = int(raw_inactivity)
                except (TypeError, ValueError):
                    pass

            for root_name in ("HKLM", "HKCU"):
                disable_lock = read_registry_value(
                    root_name, sys_pol_path, "DisableLockWorkstation"
                )
                if disable_lock is not None:
                    try:
                        if int(disable_lock) == 1:
                            lock_disabled_by_policy = True
                    except (TypeError, ValueError):
                        pass

            console_lock_guid = "0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
            gpo_wake_path = (
                rf"SOFTWARE\Policies\Microsoft\Power"
                rf"\PowerSettings\{console_lock_guid}"
            )
            wake_indices = []
            for idx_name in ("ACSettingIndex", "DCSettingIndex"):
                val = read_registry_value("HKLM", gpo_wake_path, idx_name)
                if val is not None:
                    try:
                        wake_indices.append(int(val))
                    except (TypeError, ValueError):
                        pass

            if wake_indices:
                lock_on_sleep = all(v != 0 for v in wake_indices)
            else:
                schemes_path = (
                    r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
                )
                active_guid = read_registry_value(
                    "HKLM", schemes_path, "ActivePowerScheme"
                )
                if active_guid:
                    user_wake_path = (
                        rf"{schemes_path}\{active_guid}"
                        r"\fea3413e-7e05-4911-9a71-700331f1c294"
                        rf"\{console_lock_guid}"
                    )
                    scheme_indices = []
                    for idx_name in ("ACSettingIndex", "DCSettingIndex"):
                        val = read_registry_value(
                            "HKLM", user_wake_path, idx_name
                        )
                        if val is not None:
                            try:
                                scheme_indices.append(int(val))
                            except (TypeError, ValueError):
                                pass
                    if scheme_indices:
                        lock_on_sleep = all(v != 0 for v in scheme_indices)

            desktop_paths = (
                r"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                r"Control Panel\Desktop",
            )
            ss_active = None
            ss_secure = None
            ss_timeout = None
            for d_path in desktop_paths:
                if ss_active is None:
                    val = read_registry_value("HKCU", d_path, "ScreenSaveActive")
                    if val is not None:
                        ss_active = str(val).strip()
                if ss_secure is None:
                    val = read_registry_value(
                        "HKCU", d_path, "ScreenSaverIsSecure"
                    )
                    if val is not None:
                        ss_secure = str(val).strip()
                if ss_timeout is None:
                    val = read_registry_value(
                        "HKCU", d_path, "ScreenSaveTimeOut"
                    )
                    if val is not None:
                        try:
                            ss_timeout = int(str(val).strip())
                        except (TypeError, ValueError):
                            pass

            screen_lock = (
                ss_active == "1"
                and ss_secure == "1"
                and (ss_timeout is None or ss_timeout > 0)
            )

            if lock_disabled_by_policy:
                return "Disabled (Workstation locking disabled by policy)"
            if inactivity is not None and inactivity > 0:
                timeout_label = (
                    f"{round(inactivity / 60)}min"
                    if inactivity >= 60
                    else f"{inactivity}s"
                )
                return f"Enforced ({timeout_label} inactivity timeout)"
            if inactivity == 0:
                if screen_lock:
                    return (
                        "Default (Secure screen saver lock; "
                        "inactivity policy 0s)"
                    )
                return "Disabled (Inactivity timeout set to 0s)"
            if lock_on_sleep:
                if screen_lock:
                    return "Default (Sleep lock + secure screen lock)"
                return "Default (Sleep lock enabled)"
            if screen_lock:
                return "Default (Secure screen saver lock)"
            return "Disabled (No policy enforced)"
        except Exception:
            return "Unknown"

    @staticmethod
    def _windows_anonymous_access():
        try:
            checks = (
                (
                    r"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RestrictAnonymous",
                    "Legacy default",
                ),
                (
                    r"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RestrictAnonymousSAM",
                    "Anonymous SAM enumeration – Exposed",
                ),
                (
                    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "RestrictNullSessAccess",
                    "Null-session access – Exposed",
                ),
            )

            findings = []
            all_restricted = True

            for key_path, value_name, remark in checks:
                val = read_registry_value("HKLM", key_path, value_name)
                if val is None:
                    all_restricted = False
                    continue
                try:
                    int_val = int(val)
                except (TypeError, ValueError):
                    all_restricted = False
                    continue

                if int_val == 0:
                    all_restricted = False
                    findings.append(f"{value_name} = {int_val}: {remark}")

            if all_restricted:
                return "Restricted"
            if findings:
                return "; ".join(findings)
            return "Unknown (Policy Values Missing)"
        except Exception:
            return "Unknown"

    @staticmethod
    def _windows_defender_asr():
        try:
            import winreg

            asr_paths = (
                r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
            )
            rules = {}
            found_key = False
            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)

            for path in asr_paths:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE, path, 0, access
                    ) as key:
                        found_key = True
                        idx = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, idx)
                                idx += 1
                            except OSError:
                                break
                            guid = str(name).strip().lower()
                            if not guid:
                                continue
                            try:
                                rules[guid] = int(str(value).strip())
                            except (TypeError, ValueError):
                                continue
                except FileNotFoundError:
                    continue

            if not found_key or not rules:
                return "Not Configured"

            enabled = sum(1 for v in rules.values() if v == 1)
            audit = sum(1 for v in rules.values() if v == 2)
            warn = sum(1 for v in rules.values() if v == 6)
            disabled = sum(1 for v in rules.values() if v == 0)

            details = f"Block: {enabled}, Audit: {audit}"
            if warn:
                details += f", Warn: {warn}"
            details += f", Disabled: {disabled}"
            return f"Configured ({len(rules)} rules - {details})"
        except Exception:
            return "Unknown"

    @staticmethod
    def _windows_uac():
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        enable_uac = read_registry_value("HKLM", key_path, "EnableLUA")
        if enable_uac is None:
            return "Not Found"
        try:
            if int(enable_uac) == 0:
                return "Disabled"
        except (TypeError, ValueError):
            return "Unknown"

        raw_consent = read_registry_value(
            "HKLM", key_path, "ConsentPromptBehaviorAdmin"
        )
        if raw_consent is None:
            consent_behavior = 5
        else:
            try:
                consent_behavior = int(raw_consent)
            except (TypeError, ValueError):
                consent_behavior = None

        raw_approval = read_registry_value(
            "HKLM", key_path, "TypeOfAdminApprovalMode"
        )
        try:
            admin_protection = (
                raw_approval is not None and int(raw_approval) == 2
            )
        except (TypeError, ValueError):
            admin_protection = False

        uac_levels = {
            0: "Without prompting (Potentially Dangerous)",
            1: "Prompt for credentials (Desktop Environment)",
            2: "Prompt for consent (Desktop Environment)",
            3: "Prompt for credentials",
            4: "Prompt for consent",
            5: "Prompt for consent (Non-Windows binaries)",
        }
        if consent_behavior is None:
            level_desc = f"Invalid ({raw_consent})"
        else:
            level_desc = uac_levels.get(
                consent_behavior, f"Invalid ({consent_behavior})"
            )

        if admin_protection:
            if level_desc.endswith(")"):
                level_desc = f"{level_desc[:-1]}, Administrator Protection)"
            else:
                level_desc = f"{level_desc} (Administrator Protection)"
        return level_desc

    @staticmethod
    def _windows_macro_policy():
        macro_paths = (
            ("HKCU", r"Software\Policies\Microsoft\Office\16.0\Word\Security"),
            ("HKLM", r"Software\Policies\Microsoft\Office\16.0\Word\Security"),
            ("HKCU", r"Software\Microsoft\Office\16.0\Word\Security"),
        )
        raw_macro = None
        for root_name, path in macro_paths:
            raw_macro = read_registry_value(root_name, path, "VBAWarnings")
            if raw_macro is not None:
                break

        if raw_macro is None:
            return ["Default (System controlled)"]

        try:
            macro_val = int(str(raw_macro).strip())
        except (TypeError, ValueError):
            macro_val = raw_macro

        mapping = {
            4: "Disabled (No macros)",
            3: "Disabled (Except digitally signed)",
            2: "Disabled (With notification)",
            1: "Enabled (All macros allowed - Unsafe)",
        }
        return [mapping.get(macro_val, f"Unknown ({raw_macro})")]

    def _windows_system_restore(self):
        try:
            import winreg

            policy_path = r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore"
            for val_name in ("DisableSR", "DisableConfig"):
                val = read_registry_value("HKLM", policy_path, val_name)
                if val is not None:
                    try:
                        if int(val) == 1:
                            return "Disabled"
                    except (TypeError, ValueError):
                        pass

            key_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
            )
            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, key_path, 0, access
                ):
                    pass
            except FileNotFoundError:
                return "Unusable (Server)"

            disable_sr = read_registry_value("HKLM", key_path, "DisableSR")
            if disable_sr is not None:
                try:
                    return "Disabled" if int(disable_sr) == 1 else "Enabled"
                except (TypeError, ValueError):
                    pass

            rp_interval = read_registry_value(
                "HKLM", key_path, "RPSessionInterval"
            )
            if rp_interval is not None:
                try:
                    return "Enabled" if int(rp_interval) >= 1 else "Disabled"
                except (TypeError, ValueError):
                    pass
        except Exception:
            return "Unknown"

        sc_out = (self._run(["sc.exe", "qc", "SDRSVC"]) or "").upper()
        if "DISABLED" in sc_out:
            return "Disabled"
        return "Unknown"

    @staticmethod
    def _windows_efs_scan():
        try:
            import ctypes

            invalid_attrs = 0xFFFFFFFF
            reparse_point = 0x400
            encrypted_attr = 0x4000
            get_file_attrs = ctypes.windll.kernel32.GetFileAttributesW
            skip_dirs = {
                "appdata",
                "application data",
                "windowsapps",
                ".git",
                "node_modules",
                "__pycache__",
            }

            efs_found = False
            checked_files = 0
            max_files = 15000
            deadline = time.monotonic() + 3.0

            for root, dirs, files in os.walk(
                os.path.expanduser("~"), followlinks=False
            ):
                kept_dirs = []
                for d in dirs:
                    if d.lower() in skip_dirs:
                        continue
                    d_path = os.path.join(root, d)
                    d_attrs = get_file_attrs(d_path)
                    if d_attrs in (-1, invalid_attrs):
                        continue
                    if d_attrs & reparse_point:
                        continue
                    kept_dirs.append(d)
                dirs[:] = kept_dirs

                for filename in files:
                    if checked_files >= max_files or time.monotonic() > deadline:
                        break
                    checked_files += 1
                    file_path = os.path.join(root, filename)
                    try:
                        attrs = get_file_attrs(file_path)
                        if attrs not in (-1, invalid_attrs) and (
                            attrs & encrypted_attr
                        ):
                            efs_found = True
                            break
                    except Exception:
                        continue

                if (
                    efs_found
                    or checked_files >= max_files
                    or time.monotonic() > deadline
                ):
                    break

            return (
                "Encrypted files found"
                if efs_found
                else "No encrypted files"
            )
        except Exception:
            return "Unknown"

    def _windows_audit(self):
        ps_data = self._windows_ps_bundle()

        result = {
            "Windows Defender": [],
            "Endpoint Protection": [],
            "Host-based Firewall": "Unknown",
            "Auto Screen Lock": "Unknown",
            "Office Macro Policy": "Unknown",
            "Defender ASR Rules": "Unknown",
            "UAC Elevation": "Unknown",
            "PowerShell Scripts": "Unknown",
            "Anonymous Access": "Unknown",
            "Core Isolation": "Unknown",
            "Data Execution Prevention": "Unknown",
            "UEFI Secure Boot": "Unknown",
            "Encrypted File System": "Unknown",
            "BitLocker Drive Encryption": "Unknown",
            "Removable Storage": "Unknown",
            "USB AutoRun": "Unknown",
            "System Restore": "Unknown",
        }

        # 1. Windows Defender
        def_info = ps_data.get("defender")
        if isinstance(def_info, dict) and def_info:
            active = (
                def_info.get("AMServiceEnabled") is True
                and def_info.get("AntivirusEnabled") is True
                and def_info.get("RealTimeProtectionEnabled") is True
            )
            result["Windows Defender"].append(
                f"Windows Defender ({'Active' if active else 'Inactive'})"
            )
        else:
            sc_def = (self._run(["sc.exe", "query", "WinDefend"]) or "").upper()
            if "RUNNING" in sc_def:
                result["Windows Defender"].append("Windows Defender (Active)")
            elif "STOPPED" in sc_def:
                result["Windows Defender"].append("Windows Defender (Inactive)")
            else:
                result["Windows Defender"].append("Windows Defender (Unknown)")

        # 2. Third-party Endpoint Protection (SecurityCenter2)
        for name, active in self._parse_sc2_products(ps_data.get("av")):
            if name.lower() == "windows defender":
                continue
            if active is None:
                result["Endpoint Protection"].append(f"{name} (Unknown)")
            else:
                result["Endpoint Protection"].append(
                    f"{name} ({'Active' if active else 'Inactive'})"
                )

        # 3. Host-based Firewall (SecurityCenter2 3rd-party aware + Windows Firewall fallback)
        active_3p_fw = None
        for fw_name, fw_active in self._parse_sc2_products(ps_data.get("fw")):
            if fw_active is True and fw_name.lower() != "windows firewall":
                active_3p_fw = fw_name
                break

        if active_3p_fw:
            result["Host-based Firewall"] = f"{active_3p_fw} (On)"
        else:
            fw_info = self._windows_firewall_managed_by()
            controller = (
                fw_info["product_name"]
                if fw_info["managed"]
                else "Windows Firewall"
            )
            fw_state = self._windows_firewall_state()
            result["Host-based Firewall"] = (
                f"{controller} ({fw_state})" if fw_state != "Unknown" else "Unknown"
            )

        # 4. Auto Screen Lock
        result["Auto Screen Lock"] = self._windows_auto_screen_lock()

        # 5. Office Macro Policy
        result["Office Macro Policy"] = self._windows_macro_policy()

        # 6. Defender ASR Rules
        result["Defender ASR Rules"] = self._windows_defender_asr()

        # 7. UAC Elevation
        result["UAC Elevation"] = self._windows_uac()

        # 8. Core Isolation (HVCI)
        hvc_path = (
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
            r"\HypervisorEnforcedCodeIntegrity"
        )
        raw_hvci = read_registry_value("HKLM", hvc_path, "Enabled")
        try:
            reg_hvci = int(raw_hvci) if raw_hvci is not None else None
        except (TypeError, ValueError):
            reg_hvci = None

        dg_running = ps_data.get("dg_running")
        if isinstance(dg_running, int):
            dg_running = [dg_running]
        if isinstance(dg_running, list):
            services = {
                int(x) for x in dg_running if str(x).strip().isdigit()
            }
            if 2 in services:
                result["Core Isolation"] = "Enabled"
            elif reg_hvci == 1:
                result["Core Isolation"] = "Disabled (Configured, not running)"
            else:
                result["Core Isolation"] = "Disabled"
        else:
            if reg_hvci == 0:
                result["Core Isolation"] = "Disabled"
            elif reg_hvci == 1:
                result["Core Isolation"] = "Unknown (Runtime unverified)"
            else:
                result["Core Isolation"] = "Unknown"

        # 9. PowerShell Scripts
        exec_pol = str(ps_data.get("exec_policy") or "").strip()
        valid_policies = {
            "Restricted",
            "RemoteSigned",
            "AllSigned",
            "Unrestricted",
            "Bypass",
            "Undefined",
        }
        result["PowerShell Scripts"] = (
            exec_pol if exec_pol in valid_policies else "Unknown"
        )

        # 10. Anonymous Access
        result["Anonymous Access"] = self._windows_anonymous_access()

        # 11. Data Execution Prevention (DEP)
        dep_map = {
            "0": "Disabled",
            "1": "Enabled (Always On)",
            "2": "Enabled (Opt In)",
            "3": "Enabled (Opt Out)",
        }
        dep_val = ps_data.get("dep")
        result["Data Execution Prevention"] = dep_map.get(
            str(dep_val).strip() if dep_val is not None else "",
            "Unknown",
        )

        # 12. Encrypted File System (EFS)
        result["Encrypted File System"] = self._windows_efs_scan()

        # 13. BitLocker Drive Encryption
        bl_info = ps_data.get("bitlocker")
        if isinstance(bl_info, dict):
            bl_source = bl_info.get("source")
            raw_vals = bl_info.get("values") or []
            if not isinstance(raw_vals, list):
                raw_vals = [raw_vals]
            if bl_source == "cmdlet":
                statuses = {
                    str(v).strip().lower() for v in raw_vals if v is not None
                }
                if statuses & {"1", "on"}:
                    result["BitLocker Drive Encryption"] = "Enabled"
                elif statuses & {"0", "off"}:
                    result["BitLocker Drive Encryption"] = "Disabled"
            elif bl_source == "shell":
                int_vals = {
                    int(v)
                    for v in raw_vals
                    if v is not None and str(v).strip().isdigit()
                }
                if int_vals & {1, 3, 6, 7}:
                    result["BitLocker Drive Encryption"] = "Enabled"
                elif int_vals:
                    result["BitLocker Drive Encryption"] = "Disabled"

        # 14. UEFI Secure Boot
        sb_reg = read_registry_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        )
        if sb_reg == 1:
            result["UEFI Secure Boot"] = "Enabled"
        elif sb_reg == 0:
            result["UEFI Secure Boot"] = "Disabled"
        else:
            sb_wmi = ps_data.get("sb_wmi")
            if sb_wmi is True or str(sb_wmi).lower() == "true":
                result["UEFI Secure Boot"] = "Enabled"
            elif sb_wmi is False or str(sb_wmi).lower() == "false":
                result["UEFI Secure Boot"] = "Disabled"
            else:
                result["UEFI Secure Boot"] = "Unsupported"

        # 15. Removable Storage
        usbstor = read_registry_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\USBSTOR",
            "Start",
        )
        if usbstor is None:
            result["Removable Storage"] = "Unknown"
        elif usbstor == 4:
            result["Removable Storage"] = "Disabled"
        else:
            result["Removable Storage"] = "Enabled"

        # 16. USB AutoRun
        autorun = read_registry_value(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
        )
        if autorun is None:
            result["USB AutoRun"] = "Default"
        elif autorun == 255:
            result["USB AutoRun"] = "Disabled"
        else:
            result["USB AutoRun"] = "Partially Disabled"

        # 17. System Restore
        result["System Restore"] = self._windows_system_restore()

        return result

    def _linux_audit(self):
        result = {
            "Mandatory Access Control": "Unknown",
            "Endpoint Protection": [],
            "Host-based Firewall": "Unknown",
            "Auto Screen Lock": "Unknown",
            "Kernel Hardening (ASLR)": "Unknown",
            "UEFI Secure Boot": "Unknown",
            "Disk Encryption": "Unknown",
            "Removable Storage": "Unknown",
            "System Snapshots": "Unknown",
        }

        # 1. Mandatory Access Control (AppArmor / SELinux)
        try:
            if os.path.isfile("/sys/module/apparmor/parameters/enabled"):
                with open(
                    "/sys/module/apparmor/parameters/enabled",
                    encoding="utf-8",
                ) as f:
                    aa = f.read().strip().upper()
                result["Mandatory Access Control"] = (
                    "AppArmor (Enabled)"
                    if aa == "Y"
                    else "AppArmor (Disabled)"
                )
            elif shutil.which("getenforce"):
                se = self._run(["getenforce"])
                if se:
                    result["Mandatory Access Control"] = f"SELinux ({se})"
        except OSError:
            pass

        # 2. Endpoint Protection (running AV/EDR daemons)
        detected_edr = set()
        for proc in psutil.process_iter(["name"]):
            try:
                pname = (proc.info.get("name") or "").lower()
                if pname in self._LINUX_EDR_PROCESSES:
                    detected_edr.add(
                        f"{self._LINUX_EDR_PROCESSES[pname]} (Active)"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        result["Endpoint Protection"] = sorted(detected_edr)

        # 3. Host-based Firewall
        if shutil.which("ufw"):
            out = self._run(["ufw", "status"])
            if out:
                lower = out.lower()
                if "status: active" in lower:
                    result["Host-based Firewall"] = "UFW (On)"
                elif "status: inactive" in lower:
                    result["Host-based Firewall"] = "UFW (Off)"
        if (
            result["Host-based Firewall"] == "Unknown"
            and os.path.isfile("/etc/ufw/ufw.conf")
        ):
            try:
                with open(
                    "/etc/ufw/ufw.conf", encoding="utf-8", errors="replace"
                ) as f:
                    for line in f:
                        cleaned = line.split("#", 1)[0].strip().lower()
                        if cleaned.startswith("enabled="):
                            val = cleaned.split("=", 1)[1].strip().strip("\"'")
                            if val == "yes":
                                result["Host-based Firewall"] = "UFW (On)"
                            elif val == "no":
                                result["Host-based Firewall"] = "UFW (Off)"
                            break
            except OSError:
                pass
        if (
            result["Host-based Firewall"] == "Unknown"
            and shutil.which("firewall-cmd")
        ):
            res = self._run_result(["firewall-cmd", "--state"])
            if res is not None:
                rc, stdout, stderr = res
                combined = f"{stdout}\n{stderr}".strip().lower()
                if rc == 0 and "running" in combined and "not running" not in combined:
                    result["Host-based Firewall"] = "firewalld (On)"
                elif "not running" in combined:
                    result["Host-based Firewall"] = "firewalld (Off)"
        if (
            result["Host-based Firewall"] == "Unknown"
            and shutil.which("systemctl")
        ):
            installed_inactive = None
            systemd_reachable = False
            for svc, label in (
                ("ufw", "UFW"),
                ("firewalld", "firewalld"),
                ("nftables", "nftables"),
                ("netfilter-persistent", "iptables"),
                ("iptables", "iptables"),
            ):
                props = self._run([
                    "systemctl",
                    "show",
                    "-p",
                    "LoadState",
                    "-p",
                    "ActiveState",
                    svc,
                ])
                if props:
                    systemd_reachable = True
                    kv = {}
                    for line in props.splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            kv[k.strip()] = v.strip().lower()
                    active_state = kv.get("ActiveState", "")
                    load_state = kv.get("LoadState", "")
                    if active_state == "active":
                        result["Host-based Firewall"] = f"{label} (On)"
                        break
                    if (
                        load_state == "loaded"
                        and active_state in ("inactive", "failed", "dead")
                        and installed_inactive is None
                    ):
                        installed_inactive = label
                else:
                    state = self._run(["systemctl", "is-active", svc])
                    if state and state.strip().lower() == "active":
                        result["Host-based Firewall"] = f"{label} (On)"
                        break

            if result["Host-based Firewall"] == "Unknown":
                is_root = hasattr(os, "geteuid") and os.geteuid() == 0
                if is_root and shutil.which("nft"):
                    nft_out = self._run(["nft", "list", "ruleset"])
                    if nft_out and "chain " in nft_out:
                        result["Host-based Firewall"] = "nftables (On)"
                if (
                    result["Host-based Firewall"] == "Unknown"
                    and is_root
                    and shutil.which("iptables")
                ):
                    ipt_out = self._run(["iptables", "-S"])
                    if ipt_out:
                        has_rules = any(
                            ln.strip().startswith(
                                ("-A ", "-P INPUT DROP", "-P INPUT REJECT")
                            )
                            for ln in ipt_out.splitlines()
                        )
                        if has_rules:
                            result["Host-based Firewall"] = "iptables (On)"
                if result["Host-based Firewall"] == "Unknown":
                    if installed_inactive:
                        result["Host-based Firewall"] = (
                            f"{installed_inactive} (Off)"
                        )
                    elif systemd_reachable or is_root:
                        result["Host-based Firewall"] = "Not Detected (Off)"

        # 4. Auto Screen Lock
        if shutil.which("gsettings"):
            lock_en = self._run([
                "gsettings",
                "get",
                "org.gnome.desktop.screensaver",
                "lock-enabled",
            ])
            if lock_en in ("true", "false"):
                result["Auto Screen Lock"] = (
                    "Enabled (GNOME screensaver lock)"
                    if lock_en == "true"
                    else "Disabled (GNOME screensaver lock)"
                )

        # 5. Kernel Hardening (ASLR)
        try:
            with open(
                "/proc/sys/kernel/randomize_va_space", encoding="utf-8"
            ) as f:
                aslr = f.read().strip()
            aslr_map = {
                "0": "Disabled",
                "1": "Enabled (Conservative)",
                "2": "Enabled (Full ASLR)",
            }
            result["Kernel Hardening (ASLR)"] = aslr_map.get(aslr, "Unknown")
        except OSError:
            pass

        # 6. Disk Encryption (LUKS / dm-crypt)
        if shutil.which("lsblk"):
            out = self._run(["lsblk", "-o", "NAME,TYPE,FSTYPE", "--json"])
            if out:
                try:
                    data = json.loads(out)
                    text_dump = json.dumps(data).lower()
                    if "crypto_luks" in text_dump or '"type": "crypt"' in text_dump:
                        result["Disk Encryption"] = "Enabled (LUKS/dm-crypt)"
                    else:
                        result["Disk Encryption"] = "Not Detected"
                except json.JSONDecodeError:
                    pass

        # 7. UEFI Secure Boot
        if not os.path.isdir("/sys/firmware/efi"):
            result["UEFI Secure Boot"] = "Unsupported"
        else:
            sb_files = glob.glob(
                "/sys/firmware/efi/efivars/SecureBoot-*"
            )
            if sb_files:
                try:
                    with open(sb_files[0], "rb") as f:
                        raw = f.read()
                    if len(raw) >= 5:
                        result["UEFI Secure Boot"] = (
                            "Enabled" if raw[-1] == 1 else "Disabled"
                        )
                except OSError:
                    pass
            if result["UEFI Secure Boot"] == "Unknown" and shutil.which("mokutil"):
                out = self._run(["mokutil", "--sb-state"])
                if out:
                    lower = out.lower()
                    if "enabled" in lower:
                        result["UEFI Secure Boot"] = "Enabled"
                    elif "disabled" in lower:
                        result["UEFI Secure Boot"] = "Disabled"
            if result["UEFI Secure Boot"] == "Unknown" and shutil.which("bootctl"):
                res = self._run_result(["bootctl", "status"])
                if res is not None:
                    _, stdout, _ = res
                    for line in stdout.splitlines():
                        low = line.strip().lower()
                        if low.startswith("secure boot:"):
                            val = low.split(":", 1)[1].strip()
                            if val.startswith("enabled"):
                                result["UEFI Secure Boot"] = "Enabled"
                            elif val.startswith("disabled"):
                                result["UEFI Secure Boot"] = "Disabled"
                            break

        # 8. Removable Storage
        usb_disabled = False
        for conf in glob.glob("/etc/modprobe.d/*.conf"):
            try:
                with open(conf, encoding="utf-8", errors="replace") as f:
                    content = f.read().lower()
                if "blacklist usb-storage" in content or "install usb-storage /bin/false" in content:
                    usb_disabled = True
                    break
            except OSError:
                continue
        result["Removable Storage"] = "Disabled" if usb_disabled else "Enabled"

        # 9. System Snapshots
        if shutil.which("timeshift"):
            result["System Snapshots"] = "Available (Timeshift)"
        elif shutil.which("snapper"):
            result["System Snapshots"] = "Available (Snapper)"
        else:
            result["System Snapshots"] = "Not Detected"

        return result

    def _macos_audit(self):
        result = {
            "Gatekeeper": "Unknown",
            "Endpoint Protection": [],
            "Host-based Firewall": "Unknown",
            "Auto Screen Lock": "Unknown",
            "System Integrity Protection": "Unknown",
            "FileVault Disk Encryption": "Unknown",
            "Time Machine Backups": "Unknown",
        }

        # 1. Gatekeeper
        out = self._run(["spctl", "--status"])
        if out:
            lower = out.lower()
            if "assessments enabled" in lower:
                result["Gatekeeper"] = "Enabled"
            elif "disabled" in lower:
                result["Gatekeeper"] = "Disabled"

        # 2. System Integrity Protection (SIP)
        out = self._run(["csrutil", "status"])
        if out:
            lower = out.lower()
            if "enabled" in lower:
                result["System Integrity Protection"] = "Enabled"
            elif "disabled" in lower:
                result["System Integrity Protection"] = "Disabled"

        # 3. Endpoint Protection (XProtect + running EDR daemons)
        edr = set()
        if os.path.exists(
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
        ):
            edr.add("Apple XProtect (Active)")
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info.get("name") or ""
                if pname in self._MACOS_EDR_PROCESSES:
                    edr.add(f"{self._MACOS_EDR_PROCESSES[pname]} (Active)")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        result["Endpoint Protection"] = sorted(edr)

        # 4. Host-based Firewall
        out = self._run([
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            "--getglobalstate",
        ])
        if out:
            lower = out.lower()
            if "enabled" in lower:
                result["Host-based Firewall"] = "Application Firewall (On)"
            elif "disabled" in lower:
                result["Host-based Firewall"] = "Application Firewall (Off)"

        # 5. Auto Screen Lock
        out = self._run([
            "defaults",
            "-currentHost",
            "read",
            "com.apple.screensaver",
            "askForPassword",
        ])
        if out in ("1", "0"):
            result["Auto Screen Lock"] = (
                "Enabled" if out == "1" else "Disabled"
            )

        # 6. FileVault Disk Encryption
        out = self._run(["fdesetup", "status"])
        if out:
            lower = out.lower()
            if "filevault is on" in lower:
                result["FileVault Disk Encryption"] = "Enabled"
            elif "filevault is off" in lower:
                result["FileVault Disk Encryption"] = "Disabled"

        # 7. Time Machine Backups
        out = self._run(["tmutil", "destinationinfo"])
        if out:
            if "no destinations configured" in out.lower():
                result["Time Machine Backups"] = "Disabled"
            else:
                result["Time Machine Backups"] = "Configured"

        return result

    def audit(self):
        """Return a structured endpoint security report."""
        if self.system == "Windows":
            checks = self._windows_audit()
        elif self.system == "Linux":
            checks = self._linux_audit()
        elif self.system == "Darwin":
            checks = self._macos_audit()
        else:
            checks = {}

        return {
            "platform": self.system,
            "hostname": platform.node(),
            "checks": checks,
            "notes": [
                "Unknown means the check could not be verified.",
                "Some checks may require elevated permissions.",
                "Configuration does not necessarily prove runtime enforcement.",
            ],
        }


SecurityAudit = SecuritySettingsAudit
EndpointSecurity = SecuritySettingsAudit

if __name__ == "__main__":
    print(json.dumps(
        SecuritySettingsAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
