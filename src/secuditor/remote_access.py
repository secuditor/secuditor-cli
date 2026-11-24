# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform remote access services and protocol exposure audit."""

import json
import os
import platform
import re
import shutil
import socket

import psutil

from ._utils import (
    _system_exe,
    find_powershell,
    read_registry_value,
    run_command,
    run_command_result,
    run_powershell,
)

__all__ = ["RemoteAccessSettings", "RemoteAccessAudit"]


class RemoteAccessAudit:
    """Audit remote access services, protocols, and wireless exposure across OSes."""

    def __init__(self, timeout=15.0):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        return run_command(args, timeout=self.timeout)

    def _run_raw(self, args):
        """Run a command and return combined stdout/stderr even on non-zero exit."""
        res = run_command_result(args, timeout=self.timeout)
        if res is None:
            return ""
        _rc, stdout, stderr = res
        return ((stdout or "") + "\n" + (stderr or "")).strip()

    @staticmethod
    def _windows_is_admin():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (ImportError, AttributeError, OSError):
            return False

    @staticmethod
    def _windows_os_build():
        raw = (
            read_registry_value(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "CurrentBuildNumber",
            )
            or read_registry_value(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "CurrentBuild",
            )
        )
        try:
            return int(raw) if raw is not None else 0
        except (TypeError, ValueError):
            return 0

    def _windows_ps_bundle(self):
        """Run a single batched PowerShell query for Windows remote access checks."""
        if not find_powershell():
            return {}

        script = (
            "$fw = @(); "
            "try { $fw = @(Get-NetFirewallProfile -ErrorAction Stop "
            "| Select-Object -ExpandProperty Enabled) } catch {}; "
            "$wrm = @{ ok = $false; keys = @() }; "
            "try { $wrm_keys = @(Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction Stop "
            "| ForEach-Object { [string]($_.Keys -join ',') }); "
            "$wrm = @{ ok = $true; keys = $wrm_keys } } catch {}; "
            "$smb_svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue; "
            "$smb_cfg = $null; "
            "try { $smb_cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue "
            "| Select-Object EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,"
            "EncryptData,RejectUnencryptedAccess,EnableStrictNameChecking,"
            "EnableAuthenticateUserSharing,NullSessionShares,NullSessionPipes,"
            "SmbServerNameHardeningLevel } catch {}; "
            "$smb_reg = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
            "-ErrorAction SilentlyContinue; "
            "$smb2 = [PSCustomObject]@{ "
            "Service = if ($smb_svc) { @{ Status = $smb_svc.Status.ToString(); StartType = $smb_svc.StartType.ToString() } } else { $null }; "
            "Config = $smb_cfg; "
            "RestrictNullSessAccess = if ($smb_reg -and ($smb_reg.PSObject.Properties.Name -contains 'restrictnullsessaccess')) { $smb_reg.restrictnullsessaccess } else { $null } "
            "}; "
            "$rsync = $null; "
            "try { $s = Get-CimInstance Win32_Service -Filter \"Name='rsync'\" -ErrorAction SilentlyContinue; "
            "if ($s) { $rsync = @{ State = $s.State; StartMode = $s.StartMode } } } catch {}; "
            "$upnp = $null; "
            "try { $s = Get-CimInstance Win32_Service -Filter \"Name='upnphost'\" -ErrorAction SilentlyContinue; "
            "if ($s) { $upnp = @{ State = $s.State; StartMode = $s.StartMode } } } catch {}; "
            "$bt_ok = $false; $bt_devs = @(); "
            "try { "
            "$bt_devs = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue "
            "| Where-Object { $_.Present -eq $true } "
            "| Select-Object Status,FriendlyName,InstanceId,Present,"
            "@{Name='ProblemCode';Expression={ try { (Get-PnpDeviceProperty -InstanceId $_.InstanceId "
            "-KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop).Data } catch { $null } }}); "
            "$bt_drv = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter \"DeviceClass='BLUETOOTH'\" "
            "-ErrorAction SilentlyContinue | Select-Object DeviceID,IsSigned,Signer,DriverVersion); "
            "foreach ($d in $bt_devs) { "
            "$m = $bt_drv | Where-Object { $_.DeviceID -eq $d.InstanceId } | Select-Object -First 1; "
            "$d | Add-Member -NotePropertyName DriverIsSigned -NotePropertyValue $(if ($m) { $m.IsSigned } else { $null }) -Force; "
            "}; $bt_ok = $true "
            "} catch {}; "
            "[PSCustomObject]@{ "
            "fw_profiles = $fw; winrm_listeners = $wrm; smb2 = $smb2; "
            "rsync = $rsync; upnp = $upnp; "
            "bluetooth = @{ QuerySucceeded = $bt_ok; Devices = @($bt_devs) } "
            "} | ConvertTo-Json -Depth 5 -Compress"
        )
        data = run_powershell(script, timeout=self.timeout, parse_json=True)
        return data if isinstance(data, dict) else {}

    # --- Windows WinRM helpers ---

    def _windows_winrm_service(self):
        qc_out = self._run_raw(["sc.exe", "qc", "WinRM"]).upper()
        if not qc_out:
            return {"status": "Unknown", "running": False, "startup": "Unknown"}
        if "1060" in qc_out:
            return {"status": "Disabled", "running": False, "startup": "Disabled"}
        if "SERVICE_NAME" not in qc_out:
            return {"status": "Unknown", "running": False, "startup": "Unknown"}

        if "AUTO_START" in qc_out:
            startup = "Automatic"
        elif "DEMAND_START" in qc_out:
            startup = "Manual"
        elif "DISABLED" in qc_out:
            startup = "Disabled"
        else:
            startup = "Unknown"

        if "DISABLED" in qc_out:
            return {"status": "Disabled", "running": False, "startup": startup}

        query_out = self._run_raw(["sc.exe", "query", "WinRM"]).upper()
        running = "RUNNING" in query_out
        return {"status": "Enabled", "running": running, "startup": startup}

    @staticmethod
    def _windows_winrm_ports():
        ports = set()
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if (
                    conn.status == psutil.CONN_LISTEN
                    and conn.laddr
                    and conn.laddr.port in (5985, 5986)
                ):
                    ports.add(conn.laddr.port)
            return sorted(ports)
        except Exception:
            pass

        for port in (5985, 5986):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        ports.add(port)
            except OSError:
                continue
        return sorted(ports)

    @staticmethod
    def _windows_winrm_auth():
        auth = {}
        value_map = {
            "Basic": ("AllowBasic", "auth_basic"),
            "Kerberos": ("AllowKerberos", "auth_kerberos"),
            "Negotiate": ("AllowNegotiate", "auth_negotiate"),
            "Certificate": (None, "auth_certificate"),
        }
        policy_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        wsman_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"

        any_found = False
        for display_name, (gpo_name, local_name) in value_map.items():
            val = None
            if gpo_name:
                val = read_registry_value("HKLM", policy_path, gpo_name)
            if val is None and local_name:
                val = read_registry_value("HKLM", wsman_path, local_name)
            if val is not None:
                any_found = True
                auth[display_name] = bool(val)
            else:
                auth[display_name] = False
        return auth if any_found else {}

    @staticmethod
    def _windows_winrm_encrypted():
        for path, val_name in (
            (
                r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
                "AllowUnencryptedTraffic",
            ),
            (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service",
                "allow_unencrypted",
            ),
        ):
            val = read_registry_value("HKLM", path, val_name)
            if val is not None:
                return not bool(val)
        return True

    @staticmethod
    def _assess_winrm_risk(service, listeners, auth, encrypted):
        if not service.get("running"):
            return "None"
        if auth.get("Basic"):
            return "Critical"
        if listeners.get("http") and not encrypted:
            return "High"
        if listeners.get("http") and listeners.get("https"):
            return "Medium"
        if listeners.get("https"):
            return "Low"
        return "Medium"

    @staticmethod
    def _winrm_verdict(service, listeners, ports, risk):
        status = str(service.get("status") or "Unknown").lower()
        if status == "unknown":
            return "Unknown"
        if status != "enabled":
            return "Disabled"

        if listeners.get("unknown"):
            if not service.get("running") and not ports:
                return "Enabled, Low Risk (No port listeners)"
            if 5985 in ports:
                return "Enabled, High Risk (HTTP listener on 5985)"
            if 5986 in ports:
                return "Enabled, Moderate Risk (HTTPS listener on 5986)"
            return "Unknown"

        if not listeners.get("http") and not listeners.get("https"):
            return "Enabled, Low Risk (No listeners)"
        if not ports:
            return "Enabled, Low Risk (No port listeners)"
        if risk == "Low":
            return "Enabled, Moderate Risk (Restricted exposure)"
        if risk == "Medium":
            return "Enabled, Moderate Risk (Network exposure)"
        if risk in ("High", "Critical"):
            return "Enabled, High Risk (Remote access exposed)"
        return "Enabled, Unknown Risk (Exposure unknown)"

    @staticmethod
    def _parse_winrm_listeners(raw_wrm):
        if not isinstance(raw_wrm, dict) or not raw_wrm.get("ok"):
            return {"http": False, "https": False, "unknown": True}
        keys = raw_wrm.get("keys") or []
        if isinstance(keys, str):
            keys = [keys]
        text = "\n".join(str(k) for k in keys if k)
        return {
            "http": bool(re.search(r"\bTransport\s*=\s*HTTP\b", text, re.IGNORECASE)),
            "https": bool(re.search(r"\bTransport\s*=\s*HTTPS\b", text, re.IGNORECASE)),
            "unknown": False,
        }

    # --- Windows Bluetooth helpers ---

    @staticmethod
    def _is_bluetooth_radio_controller(instance_id):
        iid = str(instance_id or "").strip().upper()
        if not iid:
            return False
        if iid.startswith(("BTHENUM\\", "BTHLE\\", "BTHLEDEVICE\\", "BTH\\")):
            return False
        return iid.startswith(
            ("USB\\", "PCI\\", "ACPI\\", "SD\\", "UART\\", "BTHUSB\\", "HID\\", "ROOT\\")
        )

    @staticmethod
    def _query_bluetooth_win32_state():
        state = {
            "active_radios": 0,
            "connectable": False,
            "discoverable": False,
            "connected_count": 0,
            "paired_count": 0,
            "unauthenticated_connected": 0,
        }
        try:
            import ctypes
            from ctypes import wintypes

            class _BLUETOOTH_FIND_RADIO_PARAMS(ctypes.Structure):
                _fields_ = [("dwSize", wintypes.DWORD)]

            class _SYSTEMTIME(ctypes.Structure):
                _fields_ = [
                    ("wYear", wintypes.WORD),
                    ("wMonth", wintypes.WORD),
                    ("wDayOfWeek", wintypes.WORD),
                    ("wDay", wintypes.WORD),
                    ("wHour", wintypes.WORD),
                    ("wMinute", wintypes.WORD),
                    ("wSecond", wintypes.WORD),
                    ("wMilliseconds", wintypes.WORD),
                ]

            class _BLUETOOTH_DEVICE_SEARCH_PARAMS(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("fReturnAuthenticated", wintypes.BOOL),
                    ("fReturnRemembered", wintypes.BOOL),
                    ("fReturnUnknown", wintypes.BOOL),
                    ("fReturnConnected", wintypes.BOOL),
                    ("fIssueInquiry", wintypes.BOOL),
                    ("cTimeoutMultiplier", ctypes.c_ubyte),
                    ("hRadio", wintypes.HANDLE),
                ]

            class _BLUETOOTH_DEVICE_INFO(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("Address", ctypes.c_ulonglong),
                    ("ulClassofDevice", wintypes.ULONG),
                    ("fConnected", wintypes.BOOL),
                    ("fRemembered", wintypes.BOOL),
                    ("fAuthenticated", wintypes.BOOL),
                    ("stLastSeen", _SYSTEMTIME),
                    ("stLastUsed", _SYSTEMTIME),
                    ("szName", wintypes.WCHAR * 248),
                ]

            bth = ctypes.WinDLL(_system_exe("bthprops.cpl"))
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL

            bth.BluetoothFindFirstRadio.argtypes = [
                ctypes.POINTER(_BLUETOOTH_FIND_RADIO_PARAMS),
                ctypes.POINTER(wintypes.HANDLE),
            ]
            bth.BluetoothFindFirstRadio.restype = wintypes.HANDLE
            bth.BluetoothFindNextRadio.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            bth.BluetoothFindNextRadio.restype = wintypes.BOOL
            bth.BluetoothFindRadioClose.argtypes = [wintypes.HANDLE]
            bth.BluetoothFindRadioClose.restype = wintypes.BOOL

            bth.BluetoothIsConnectable.argtypes = [wintypes.HANDLE]
            bth.BluetoothIsConnectable.restype = wintypes.BOOL
            bth.BluetoothIsDiscoverable.argtypes = [wintypes.HANDLE]
            bth.BluetoothIsDiscoverable.restype = wintypes.BOOL

            bth.BluetoothFindFirstDevice.argtypes = [
                ctypes.POINTER(_BLUETOOTH_DEVICE_SEARCH_PARAMS),
                ctypes.POINTER(_BLUETOOTH_DEVICE_INFO),
            ]
            bth.BluetoothFindFirstDevice.restype = wintypes.HANDLE
            bth.BluetoothFindNextDevice.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(_BLUETOOTH_DEVICE_INFO),
            ]
            bth.BluetoothFindNextDevice.restype = wintypes.BOOL
            bth.BluetoothFindDeviceClose.argtypes = [wintypes.HANDLE]
            bth.BluetoothFindDeviceClose.restype = wintypes.BOOL

            rp = _BLUETOOTH_FIND_RADIO_PARAMS(
                dwSize=ctypes.sizeof(_BLUETOOTH_FIND_RADIO_PARAMS)
            )
            hradio = wintypes.HANDLE()
            hfind = bth.BluetoothFindFirstRadio(
                ctypes.byref(rp), ctypes.byref(hradio)
            )
            if hfind:
                try:
                    while True:
                        state["active_radios"] += 1
                        if bth.BluetoothIsConnectable(hradio):
                            state["connectable"] = True
                        if bth.BluetoothIsDiscoverable(hradio):
                            state["discoverable"] = True
                        k32.CloseHandle(hradio)
                        hradio = wintypes.HANDLE()
                        if not bth.BluetoothFindNextRadio(
                            hfind, ctypes.byref(hradio)
                        ):
                            break
                finally:
                    bth.BluetoothFindRadioClose(hfind)
            else:
                if bth.BluetoothIsConnectable(None):
                    state["connectable"] = True
                if bth.BluetoothIsDiscoverable(None):
                    state["discoverable"] = True

            if (
                state["active_radios"] > 0
                or state["connectable"]
                or state["discoverable"]
            ):
                sp = _BLUETOOTH_DEVICE_SEARCH_PARAMS(
                    dwSize=ctypes.sizeof(_BLUETOOTH_DEVICE_SEARCH_PARAMS),
                    fReturnAuthenticated=1,
                    fReturnRemembered=1,
                    fReturnUnknown=0,
                    fReturnConnected=1,
                    fIssueInquiry=0,
                    cTimeoutMultiplier=0,
                    hRadio=None,
                )
                di = _BLUETOOTH_DEVICE_INFO(
                    dwSize=ctypes.sizeof(_BLUETOOTH_DEVICE_INFO)
                )
                hdev = bth.BluetoothFindFirstDevice(
                    ctypes.byref(sp), ctypes.byref(di)
                )
                if hdev:
                    try:
                        seen_addrs = set()
                        while True:
                            addr = int(di.Address)
                            if addr not in seen_addrs:
                                seen_addrs.add(addr)
                                is_conn = bool(di.fConnected)
                                is_auth = bool(di.fAuthenticated)
                                is_rem = bool(di.fRemembered)
                                if is_auth or is_rem:
                                    state["paired_count"] += 1
                                if is_conn:
                                    state["connected_count"] += 1
                                    if not is_auth:
                                        state["unauthenticated_connected"] += 1
                            if not bth.BluetoothFindNextDevice(
                                hdev, ctypes.byref(di)
                            ):
                                break
                    finally:
                        bth.BluetoothFindDeviceClose(hdev)
        except (ImportError, OSError, AttributeError, ValueError):
            pass
        return state

    @staticmethod
    def _query_bluetooth_exposure_extras():
        extras = {
            "nearby_sharing_everyone": False,
            "pan_active": False,
            "file_transfer_active": False,
            "policy_hardened": False,
        }

        val = read_registry_value(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\CDP",
            "NearShareChannelUserAuthzPolicy",
        )
        try:
            if val is not None and int(val) == 2:
                extras["nearby_sharing_everyone"] = True
        except (TypeError, ValueError):
            pass

        try:
            for if_name, stats in psutil.net_if_stats().items():
                if "bluetooth" in str(if_name).lower() and getattr(
                    stats, "isup", False
                ):
                    extras["pan_active"] = True
                    break
        except Exception:
            pass

        try:
            for proc in psutil.process_iter(["name"]):
                pname = str((proc.info or {}).get("name") or "").strip().lower()
                if pname == "fsquirt.exe":
                    extras["file_transfer_active"] = True
                    break
        except Exception:
            pass

        for ppath in (
            r"SOFTWARE\Policies\Microsoft\Windows\Bluetooth",
            r"SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth",
        ):
            for vname in (
                "AllowDiscoverableMode",
                "AllowAdvertising",
                "AllowBluetooth",
            ):
                pval = read_registry_value("HKLM", ppath, vname)
                try:
                    if pval is not None and int(pval) == 0:
                        extras["policy_hardened"] = True
                        break
                except (TypeError, ValueError):
                    continue
            if extras["policy_hardened"]:
                break

        return extras

    @classmethod
    def _evaluate_bluetooth_verdict(cls, devices, win32_state, extras):
        present_devices = [
            d
            for d in (devices or [])
            if isinstance(d, dict) and d.get("Present", True) is not False
        ]
        radios = [
            d
            for d in present_devices
            if cls._is_bluetooth_radio_controller(d.get("InstanceId"))
        ]
        if not radios:
            radios = [
                d
                for d in present_devices
                if str(d.get("InstanceId") or "")
                .strip()
                .upper()
                .startswith("BTH\\MS_BTHBRB")
            ]

        active_radios = int(win32_state.get("active_radios") or 0)
        connectable = bool(win32_state.get("connectable"))
        discoverable = bool(win32_state.get("discoverable"))
        connected_count = int(win32_state.get("connected_count") or 0)
        unauth_connected = int(
            win32_state.get("unauthenticated_connected") or 0
        )

        radio_on = active_radios > 0 or connectable or discoverable

        operational_radios = [
            d
            for d in radios
            if str(d.get("Status") or "").strip().upper() == "OK"
        ]
        disabled_radios = [
            d
            for d in radios
            if str(d.get("ProblemCode") or "").strip() == "22"
        ]

        if not radios and not radio_on:
            return "Not Detected"

        if not radio_on:
            if disabled_radios:
                return "Disabled (Hardware disabled)"
            if operational_radios:
                return "Disabled (Radio off)"
            return "Disabled (Adapter unavailable)"

        radio_driver_unsigned = bool(operational_radios) and any(
            d.get("DriverIsSigned") is not True for d in operational_radios
        )

        high_findings = []
        moderate_findings = []

        if discoverable:
            high_findings.append("Discoverable")
        if unauth_connected > 0:
            high_findings.append(
                f"{unauth_connected} unauthenticated connected"
            )

        if radio_driver_unsigned:
            moderate_findings.append("Unsigned/unknown radio driver")
        if extras.get("nearby_sharing_everyone"):
            moderate_findings.append("Nearby Sharing: Everyone")
        if extras.get("pan_active"):
            moderate_findings.append("Bluetooth PAN active")
        if extras.get("file_transfer_active"):
            moderate_findings.append("File transfer active (fsquirt)")

        if high_findings:
            details = high_findings + moderate_findings
            if connected_count > 0 and unauth_connected == 0:
                details.append(f"{connected_count} connected")
            return f"Enabled, Exposure Detected ({'; '.join(details)})"

        if moderate_findings:
            if connected_count > 0:
                moderate_findings.append(f"{connected_count} connected")
            return f"Enabled, Moderate Risk ({'; '.join(moderate_findings)})"

        context = ["Radio on, not discoverable"]
        if connected_count > 0:
            context.append(f"{connected_count} connected")
        if extras.get("policy_hardened"):
            context.append("Policy hardened")
        return f"Enabled, Low Risk ({'; '.join(context)})"

    # --- Windows SMB2 / PKU2U / FTP helpers ---

    @staticmethod
    def _evaluate_smb2_service_verdict(data: dict) -> str:
        if not isinstance(data, dict):
            return "Unknown"

        svc = data.get("Service") if isinstance(data.get("Service"), dict) else {}
        cfg = data.get("Config") if isinstance(data.get("Config"), dict) else {}

        svc_status = str(svc.get("Status") or "").strip().lower()
        svc_start = str(svc.get("StartType") or "").strip().lower()
        if svc_start == "disabled" or svc_status == "stopped":
            return "Disabled"

        enable_smb2 = cfg.get("EnableSMB2Protocol")
        if enable_smb2 is None:
            return "Unknown"
        if not enable_smb2:
            return "Disabled"

        null_shares_raw = cfg.get("NullSessionShares")
        if isinstance(null_shares_raw, str):
            has_null_shares = any(
                s.strip() for s in null_shares_raw.splitlines()
            )
        elif isinstance(null_shares_raw, list):
            has_null_shares = any(
                str(s).strip() for s in null_shares_raw if s is not None
            )
        else:
            has_null_shares = False

        restrict_null_sess = data.get("RestrictNullSessAccess")
        unrestricted_null_sess = (
            restrict_null_sess is not None
            and str(restrict_null_sess).strip().lower() in ("0", "false")
        )
        auth_user_sharing = bool(cfg.get("EnableAuthenticateUserSharing"))
        reject_unencrypted = cfg.get("RejectUnencryptedAccess")
        strict_name = cfg.get("EnableStrictNameChecking")

        if (
            has_null_shares
            or unrestricted_null_sess
            or auth_user_sharing
            or reject_unencrypted is False
            or strict_name is False
        ):
            return "Enabled, Potentially Dangerous (Insecure SMB service settings)"

        if bool(cfg.get("RequireSecuritySignature")) or bool(
            cfg.get("EncryptData")
        ):
            return "Enabled, Low Risk (Signing/Encryption enforced)"

        return "Enabled, Moderate Risk (Signing/Encryption not required)"

    @staticmethod
    def _windows_check_pku2u():
        val = read_registry_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Lsa\pku2u",
            "AllowOnlineID",
        )
        if val is None:
            return "Enabled, Default (Not configured; allows online IDs)"
        try:
            allow = int(val)
            if allow == 0:
                return "Disabled"
            if allow == 1:
                return "Enabled, Moderate Risk (Online identities allowed)"
        except (TypeError, ValueError):
            pass
        return "Unknown"

    @staticmethod
    def _parse_fw_profiles(raw_profiles):
        if isinstance(raw_profiles, (bool, str, int)):
            vals = [raw_profiles]
        elif isinstance(raw_profiles, list):
            vals = raw_profiles
        else:
            return "Unknown", None

        normalized = []
        for v in vals:
            if isinstance(v, bool):
                normalized.append(v)
            elif str(v).strip().lower() in ("true", "1"):
                normalized.append(True)
            elif str(v).strip().lower() in ("false", "0"):
                normalized.append(False)

        if len(normalized) != 3:
            return "Unknown", None
        if all(normalized):
            return "Fully Enabled", True
        if not any(normalized):
            return "Fully Disabled", False
        return "Partially Enabled", False

    @staticmethod
    def _windows_ftp_service():
        service_state = None
        ftp_detected = False
        ftp_port = None
        custom_ftp_port = None
        sftp = False
        tftp_detected = False
        ftp_service_pids = set()
        sshd_running = False
        pid_service_counts = {}

        try:
            if hasattr(psutil, "win_service_iter"):
                for svc in psutil.win_service_iter():
                    try:
                        svc_name = (svc.name() or "").lower()
                        svc_status = (svc.status() or "").lower()
                        svc_pid = svc.pid()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        continue

                    if svc_pid:
                        pid_service_counts[svc_pid] = (
                            pid_service_counts.get(svc_pid, 0) + 1
                        )

                    if "ftpsvc" in svc_name or "filezilla" in svc_name:
                        ftp_detected = True
                        if svc_status == "running":
                            service_state = "Running"
                            if svc_pid:
                                ftp_service_pids.add(svc_pid)
                        elif svc_status == "stopped" and service_state is None:
                            service_state = "Stopped"
                    elif svc_name == "sshd" and svc_status == "running":
                        sshd_running = True
        except Exception:
            pass

        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    if pname == "filezilla server.exe":
                        ftp_detected = True
                        service_state = "Running"
                        if proc.pid:
                            ftp_service_pids.add(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        tcp_conns_ok = False
        try:
            tcp_conns = psutil.net_connections(kind="tcp")
            tcp_conns_ok = True
            for conn in tcp_conns:
                if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                    continue
                port = conn.laddr.port
                if port in (21, 990):
                    if ftp_port is None or port == 21:
                        ftp_port = port
                    ftp_detected = True
                    service_state = "Running"
                elif port == 22 and sshd_running:
                    sftp = True
                elif (
                    conn.pid
                    and conn.pid in ftp_service_pids
                    and pid_service_counts.get(conn.pid, 1) <= 1
                    and 0 < port < 49152
                ):
                    if custom_ftp_port is None or port < custom_ftp_port:
                        custom_ftp_port = port
        except Exception:
            tcp_conns_ok = False

        try:
            tftp_names = {
                "tftpd.exe",
                "tftpserver.exe",
                "tftpsrv.exe",
                "solarwinds tftp server.exe",
            }
            for conn in psutil.net_connections(kind="udp"):
                if not conn.laddr or conn.laddr.port != 69 or not conn.pid:
                    continue
                try:
                    if (
                        psutil.Process(conn.pid).name() or ""
                    ).lower() in tftp_names:
                        tftp_detected = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except Exception:
            pass

        if ftp_detected and ftp_port == 21:
            return "Running, Potentially Exposed (FTP Port 21)"
        if sftp:
            return "Running, Potentially Exposed (SSH/SFTP Port 22)"
        if ftp_detected and ftp_port == 990:
            return "Running, Potentially Exposed (FTPS Port 990)"
        if tftp_detected:
            return "Running, Potentially Exposed (TFTP Port 69)"
        if ftp_detected and custom_ftp_port:
            return f"Running, Potentially Exposed (FTP Port {custom_ftp_port})"
        if ftp_detected and service_state == "Running":
            return (
                "Running, No Active Listener"
                if tcp_conns_ok
                else "Running, Unknown Port"
            )
        if ftp_detected and service_state == "Stopped":
            return "Stopped"
        return "Not Detected"

    def _windows_audit(self):
        ps_data = self._windows_ps_bundle()
        fw_state, fw_all_on = self._parse_fw_profiles(
            ps_data.get("fw_profiles")
        )
        os_build = self._windows_os_build()

        result = {
            "Remote Desktop": "Unknown",
            "Remote Registry": "Unknown",
            "Remote Assistance": "Unknown",
            "PowerShell Remoting": "Unknown",
            "WinRM": "Unknown",
            "SMB1": "Unknown",
            "SMB2": "Unknown",
            "FTP Service": "Unknown",
            "Rsync Service": "Unknown",
            "RPC Print Spooler": "Unknown",
            "PKU2U Authentication": "Unknown",
            "DCOM": "Unknown",
            "NetBIOS": "Unknown",
            "UPnPHost": "Unknown",
            "Bluetooth": "Unknown",
        }

        # 1. Remote Desktop (RDP)
        f_deny = read_registry_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        if f_deny is None:
            result["Remote Desktop"] = "Disabled"
        elif f_deny == 0:
            nla = read_registry_value(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication",
            )
            min_enc = read_registry_value(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "MinEncryptionLevel",
            )
            if nla is not None and min_enc is not None:
                if int(nla) == 1 and int(min_enc) >= 2:
                    result["Remote Desktop"] = (
                        "Enabled, Low Risk (Default settings)"
                    )
                else:
                    result["Remote Desktop"] = (
                        "Enabled, Potentially Exposed (Without NLA or weak encryption)"
                    )
            else:
                result["Remote Desktop"] = (
                    "Enabled, Potentially Exposed (Configuration missing or insecure)"
                )
        else:
            result["Remote Desktop"] = "Disabled"

        # 2. Remote Registry
        rr_qc = self._run_raw(["sc.exe", "qc", "RemoteRegistry"]).lower()
        if "start_type" not in rr_qc:
            result["Remote Registry"] = "Unknown"
        elif "disabled" in rr_qc:
            result["Remote Registry"] = "Disabled"
        elif "auto_start" in rr_qc or "demand_start" in rr_qc:
            rr_q = self._run_raw(["sc.exe", "query", "RemoteRegistry"]).lower()
            if "running" in rr_q:
                svc_running = True
            elif "stopped" in rr_q:
                svc_running = False
            else:
                svc_running = None

            if svc_running is False:
                result["Remote Registry"] = "Enabled, Low Risk (Service stopped)"
            elif svc_running is None:
                result["Remote Registry"] = (
                    "Enabled, Unknown (Service state unavailable)"
                )
            elif fw_all_on is True:
                result["Remote Registry"] = (
                    "Enabled, Moderate Risk (Firewall On)"
                )
            else:
                result["Remote Registry"] = "Enabled, Potentially Dangerous"

        # 3. Remote Assistance
        ra_val = read_registry_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
            "fAllowToGetHelp",
        )
        if ra_val == 1:
            result["Remote Assistance"] = "Enabled, Moderate Risk"
        else:
            result["Remote Assistance"] = "Disabled"

        # 4 & 5. WinRM & PowerShell Remoting
        winrm_svc = self._windows_winrm_service()
        winrm_listeners = self._parse_winrm_listeners(
            ps_data.get("winrm_listeners")
        )
        winrm_ports = self._windows_winrm_ports()
        winrm_auth = self._windows_winrm_auth()
        winrm_enc = self._windows_winrm_encrypted()
        winrm_risk = self._assess_winrm_risk(
            winrm_svc, winrm_listeners, winrm_auth, winrm_enc
        )
        result["WinRM"] = self._winrm_verdict(
            winrm_svc, winrm_listeners, winrm_ports, winrm_risk
        )

        if winrm_svc.get("status") == "Unknown":
            result["PowerShell Remoting"] = "Unknown"
        elif winrm_svc.get("status") != "Enabled" or not winrm_svc.get("running"):
            result["PowerShell Remoting"] = "Disabled"
        elif winrm_listeners.get("http") or winrm_listeners.get("https"):
            result["PowerShell Remoting"] = "Enabled, Potentially Dangerous"
        elif winrm_listeners.get("unknown"):
            allow_shell = None
            for reg_path in (
                r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\WinRS",
            ):
                val = read_registry_value("HKLM", reg_path, "AllowRemoteShellAccess")
                if val is not None:
                    try:
                        allow_shell = int(val)
                        break
                    except (TypeError, ValueError):
                        continue
            if allow_shell == 0:
                result["PowerShell Remoting"] = "Disabled"
            elif winrm_ports:
                result["PowerShell Remoting"] = "Enabled, Potentially Dangerous"
            else:
                result["PowerShell Remoting"] = "Unknown"
        else:
            result["PowerShell Remoting"] = "Disabled"

        # 6. SMB1
        if self._windows_is_admin() and find_powershell():
            smb1_out = run_powershell(
                "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
                "| Select-Object -ExpandProperty State",
                timeout=self.timeout,
                parse_json=False,
            )
            if smb1_out:
                out_l = smb1_out.strip().lower()
                if out_l == "enabled":
                    result["SMB1"] = "Enabled, High Risk"
                elif out_l.startswith("disabled"):
                    result["SMB1"] = "Disabled"
                else:
                    result["SMB1"] = smb1_out.strip()
        if result["SMB1"] == "Unknown":
            srv_smb1 = read_registry_value(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "SMB1",
            )
            mrx_start = read_registry_value(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
                "Start",
            )
            try:
                mrx_enabled = mrx_start is not None and int(mrx_start) in (
                    0,
                    1,
                    2,
                    3,
                )
            except (TypeError, ValueError):
                mrx_enabled = False
            result["SMB1"] = (
                "Enabled, High Risk"
                if (srv_smb1 == 1 or mrx_enabled)
                else "Disabled"
            )

        # 7. SMB2
        result["SMB2"] = self._evaluate_smb2_service_verdict(
            ps_data.get("smb2")
        )

        # 8. FTP Service
        result["FTP Service"] = self._windows_ftp_service()

        # 9. Rsync Service
        rsync_info = ps_data.get("rsync")
        if rsync_info is None:
            result["Rsync Service"] = "Not Detected"
        elif isinstance(rsync_info, dict):
            st = str(rsync_info.get("State") or "")
            sm = str(rsync_info.get("StartMode") or "")
            if st == "Running":
                result["Rsync Service"] = "Running"
            elif sm == "Disabled":
                result["Rsync Service"] = "Disabled"
            elif st == "Stopped":
                result["Rsync Service"] = "Stopped"

        # 10. RPC Print Spooler
        sp_qc = self._run_raw(["sc.exe", "qc", "Spooler"]).upper()
        sp_q = self._run_raw(["sc.exe", "query", "Spooler"]).upper()
        if not sp_qc and not sp_q:
            result["RPC Print Spooler"] = "Unknown"
        elif "DISABLED" in sp_qc or "STOPPED" in sp_q or "1060" in sp_qc:
            result["RPC Print Spooler"] = "Disabled"
        else:
            rem_rpc = read_registry_value(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows NT\Printers",
                "RegisterSpoolerRemoteRpcEndPoint",
            )
            try:
                remote_rpc_disabled = rem_rpc is not None and int(rem_rpc) == 2
            except (TypeError, ValueError):
                remote_rpc_disabled = False

            if remote_rpc_disabled:
                result["RPC Print Spooler"] = "Disabled"
            else:
                rc_val = read_registry_value(
                    "HKLM",
                    r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
                    "RestrictRemoteClients",
                )
                try:
                    restrict_clients = (
                        1 if (rc_val is not None and int(rc_val) >= 1) else 0
                    )
                except (TypeError, ValueError):
                    restrict_clients = 0

                priv_val = read_registry_value(
                    "HKLM",
                    r"SYSTEM\CurrentControlSet\Control\Print",
                    "RpcAuthnLevelPrivacyEnabled",
                )
                if priv_val is not None:
                    try:
                        privacy_enabled = 1 if int(priv_val) == 1 else 0
                    except (TypeError, ValueError):
                        privacy_enabled = 0
                else:
                    privacy_enabled = 1 if os_build >= 19041 else 0

                if restrict_clients == 1 and privacy_enabled == 1:
                    result["RPC Print Spooler"] = (
                        "Enabled, Low Risk (Restricted access)"
                    )
                elif restrict_clients == 1 or privacy_enabled == 1:
                    result["RPC Print Spooler"] = (
                        "Enabled, Moderate Risk (Partially restricted)"
                    )
                else:
                    result["RPC Print Spooler"] = (
                        "Enabled, Potentially Dangerous (Unrestricted network access)"
                    )

        # 11. PKU2U Authentication
        result["PKU2U Authentication"] = self._windows_check_pku2u()

        # 12. DCOM
        enable_dcom = read_registry_value(
            "HKLM", r"SOFTWARE\Microsoft\Ole", "EnableDCOM"
        )
        reg_output = str(enable_dcom).strip().upper() if enable_dcom is not None else ""
        if reg_output == "N":
            result["DCOM"] = "Remote Disabled"
        elif reg_output == "Y":
            legacy_auth = read_registry_value(
                "HKLM", r"SOFTWARE\Microsoft\Ole", "LegacyAuthenticationLevel"
            )
            auth_str = str(legacy_auth).strip() if legacy_auth is not None else ""
            harden_raw = read_registry_value(
                "HKLM",
                r"SOFTWARE\Microsoft\Ole\AppCompat",
                "RequireIntegrityActivationAuthenticationLevel",
            )
            try:
                harden_val = int(harden_raw) if harden_raw is not None else None
            except (TypeError, ValueError):
                harden_val = None

            if harden_val == 1:
                harden_state = "Enabled"
            elif harden_val == 0:
                harden_state = "Disabled"
            else:
                harden_state = "Enabled" if os_build >= 19041 else "Unknown"

            if auth_str in ("5", "6"):
                result["DCOM"] = "Enabled, Low Risk (Secured authentication)"
            elif harden_state == "Enabled":
                result["DCOM"] = "Enabled, Hardened by Patch"
            elif fw_state in ("Fully Enabled", "Partially Enabled"):
                result["DCOM"] = "Enabled, Moderate Risk (Firewall On)"
            elif fw_state == "Fully Disabled":
                result["DCOM"] = (
                    "Enabled, Potentially Dangerous (Firewall Off)"
                )
            else:
                result["DCOM"] = (
                    "Enabled, Moderate Risk (Firewall Status Unknown)"
                )

        # 13. NetBIOS
        ipconfig_out = self._run(["ipconfig.exe", "/all"])
        if ipconfig_out:
            for line in ipconfig_out.splitlines():
                if "NetBIOS over Tcpip" in line:
                    nb_status = line.split(":", 1)[-1].strip()
                    if nb_status.lower() == "enabled":
                        result["NetBIOS"] = "Enabled, Legacy default"
                    elif nb_status.lower() == "disabled":
                        result["NetBIOS"] = "Disabled"
                    else:
                        result["NetBIOS"] = nb_status
                    break

        # 14. UPnPHost
        upnp_info = ps_data.get("upnp")
        if upnp_info is None:
            result["UPnPHost"] = "Not Detected"
        elif isinstance(upnp_info, dict):
            st = str(upnp_info.get("State") or "")
            sm = str(upnp_info.get("StartMode") or "")
            if st == "Running":
                result["UPnPHost"] = "Running, Moderate Risk"
            elif sm == "Disabled":
                result["UPnPHost"] = "Disabled"
            elif st == "Stopped":
                result["UPnPHost"] = "Stopped"

        # 15. Bluetooth
        bt_data = ps_data.get("bluetooth")
        if isinstance(bt_data, dict) and bt_data.get("QuerySucceeded"):
            bt_devs = bt_data.get("Devices") or []
            if isinstance(bt_devs, dict):
                bt_devs = [bt_devs]
            win32_bt = self._query_bluetooth_win32_state()
            extras = self._query_bluetooth_exposure_extras()
            result["Bluetooth"] = self._evaluate_bluetooth_verdict(
                bt_devs, win32_bt, extras
            )

        return result

    # --- Shared POSIX listening-port helper ---

    @staticmethod
    def _listening_ports_and_addrs():
        """Return (tcp_port_to_ips, udp_ports) from psutil."""
        tcp_map: dict[int, set[str]] = {}
        udp_ports: set[int] = set()
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    tcp_map.setdefault(conn.laddr.port, set()).add(
                        (conn.laddr.ip or "").lower()
                    )
        except Exception:
            pass
        try:
            for conn in psutil.net_connections(kind="udp"):
                if conn.laddr:
                    udp_ports.add(conn.laddr.port)
        except Exception:
            pass
        return tcp_map, udp_ports

    @staticmethod
    def _is_loopback_only(ips: set[str]) -> bool:
        return bool(ips) and all(
            ip in ("127.0.0.1", "::1", "127.0.0.53") for ip in ips
        )

    @staticmethod
    def _parse_sshd_config(path="/etc/ssh/sshd_config"):
        settings = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        settings[parts[0].lower()] = parts[1].strip().lower()
        except OSError:
            pass
        return settings

    # --- Linux audit ---

    def _linux_audit(self):
        tcp_map, udp_ports = self._listening_ports_and_addrs()
        proc_names = set()
        try:
            for proc in psutil.process_iter(["name"]):
                n = (proc.info.get("name") or "").lower()
                if n:
                    proc_names.add(n)
        except Exception:
            pass

        result = {
            "SSH Service": "Not Detected",
            "Remote Desktop (XRDP / VNC)": "Not Detected",
            "Telnet Service": "Not Detected",
            "SMB / Samba": "Not Detected",
            "NFS Server": "Not Detected",
            "FTP / TFTP Service": "Not Detected",
            "Rsync Daemon": "Not Detected",
            "Print Service (CUPS)": "Not Detected",
            "Bluetooth": "Unknown",
        }

        # 1. SSH
        if 22 in tcp_map or "sshd" in proc_names:
            cfg = self._parse_sshd_config()
            root_login = cfg.get("permitrootlogin", "")
            pwd_auth = cfg.get("passwordauthentication", "")
            if root_login == "yes":
                result["SSH Service"] = (
                    "Enabled, High Risk (Root login permitted)"
                )
            elif pwd_auth == "no":
                result["SSH Service"] = (
                    "Enabled, Low Risk (Key-based authentication)"
                )
            elif 22 in tcp_map and self._is_loopback_only(tcp_map[22]):
                result["SSH Service"] = "Enabled, Low Risk (Loopback only)"
            else:
                result["SSH Service"] = (
                    "Enabled, Moderate Risk (Listening on port 22)"
                )
        elif shutil.which("systemctl"):
            st = (self._run(["systemctl", "is-active", "ssh"]) or self._run(["systemctl", "is-active", "sshd"]) or "").strip()
            if st in ("inactive", "failed", "dead"):
                result["SSH Service"] = "Disabled"

        # 2. Remote Desktop (XRDP / VNC)
        vnc_ports = [p for p in range(5900, 5910) if p in tcp_map]
        rdp_active = 3389 in tcp_map or "xrdp" in proc_names
        vnc_active = bool(vnc_ports) or bool(
            proc_names & {"x11vnc", "xvnc", "xtigervnc", "vncserver", "wayvnc"}
        )
        if rdp_active and vnc_active:
            result["Remote Desktop (XRDP / VNC)"] = (
                "Enabled, Potentially Exposed (XRDP and VNC active)"
            )
        elif rdp_active:
            result["Remote Desktop (XRDP / VNC)"] = (
                "Enabled, Moderate Risk (XRDP on port 3389)"
            )
        elif vnc_active:
            p_list = ", ".join(str(p) for p in vnc_ports) or "VNC"
            result["Remote Desktop (XRDP / VNC)"] = (
                f"Enabled, Potentially Exposed (VNC: {p_list})"
            )

        # 3. Telnet
        if 23 in tcp_map or "telnetd" in proc_names or "in.telnetd" in proc_names:
            result["Telnet Service"] = (
                "Enabled, High Risk (Unencrypted Telnet on port 23)"
            )

        # 4. SMB / Samba
        if 445 in tcp_map or 139 in tcp_map or "smbd" in proc_names:
            smb_risk = "Enabled, Moderate Risk (Samba active)"
            try:
                with open(
                    "/etc/samba/smb.conf", encoding="utf-8", errors="replace"
                ) as f:
                    smb_txt = f.read().lower()
                if re.search(r"^\s*server\s+min\s+protocol\s*=\s*(nt1|lanman|core)", smb_txt, re.MULTILINE):
                    smb_risk = "Enabled, High Risk (SMB1/NT1 enabled)"
                elif re.search(r"^\s*guest\s+ok\s*=\s*yes", smb_txt, re.MULTILINE):
                    smb_risk = "Enabled, Potentially Dangerous (Guest shares allowed)"
            except OSError:
                pass
            result["SMB / Samba"] = smb_risk

        # 5. NFS Server
        if 2049 in tcp_map or "nfsd" in proc_names:
            nfs_verdict = "Enabled, Moderate Risk (NFS active)"
            try:
                with open("/etc/exports", encoding="utf-8", errors="replace") as f:
                    exports_txt = f.read()
                if "no_root_squash" in exports_txt:
                    nfs_verdict = (
                        "Enabled, High Risk (no_root_squash configured)"
                    )
            except OSError:
                pass
            result["NFS Server"] = nfs_verdict

        # 6. FTP / TFTP
        if 21 in tcp_map:
            result["FTP / TFTP Service"] = (
                "Running, Potentially Exposed (FTP Port 21)"
            )
        elif 990 in tcp_map:
            result["FTP / TFTP Service"] = (
                "Running, Potentially Exposed (FTPS Port 990)"
            )
        elif 69 in udp_ports:
            result["FTP / TFTP Service"] = (
                "Running, Potentially Exposed (TFTP Port 69)"
            )
        elif proc_names & {"vsftpd", "proftpd", "pure-ftpd", "tftpd", "in.tftpd"}:
            result["FTP / TFTP Service"] = "Running"

        # 7. Rsync Daemon
        if 873 in tcp_map:
            result["Rsync Daemon"] = "Running, Moderate Risk (Port 873)"

        # 8. Print Service (CUPS)
        if 631 in tcp_map:
            if self._is_loopback_only(tcp_map[631]):
                result["Print Service (CUPS)"] = (
                    "Enabled, Low Risk (Loopback only)"
                )
            else:
                result["Print Service (CUPS)"] = (
                    "Enabled, Moderate Risk (Network accessible on port 631)"
                )
        elif "cupsd" in proc_names:
            result["Print Service (CUPS)"] = "Enabled, Low Risk (Local socket)"

        # 9. Bluetooth
        if shutil.which("bluetoothctl"):
            bt_out = self._run(["bluetoothctl", "show"])
            if not bt_out:
                result["Bluetooth"] = "Not Detected"
            else:
                powered = bool(
                    re.search(r"Powered:\s*yes", bt_out, re.IGNORECASE)
                )
                discoverable = bool(
                    re.search(r"Discoverable:\s*yes", bt_out, re.IGNORECASE)
                )
                if not powered:
                    result["Bluetooth"] = "Disabled (Radio off)"
                elif discoverable:
                    result["Bluetooth"] = (
                        "Enabled, Exposure Detected (Discoverable)"
                    )
                else:
                    result["Bluetooth"] = (
                        "Enabled, Low Risk (Radio on, not discoverable)"
                    )

        return result

    # --- macOS audit ---

    def _macos_audit(self):
        tcp_map, udp_ports = self._listening_ports_and_addrs()
        proc_names = set()
        try:
            for proc in psutil.process_iter(["name"]):
                n = (proc.info.get("name") or "").lower()
                if n:
                    proc_names.add(n)
        except Exception:
            pass

        result = {
            "SSH (Remote Login)": "Disabled",
            "Screen Sharing (VNC)": "Disabled",
            "Apple Remote Desktop": "Disabled",
            "File Sharing (SMB)": "Disabled",
            "FTP / TFTP Service": "Not Detected",
            "Rsync Daemon": "Not Detected",
            "Print Sharing (CUPS)": "Disabled",
            "Bluetooth": "Unknown",
        }

        # 1. SSH (Remote Login)
        if 22 in tcp_map or "sshd" in proc_names:
            cfg = self._parse_sshd_config()
            if cfg.get("permitrootlogin") == "yes":
                result["SSH (Remote Login)"] = (
                    "Enabled, High Risk (Root login permitted)"
                )
            elif cfg.get("passwordauthentication") == "no":
                result["SSH (Remote Login)"] = (
                    "Enabled, Low Risk (Key-based authentication)"
                )
            else:
                result["SSH (Remote Login)"] = (
                    "Enabled, Moderate Risk (Listening on port 22)"
                )

        # 2. Screen Sharing (VNC)
        if 5900 in tcp_map or "screensharingd" in proc_names:
            result["Screen Sharing (VNC)"] = (
                "Enabled, Moderate Risk (Port 5900)"
            )

        # 3. Apple Remote Desktop
        if "ardagent" in proc_names or 3283 in tcp_map:
            result["Apple Remote Desktop"] = "Enabled, Moderate Risk"

        # 4. File Sharing (SMB)
        if 445 in tcp_map or "smbd" in proc_names:
            result["File Sharing (SMB)"] = "Enabled, Moderate Risk (Port 445)"

        # 5. FTP / TFTP
        if 21 in tcp_map:
            result["FTP / TFTP Service"] = (
                "Running, Potentially Exposed (FTP Port 21)"
            )
        elif 990 in tcp_map:
            result["FTP / TFTP Service"] = (
                "Running, Potentially Exposed (FTPS Port 990)"
            )
        elif 69 in udp_ports:
            result["FTP / TFTP Service"] = (
                "Running, Potentially Exposed (TFTP Port 69)"
            )

        # 6. Rsync
        if 873 in tcp_map:
            result["Rsync Daemon"] = "Running, Moderate Risk (Port 873)"

        # 7. Print Sharing (CUPS)
        if 631 in tcp_map:
            if self._is_loopback_only(tcp_map[631]):
                result["Print Sharing (CUPS)"] = (
                    "Enabled, Low Risk (Loopback only)"
                )
            else:
                result["Print Sharing (CUPS)"] = (
                    "Enabled, Moderate Risk (Network accessible on port 631)"
                )

        # 8. Bluetooth
        bt_out = self._run(["system_profiler", "SPBluetoothDataType", "-json"])
        if bt_out:
            try:
                bt_json = json.loads(bt_out)
                items = bt_json.get("SPBluetoothDataType") or []
                ctrl = (
                    items[0].get("controller_properties", {})
                    if items and isinstance(items[0], dict)
                    else {}
                )
                state = str(ctrl.get("controller_state") or "").lower()
                disc = str(ctrl.get("controller_discoverable") or "").lower()
                if "off" in state:
                    result["Bluetooth"] = "Disabled (Radio off)"
                elif "on" in state:
                    if "on" in disc:
                        result["Bluetooth"] = (
                            "Enabled, Exposure Detected (Discoverable)"
                        )
                    else:
                        result["Bluetooth"] = (
                            "Enabled, Low Risk (Radio on, not discoverable)"
                        )
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass

        return result

    def audit(self):
        """Run the remote access audit and return a structured report."""
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


RemoteAccessSettings = RemoteAccessAudit

if __name__ == "__main__":
    print(json.dumps(
        RemoteAccessAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
