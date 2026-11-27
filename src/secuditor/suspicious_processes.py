# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform behavioral audit for suspicious running processes."""

import glob
import ipaddress
import json
import math
import os
import platform
import plistlib
import re
import shutil
import sys

import psutil

from ._utils import find_powershell, run_command_result, run_powershell

__all__ = ["SuspiciousProcesses", "SuspiciousProcessesAudit", "RISK_THRESHOLD"]

RISK_THRESHOLD = 60


class SuspiciousProcessesAudit:
    """Scan running processes for cross-platform suspicious behavioral indicators."""

    _SUSPICIOUS_REMOTE_PORTS = frozenset({
        23, 69, 79, 113, 512, 513, 514, 515, 540, 543, 544, 548, 623,
        1080, 1099, 1337, 2222, 3128, 4444, 4445, 5555, 5900, 6666, 6667,
        7777, 8888, 9001, 9050, 9051, 9999, 12345, 14444, 27374, 31337, 50050,
    })

    _WINDOWS_CMD_PATTERNS = (
        "-enc", "-encodedcommand", "frombase64string", "invoke-expression",
        "iex", "invoke-command", "add-type", "-executionpolicy bypass",
        "-nop", "-noprofile", "--hidden", "-hidden", "-windowstyle hidden",
        "-w hidden", "-silent", "-noexit", "mshta", "certutil", "bitsadmin",
        "regsvr32", "rundll32", "wmic", "installutil", "cmd /c",
        "powershell -command", "start-process", "downloadfile",
        "downloadstring", "invoke-webrequest", "curl", "wget", "-w 1",
        "iwr", "irm", "-ep bypass", "-exec bypass", "-win hidden",
        "-window hidden", "amsiutils", "comsvcs.dll", "minidump", "procdump",
        "reg save", "reg export", "vssadmin delete", "wbadmin delete",
        "bcdedit /set", "wevtutil cl", "certreq", "pcalua", "odbcconf",
        "forfiles", "scrobj.dll", "invoke-restmethod", "start-bitstransfer",
        "webclient", "net.webclient", "system.net.webclient",
        "set-executionpolicy", "msbuild", "cmstp", "regasm", "regsvcs",
        "cscript", "wscript",
    )

    _POSIX_CMD_PATTERNS = (
        "/dev/tcp/", "/dev/udp/", "base64 -d", "base64 --decode",
        "nc -e", "ncat -e", "bash -i", "sh -i", "mkfifo",
        "chmod +x /tmp", "chmod 777 /tmp", "curl -fs", "wget -q",
        "osascript -e", "python -c", "python3 -c", "perl -e",
    )

    _WINDOWS_SUSPICIOUS_PARENTS = {
        "powershell.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe", "mspub.exe", "visio.exe"),
        "pwsh.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe", "mspub.exe", "visio.exe"),
        "cmd.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe", "mspub.exe", "visio.exe"),
        "rundll32.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
        "regsvr32.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
        "mshta.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
        "wscript.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
        "cscript.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
        "certutil.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
        "bitsadmin.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
        "curl.exe": ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "onenote.exe"),
    }

    _POSIX_SUSPICIOUS_PARENTS = {
        "sh": ("nginx", "apache2", "httpd", "php-fpm", "caddy", "postgres", "mysqld", "mariadbd"),
        "bash": ("nginx", "apache2", "httpd", "php-fpm", "caddy", "postgres", "mysqld", "mariadbd"),
        "dash": ("nginx", "apache2", "httpd", "php-fpm", "caddy", "postgres", "mysqld", "mariadbd"),
        "zsh": ("nginx", "apache2", "httpd", "php-fpm", "caddy"),
        "curl": ("nginx", "apache2", "httpd", "php-fpm", "mysqld"),
        "wget": ("nginx", "apache2", "httpd", "php-fpm", "mysqld"),
        "nc": ("nginx", "apache2", "httpd", "php-fpm", "postgres", "mysqld"),
        "ncat": ("nginx", "apache2", "httpd", "php-fpm", "postgres", "mysqld"),
    }

    _WINDOWS_CORE_PARENT_RULES = {
        "svchost.exe": frozenset({"services.exe"}),
        "services.exe": frozenset({"wininit.exe"}),
        "lsass.exe": frozenset({"wininit.exe"}),
        "lsaiso.exe": frozenset({"wininit.exe"}),
        "spoolsv.exe": frozenset({"services.exe"}),
        "smss.exe": frozenset({"system", "smss.exe"}),
        "taskhostw.exe": frozenset({"svchost.exe"}),
    }

    _WINDOWS_SYSTEM_PREFIXES = (
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Windows\SysArm32",
        r"C:\Windows\SystemApps",
        r"C:\Windows\WinSxS",
        r"C:\Windows\servicing",
        r"C:\Windows\UUS",
        r"C:\Windows\Microsoft.NET",
    )

    _WINDOWS_APP_PREFIXES = (
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\Program Files\WindowsApps",
    )

    _POSIX_SYSTEM_PREFIXES = (
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/libexec",
        "/usr/lib",
        "/lib",
        "/System/Library",
        "/System/Applications",
    )

    _POSIX_APP_PREFIXES = (
        "/Applications",
        "/opt",
        "/usr/local/bin",
        "/snap",
        "/flatpak",
    )

    _WINDOWS_SUSPICIOUS_LOCATIONS = (
        "\\appdata\\roaming\\",
        "\\appdata\\local\\temp\\",
        "\\temp\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\documents\\",
        "\\public\\",
        "\\programdata\\",
        "\\recycler\\",
        "\\$recycle.bin\\",
        "\\perflogs\\",
        "\\appdata\\local\\microsoft\\windows\\inetcache\\",
        "\\appdata\\local\\microsoft\\windows\\iedownloads\\",
        "\\appdata\\local\\packages\\",
        "\\windows\\temp\\",
        "\\windows\\tracing\\",
        "\\windows\\debug\\",
        "\\windows\\fonts\\",
        "\\windows\\help\\",
        "\\windows\\tasks\\",
    )

    _POSIX_SUSPICIOUS_LOCATIONS = (
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/downloads/",
        "/desktop/",
    )

    _WINDOWS_KNOWN_SYSTEM = frozenset({
        "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe",
        "lsass.exe", "lsaiso.exe", "winlogon.exe", "dwm.exe", "conhost.exe",
        "spoolsv.exe", "wmiprvse.exe", "wmiapsrv.exe", "ntoskrnl.exe",
        "mstsc.exe", "explorer.exe", "sihost.exe", "shellexperiencehost.exe",
        "startmenuexperiencehost.exe", "runtimebroker.exe",
        "backgroundtaskhost.exe", "taskhostw.exe", "ctfmon.exe",
        "textinputhost.exe", "fontdrvhost.exe", "dllhost.exe",
        "openconsole.exe", "logonui.exe", "searchhost.exe",
        "searchindexer.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
        "smartscreen.exe", "unsecapp.exe", "wudfhost.exe", "dashost.exe",
        "dfsrs.exe", "dfssvc.exe", "dns.exe", "dnscache.exe", "kdcsvc.exe",
        "netlogon.exe", "ntds.exe", "adws.exe", "dsa.exe", "frs.exe",
        "dfsrdiag.exe", "aggregatorhost.exe", "rdpclip.exe", "tiworker.exe",
        "trustedinstaller.exe", "taskmgr.exe", "shellhost.exe",
        "presentationfontcache.exe", "audiodg.exe",
        "applicationframehost.exe", "useroobebroker.exe", "comppkgsrv.exe",
        "mousocoreworker.exe", "ngciso.exe", "sppsvc.exe", "wlms.exe",
    })

    _POSIX_KNOWN_SYSTEM = frozenset({
        "systemd", "init", "sshd", "cron", "crond", "rsyslogd", "syslogd",
        "dbus-daemon", "udevd", "systemd-udevd", "systemd-journald",
        "systemd-logind", "launchd", "logd", "configd", "mDNSResponder",
    })

    _LEGIT_NETWORK_APPS = frozenset({
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "vivaldi.exe", "teams.exe", "discord.exe", "slack.exe", "zoom.exe",
        "telegram.exe", "whatsapp.exe", "onedrive.exe", "dropbox.exe",
        "googledrivefs.exe", "msedgewebview2.exe", "outlook.exe",
        "thunderbird.exe", "spotify.exe", "steam.exe", "signal.exe",
        "skype.exe", "webex.exe", "ms-teams.exe", "devenv.exe",
        "searchapp.exe", "crossdeviceresume.exe", "crossdeviceservice.exe",
        "microsoftstartfeedprovider.exe", "phoneexperiencehost.exe",
        "widgetservice.exe", "widgetboard.exe", "widgets.exe",
        "wslservice.exe",
        # POSIX equivalents
        "chrome", "chromium", "firefox", "brave", "safari", "slack",
        "discord", "zoom", "telegram-desktop", "spotify", "code",
    })

    _WINDOWS_LOLBINS = frozenset({
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "wmic.exe",
        "schtasks.exe", "reg.exe", "net.exe", "net1.exe", "sc.exe",
        "certutil.exe", "bitsadmin.exe", "curl.exe", "tar.exe", "msbuild.exe",
        "installutil.exe", "forfiles.exe", "at.exe", "regasm.exe",
        "regsvcs.exe", "cmstp.exe", "mavinject.exe", "certreq.exe", "msdt.exe",
        "hh.exe", "ieexec.exe", "pcalua.exe", "ftp.exe", "finger.exe",
        "esentutl.exe", "extrac32.exe", "expand.exe", "makecab.exe",
        "dfsvc.exe", "odbcconf.exe",
    })

    _POSIX_LOLBINS = frozenset({
        "curl", "wget", "nc", "ncat", "netcat", "socat", "osascript",
        "python", "python3", "perl", "ruby", "php", "base64", "openssl",
    })

    _WINDOWS_TYPOSQUAT_TARGETS = (
        "svchost", "lsass", "csrss", "services", "winlogon", "wininit",
        "explorer", "spoolsv", "taskhostw", "runtimebroker", "smartscreen",
    )

    _POSIX_TYPOSQUAT_TARGETS = (
        "systemd", "launchd", "sshd", "crond", "rsyslogd", "syslogd",
    )

    _TYPOSQUAT_EXCLUDE = frozenset({
        "sihost", "dllhost", "conhost", "dashost", "wudfhost",
        "shellhost", "searchhost", "fontdrvhost", "system",
    })

    _DOUBLE_EXT_RE = re.compile(
        r"\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp[34]|zip|rar|7z|iso)"
        r"\.(?:exe|scr|com|pif|bat|cmd|vbs|js|hta|sh|py|command)$",
        re.IGNORECASE,
    )

    _MOTW_ZONE_RE = re.compile(r"(?im)^\s*ZoneId\s*=\s*([34])\b")
    _STARTUP_EXEC_EXTS = frozenset({
        ".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".com", ".pif", ".hta",
    })
    _WINLOGON_DEFAULTS = frozenset({"explorer.exe", "explorer", "userinit.exe", "userinit"})
    _SPECIAL_SYSTEM_PIDS = frozenset({0, 4})

    def __init__(self, threshold=RISK_THRESHOLD, timeout=8.0, max_candidates=30):
        self.system = platform.system()
        self.threshold = threshold
        self.timeout = timeout
        self.max_candidates = max_candidates

    # --- Static utility helpers ---

    @staticmethod
    def _risk_tier(risk: int) -> str:
        if risk >= 90:
            return "High"
        if risk >= 60:
            return "Medium"
        if risk >= 30:
            return "Low"
        return "Very Low"

    @staticmethod
    def _strip_extension(name: str) -> str:
        if not name:
            return ""
        parts = name.split(".")
        return name.lower() if len(parts) == 1 else ".".join(parts[:-1]).lower()

    @staticmethod
    def is_private_ip(ip: str | None) -> bool:
        try:
            addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return True

    @staticmethod
    def _compile_cmd_patterns(patterns):
        compiled = []
        for pat in patterns:
            token = re.escape(pat.lower())
            if pat.startswith("-"):
                regex = re.compile(rf"(?:^|[\s\"'(/]){token}(?=$|[\s\"'=:;)\]])")
            else:
                regex = re.compile(rf"(?:^|[\s\"'\\/(\[.]){token}(?=$|[\s\"'();.,:\]])")
            compiled.append((pat, regex))
        return compiled

    @staticmethod
    def _extract_exec_name(cmd_str: str) -> str:
        if not isinstance(cmd_str, str):
            return ""
        s = cmd_str.strip()
        if not s:
            return ""
        m = re.match(
            r'^(?:"([^"]+)"|\'([^\']+)\'|(.+?\.exe)(?=\s|$)|(\S+))',
            s,
            re.IGNORECASE,
        )
        if not m:
            return ""
        token = next((g for g in m.groups() if g), "").strip()
        return os.path.basename(token).lower() if token else ""

    @staticmethod
    def _levenshtein_distance(a: str, b: str) -> int:
        if a == b:
            return 0
        if abs(len(a) - len(b)) > 2:
            return 3
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i] + [0] * len(b)
            row_min = i
            for j, cb in enumerate(b, 1):
                cost = 0 if ca == cb else 1
                val = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
                curr[j] = val
                if val < row_min:
                    row_min = val
            if row_min > 2:
                return 3
            prev = curr
        return prev[-1]

    def _find_typosquat_target(self, stem: str) -> str | None:
        if not stem or stem in self._TYPOSQUAT_EXCLUDE:
            return None
        targets = (
            self._WINDOWS_TYPOSQUAT_TARGETS
            if self.system == "Windows"
            else self._POSIX_TYPOSQUAT_TARGETS
        )
        suffix = ".exe" if self.system == "Windows" else ""
        for target in targets:
            max_dist = 1 if len(target) <= 6 else 2
            dist = self._levenshtein_distance(stem, target)
            if 1 <= dist <= max_dist:
                return f"{target}{suffix}"
        return None

    def _resolve_prefixes(self, prefixes):
        if self.system != "Windows":
            return [p.replace("\\", "/").rstrip("/") for p in prefixes]

        sysroot = os.environ.get("SystemRoot") or r"C:\Windows"
        pf = os.environ.get("ProgramFiles") or r"C:\Program Files"
        pf86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
        resolved = []
        for p in prefixes:
            pl = p.lower()
            if pl.startswith("c:\\windows"):
                p = sysroot + p[len("C:\\Windows"):]
            elif pl.startswith("c:\\program files (x86)"):
                p = pf86 + p[len("C:\\Program Files (x86)"):]
            elif pl.startswith("c:\\program files"):
                p = pf + p[len("C:\\Program Files"):]
            resolved.append(os.path.normcase(os.path.abspath(p)))
        return resolved

    def _path_matches_prefixes(self, normalized_path: str | None, prefixes) -> bool:
        if not normalized_path:
            return False
        if self.system != "Windows":
            p_norm = normalized_path.replace("\\", "/").rstrip("/")
            return any(
                p_norm == pref or p_norm.startswith(pref + "/")
                for pref in prefixes
            )
        for pref in prefixes:
            if normalized_path == pref:
                return True
            try:
                if os.path.commonpath([normalized_path, pref]) == pref:
                    return True
            except ValueError:
                continue
        return False

    # --- Persistence preloaders (zero pywin32) ---

    def _preload_windows_persistence(self):
        run_execs = set()
        runonce_execs = set()
        winlogon_execs = set()
        startup_execs = set()
        ifeo_execs = set()

        try:
            import winreg
        except ImportError:
            return run_execs, runonce_execs, winlogon_execs, startup_execs, ifeo_execs

        wow64 = getattr(winreg, "KEY_WOW64_64KEY", 0)
        wow32 = getattr(winreg, "KEY_WOW64_32KEY", 0)

        def _enum_reg_values(hive, subkey, access, dest):
            try:
                with winreg.OpenKey(hive, subkey, 0, access) as key:
                    idx = 0
                    while True:
                        try:
                            _, val, _ = winreg.EnumValue(key, idx)
                            idx += 1
                            if isinstance(val, str):
                                exe = self._extract_exec_name(val)
                                if exe:
                                    dest.add(exe)
                        except OSError:
                            break
            except OSError:
                pass

        for subkey, dest in (
            (r"Software\Microsoft\Windows\CurrentVersion\Run", run_execs),
            (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", runonce_execs),
        ):
            _enum_reg_values(winreg.HKEY_CURRENT_USER, subkey, winreg.KEY_READ, dest)
            _enum_reg_values(winreg.HKEY_LOCAL_MACHINE, subkey, winreg.KEY_READ | wow64, dest)
            _enum_reg_values(winreg.HKEY_LOCAL_MACHINE, subkey, winreg.KEY_READ | wow32, dest)

        # Winlogon Shell / Userinit
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                0,
                winreg.KEY_READ | wow64,
            ) as key:
                for vname in ("Shell", "Userinit"):
                    try:
                        val, _ = winreg.QueryValueEx(key, vname)
                        if isinstance(val, str):
                            for part in val.split(","):
                                exe = self._extract_exec_name(part)
                                if exe and exe not in self._WINLOGON_DEFAULTS:
                                    winlogon_execs.add(exe)
                    except OSError:
                        continue
        except OSError:
            pass

        # IFEO Debugger
        ifeo_root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        for access in (winreg.KEY_READ | wow64, winreg.KEY_READ | wow32):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_root, 0, access) as root:
                    idx = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(root, idx)
                            idx += 1
                        except OSError:
                            break
                        if sub.lower() == "yourimagefilenameherewithoutanyextension":
                            continue
                        try:
                            with winreg.OpenKey(root, sub, 0, access) as sk:
                                val, _ = winreg.QueryValueEx(sk, "Debugger")
                                if isinstance(val, str) and val.strip():
                                    exe = self._extract_exec_name(val)
                                    if exe:
                                        ifeo_execs.add(exe)
                        except OSError:
                            continue
            except OSError:
                continue

        # Startup folder direct executables (no COM .lnk parsing)
        for env_var, rel in (
            ("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
            ("ProgramData", r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        ):
            base = os.environ.get(env_var)
            if not base:
                continue
            sdir = os.path.join(base, rel)
            if not os.path.isdir(sdir):
                continue
            try:
                for entry in os.listdir(sdir):
                    full = os.path.join(sdir, entry)
                    if os.path.isfile(full) and os.path.splitext(entry)[1].lower() in self._STARTUP_EXEC_EXTS:
                        startup_execs.add(entry.lower())
            except OSError:
                continue

        return run_execs, runonce_execs, winlogon_execs, startup_execs, ifeo_execs

    def _preload_posix_persistence(self):
        """Read-only persistence discovery for Linux (cron/autostart/systemd) and macOS (LaunchAgents)."""
        persisted = set()
        home = os.path.expanduser("~")

        if self.system == "Linux":
            # /etc/crontab and /etc/cron.d/*
            cron_files = ["/etc/crontab"] + glob.glob("/etc/cron.d/*")
            for cpath in cron_files:
                try:
                    with open(cpath, encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.split("#", 1)[0].strip()
                            parts = line.split()
                            if len(parts) >= 7:
                                exe = self._extract_exec_name(" ".join(parts[6:]))
                                if exe:
                                    persisted.add(exe)
                except OSError:
                    continue

            # Desktop autostart & user systemd services
            if home and home != "~":
                for pattern, key_prefix in (
                    (os.path.join(home, ".config/autostart/*.desktop"), "exec="),
                    (os.path.join(home, ".config/systemd/user/*.service"), "execstart="),
                ):
                    for fpath in glob.glob(pattern):
                        try:
                            with open(fpath, encoding="utf-8", errors="replace") as f:
                                for line in f:
                                    if line.strip().lower().startswith(key_prefix):
                                        exe = self._extract_exec_name(line.split("=", 1)[1])
                                        if exe:
                                            persisted.add(exe)
                        except OSError:
                            continue

        elif self.system == "Darwin":
            plist_dirs = [
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
            ]
            if home and home != "~":
                plist_dirs.append(os.path.join(home, "Library/LaunchAgents"))

            for pdir in plist_dirs:
                if not os.path.isdir(pdir):
                    continue
                for fpath in glob.glob(os.path.join(pdir, "*.plist")):
                    try:
                        with open(fpath, "rb") as f:
                            data = plistlib.load(f)
                        if not isinstance(data, dict):
                            continue
                        prog = data.get("Program")
                        if isinstance(prog, str):
                            exe = self._extract_exec_name(prog)
                            if exe:
                                persisted.add(exe)
                        args = data.get("ProgramArguments")
                        if isinstance(args, list) and args and isinstance(args[0], str):
                            exe = self._extract_exec_name(args[0])
                            if exe:
                                persisted.add(exe)
                    except Exception:
                        continue

        return persisted

    # --- OS-specific file / token / signature helpers ---

    @staticmethod
    def _windows_file_attrs_and_drive(path: str, drive_cache: dict):
        """Return (is_hidden_or_system, is_removable, drive_letter, is_cloud_placeholder)."""
        hidden_or_sys = False
        is_removable = False
        drive_letter = ""
        is_cloud = False

        try:
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.windll.kernel32
            GetFileAttributesW = k32.GetFileAttributesW
            GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
            GetFileAttributesW.restype = wintypes.DWORD

            attrs = int(GetFileAttributesW(path))
            if attrs != 0xFFFFFFFF:
                hidden_or_sys = bool(attrs & (0x2 | 0x4))
                is_cloud = bool(attrs & (0x1000 | 0x00040000 | 0x00400000))

            drive, _ = os.path.splitdrive(path)
            if len(drive) == 2 and drive[1] == ":":
                drive_letter = drive.upper()
                if drive_letter not in drive_cache:
                    GetDriveTypeW = k32.GetDriveTypeW
                    GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
                    GetDriveTypeW.restype = wintypes.UINT
                    drive_cache[drive_letter] = int(GetDriveTypeW(drive_letter + "\\")) == 2
                is_removable = drive_cache[drive_letter]
        except (ImportError, AttributeError, OSError):
            pass

        return hidden_or_sys, is_removable, drive_letter, is_cloud

    @staticmethod
    def _windows_motw_zone(path: str) -> str | None:
        try:
            with open(f"{path}:Zone.Identifier", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)
            m = SuspiciousProcessesAudit._MOTW_ZONE_RE.search(content)
            return m.group(1) if m else None
        except OSError:
            return None

    @staticmethod
    def _macos_has_quarantine(path: str) -> bool:
        getxattr = getattr(os, "getxattr", None)
        if not callable(getxattr):
            return False
        try:
            val = getxattr(path, "com.apple.quarantine")
            return bool(val)
        except OSError:
            return False

    def _is_process_elevated(self, proc) -> bool | None:
        if self.system == "Windows":
            try:
                import ctypes
                from ctypes import wintypes

                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                TOKEN_QUERY = 0x0008
                TokenElevation = 20

                class TOKEN_ELEVATION(ctypes.Structure):
                    _fields_ = [("TokenIsElevated", wintypes.DWORD)]

                k32 = ctypes.windll.kernel32
                adv = ctypes.windll.advapi32

                OpenProcess = k32.OpenProcess
                OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                OpenProcess.restype = wintypes.HANDLE

                CloseHandle = k32.CloseHandle
                CloseHandle.argtypes = [wintypes.HANDLE]
                CloseHandle.restype = wintypes.BOOL

                OpenProcessToken = adv.OpenProcessToken
                OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
                OpenProcessToken.restype = wintypes.BOOL

                GetTokenInformation = adv.GetTokenInformation
                GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
                GetTokenInformation.restype = wintypes.BOOL

                hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, proc.pid)
                if not hproc:
                    return None
                try:
                    htok = wintypes.HANDLE()
                    if not OpenProcessToken(hproc, TOKEN_QUERY, ctypes.byref(htok)):
                        return None
                    try:
                        elev = TOKEN_ELEVATION()
                        ret_len = wintypes.DWORD(0)
                        if GetTokenInformation(
                            htok, TokenElevation, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret_len)
                        ):
                            return bool(elev.TokenIsElevated)
                    finally:
                        CloseHandle(htok)
                finally:
                    CloseHandle(hproc)
            except (ImportError, AttributeError, OSError):
                return None
            return None

        try:
            uids = proc.uids()
            return uids.effective == 0 if uids else None
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError):
            return None

    def _batch_verify_signatures(self, paths: list[str]) -> dict[str, tuple[str, str]]:
        """Verify signatures for candidate binaries in one batched call on Windows/macOS."""
        unique_paths = list(dict.fromkeys(p for p in paths if p))[: self.max_candidates]
        results: dict[str, tuple[str, str]] = {}
        if not unique_paths:
            return results

        if self.system == "Windows":
            if not find_powershell():
                return results
            script = (
                "$paths = $env:SECUDITOR_SIG_PATHS | ConvertFrom-Json; "
                "$out = @{}; "
                "foreach ($p in @($paths)) { "
                "  try { "
                "    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; "
                "    $signer = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }; "
                "    $out[$p] = @{ Status = [string]$s.Status; Signer = $signer } "
                "  } catch { "
                "    $out[$p] = @{ Status = 'Unknown'; Signer = '' } "
                "  } "
                "}; "
                "$out | ConvertTo-Json -Depth 3 -Compress"
            )
            data = run_powershell(
                script,
                timeout=max(self.timeout, 12.0),
                parse_json=True,
                extra_env={"SECUDITOR_SIG_PATHS": json.dumps(unique_paths)},
            )
            if isinstance(data, dict):
                for p, info in data.items():
                    if isinstance(info, dict):
                        results[os.path.normcase(p)] = (
                            str(info.get("Status") or "Unknown"),
                            str(info.get("Signer") or ""),
                        )
            return results

        if self.system == "Darwin" and shutil.which("codesign"):
            for p in unique_paths:
                res = run_command_result(["codesign", "--verify", "--strict", p], timeout=3.0)
                if res is None:
                    results[p] = ("Unknown", "")
                elif res[0] == 0:
                    results[p] = ("Valid", "")
                else:
                    results[p] = ("NotSigned", "")
            return results

        return results

    @staticmethod
    def _file_entropy(path: str) -> float | None:
        try:
            with open(path, "rb") as f:
                data = f.read(1024 * 1024)
            if not data:
                return None
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            length = len(data)
            entropy = 0.0
            for count in freq:
                if count:
                    prob = count / length
                    entropy -= prob * math.log2(prob)
            return entropy
        except OSError:
            return None

    def _module_anomalies(self, proc, suspicious_locations) -> list[str]:
        flagged = []
        try:
            for mmap in proc.memory_maps():
                mpath = getattr(mmap, "path", "") or ""
                if not mpath:
                    continue
                low = os.path.normcase(mpath).lower()
                if not low.endswith((".dll", ".so", ".dylib")):
                    continue
                if any(loc in low for loc in suspicious_locations):
                    name = os.path.basename(mpath)
                    if name not in flagged:
                        flagged.append(name)
                    if len(flagged) >= 3:
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError):
            pass
        return flagged

    # --- Main two-pass scanner ---

    def check_suspicious_processes(self):
        """Scan running processes using a fast two-pass cross-platform pipeline."""
        self_pid = os.getpid()
        limitations = []

        is_win = self.system == "Windows"
        cmd_patterns = self._compile_cmd_patterns(
            self._WINDOWS_CMD_PATTERNS if is_win else self._POSIX_CMD_PATTERNS
        )
        suspicious_parents = (
            self._WINDOWS_SUSPICIOUS_PARENTS if is_win else self._POSIX_SUSPICIOUS_PARENTS
        )
        system_prefixes = self._resolve_prefixes(
            self._WINDOWS_SYSTEM_PREFIXES if is_win else self._POSIX_SYSTEM_PREFIXES
        )
        app_prefixes = self._resolve_prefixes(
            self._WINDOWS_APP_PREFIXES if is_win else self._POSIX_APP_PREFIXES
        )
        suspicious_locations = (
            self._WINDOWS_SUSPICIOUS_LOCATIONS if is_win else self._POSIX_SUSPICIOUS_LOCATIONS
        )
        known_system = (
            self._WINDOWS_KNOWN_SYSTEM if is_win else self._POSIX_KNOWN_SYSTEM
        )
        lolbins = self._WINDOWS_LOLBINS if is_win else self._POSIX_LOLBINS

        # Network connections snapshot (single call)
        conns_by_pid: dict[int, list] = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid is not None:
                    conns_by_pid.setdefault(c.pid, []).append(c)
        except (psutil.AccessDenied, PermissionError, OSError):
            limitations.append(
                "Network connection attribution was partially unavailable; "
                "elevated privileges may be required."
            )

        # Persistence preloading
        if is_win:
            run_execs, runonce_execs, winlogon_execs, startup_execs, ifeo_execs = (
                self._preload_windows_persistence()
            )
            posix_persisted = set()
        else:
            run_execs = runonce_execs = winlogon_execs = startup_execs = ifeo_execs = set()
            posix_persisted = self._preload_posix_persistence()

        drive_cache: dict[str, bool] = {}
        total_scanned = 0
        access_denied_count = 0
        candidates = []

        # --- Pass 1: Fast in-memory heuristics across all processes ---
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = proc.pid
                if pid == self_pid:
                    continue

                pname = (proc.info.get("name") or "").lower()
                if not pname:
                    continue
                pname_stem = self._strip_extension(pname)
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()

                path = None
                deleted_binary = False
                try:
                    raw_exe = proc.exe()
                    if raw_exe:
                        if not is_win and raw_exe.endswith(" (deleted)"):
                            deleted_binary = True
                            path = raw_exe[: -len(" (deleted)")]
                        else:
                            path = raw_exe
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    access_denied_count += 1

                total_scanned += 1
                norm_path = (
                    (os.path.normcase(os.path.abspath(path)) if is_win else path.replace("\\", "/"))
                    if path
                    else None
                )
                is_system_path = self._path_matches_prefixes(norm_path, system_prefixes)
                is_app_path = self._path_matches_prefixes(norm_path, app_prefixes)

                risk = 0
                reasons: list[str] = []
                p_conns = conns_by_pid.get(pid, [])

                # 1. System process impersonation
                if pname in known_system and path and not is_system_path:
                    risk += 20
                    reasons.append("Fake system process")

                # 2. Suspicious remote port
                for c in p_conns:
                    if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                        if c.raddr.port in self._SUSPICIOUS_REMOTE_PORTS:
                            risk += 20
                            reasons.append(f"Suspicious remote port ({c.raddr.port})")
                            break

                # 3. Suspicious command-line patterns
                matched_cmds = [pat for pat, rx in cmd_patterns if rx.search(cmdline)]
                if matched_cmds:
                    risk += 20
                    reasons.append(f"Suspicious cmdline ({', '.join(matched_cmds[:3])})")

                # 4. Parent process anomalies
                try:
                    parent = proc.parent()
                    if parent:
                        parent_name = (parent.name() or "").lower()
                        bad_parents = suspicious_parents.get(pname, ())
                        if (
                            parent_name in bad_parents
                            or self._strip_extension(parent_name) in bad_parents
                        ):
                            risk += 20
                            reasons.append(f"Odd parent: {parent_name}")

                        if is_win:
                            expected = self._WINDOWS_CORE_PARENT_RULES.get(pname)
                            if expected and parent_name and parent_name not in expected:
                                try:
                                    if parent.create_time() <= proc.create_time() + 1.0:
                                        risk += 20
                                        reasons.append(f"Unexpected system parent: {parent_name}")
                                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                                    pass
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass

                # 5. Persistence correlation
                if is_win:
                    if pname in run_execs or pname_stem in run_execs:
                        risk += 10
                        reasons.append("Found in registry Run keys")
                    startup_src = []
                    if pname in startup_execs or pname_stem in startup_execs:
                        startup_src.append("Startup")
                    if pname in runonce_execs or pname_stem in runonce_execs:
                        startup_src.append("RunOnce")
                    if pname in winlogon_execs or pname_stem in winlogon_execs:
                        startup_src.append("Winlogon")
                    if startup_src:
                        risk += 10
                        reasons.append(f"Found in startup persistence ({', '.join(startup_src)})")
                    if pname in ifeo_execs or pname_stem in ifeo_execs:
                        risk += 30
                        reasons.append("Found in IFEO Debugger persistence")
                elif posix_persisted and (pname in posix_persisted or pname_stem in posix_persisted):
                    risk += 10
                    reasons.append("Found in startup/scheduled persistence")

                # 6. Deleted / ghost executable on disk
                if deleted_binary:
                    risk += 30
                    reasons.append("Deleted executable on disk")
                elif (
                    path
                    and not is_system_path
                    and "\\windowsapps\\" not in (norm_path or "")
                ):
                    try:
                        os.stat(path)
                    except FileNotFoundError:
                        risk += 30
                        reasons.append("Deleted executable on disk")
                    except OSError:
                        pass

                # 7. Windows NTFS ADS / removable / hidden / MOTW, or macOS quarantine
                is_cloud = False
                if path:
                    if is_win:
                        stripped = path[4:] if path.startswith("\\\\?\\") else path
                        if len(stripped) > 2 and ":" in stripped[2:]:
                            risk += 30
                            reasons.append("Executed from NTFS Alternate Data Stream")
                        if not is_system_path:
                            hid, rem, drv, is_cloud = self._windows_file_attrs_and_drive(
                                path, drive_cache
                            )
                            if rem:
                                risk += 10
                                reasons.append(f"Executed from removable drive ({drv})")
                            if hid:
                                risk += 10
                                reasons.append("Hidden/system executable attribute")
                            zone_id = self._windows_motw_zone(path)
                            if zone_id in ("3", "4"):
                                risk += 20
                                reasons.append(
                                    f"Downloaded executable (Mark-of-the-Web, ZoneId={zone_id})"
                                )
                    elif self.system == "Darwin" and not is_system_path:
                        if self._macos_has_quarantine(path):
                            risk += 20
                            reasons.append("Downloaded executable (macOS quarantine)")

                # 8. Suspicious executable path
                in_suspicious_loc = False
                if path and not is_system_path:
                    path_cmp = (norm_path or path).lower()
                    if any(loc in path_cmp for loc in suspicious_locations):
                        in_suspicious_loc = True
                        risk += 10
                        reasons.append("Executable in suspicious location")

                # 9. Typosquatting / double extension
                if not is_system_path and pname not in known_system:
                    if self._DOUBLE_EXT_RE.search(pname):
                        risk += 30
                        reasons.append("Masqueraded double extension")
                    else:
                        typo = self._find_typosquat_target(pname_stem)
                        if typo:
                            risk += 30
                            reasons.append(f"System process typosquatting (similar to {typo})")

                # 10. Child fan-out
                try:
                    if len(proc.children()) > 3:
                        risk += 10
                        reasons.append("Multiple child processes")
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass

                # 11. Network listener & traffic heuristics
                wildcard_ports = sorted({
                    c.laddr.port
                    for c in p_conns
                    if c.status == psutil.CONN_LISTEN
                    and c.laddr
                    and c.laddr.ip in ("0.0.0.0", "::")
                })
                if wildcard_ports and not is_system_path:
                    risk += 10
                    reasons.append(
                        f"Wildcard network listener ({', '.join(str(p) for p in wildcard_ports[:5])})"
                    )

                listen_ports = {
                    c.laddr.port
                    for c in p_conns
                    if c.status == psutil.CONN_LISTEN and c.laddr
                }
                ext_conns = [
                    c
                    for c in p_conns
                    if c.raddr and not self.is_private_ip(c.raddr.ip)
                ]
                ext_peers = {
                    c.raddr.ip
                    for c in ext_conns
                    if c.status == psutil.CONN_ESTABLISHED
                }
                incoming = any(
                    c.status == psutil.CONN_ESTABLISHED
                    and c.laddr
                    and c.raddr
                    and not self.is_private_ip(c.raddr.ip)
                    and c.laddr.port in listen_ports
                    for c in p_conns
                )
                outgoing = bool(ext_peers)

                is_allowlisted_net = pname in self._LEGIT_NETWORK_APPS and is_app_path
                has_traffic = False
                if not is_system_path and not is_allowlisted_net:
                    if incoming and outgoing:
                        risk += 20
                        reasons.append("Inbound + outbound communications")
                        has_traffic = True
                    elif incoming:
                        risk += 10
                        reasons.append("Inbound traffic detected")
                        has_traffic = True
                    elif outgoing:
                        risk += 10
                        reasons.append("Outbound traffic detected")
                        has_traffic = True

                    if len(listen_ports) > 3:
                        risk += 10
                        reasons.append(f"Multiple listening ports ({len(listen_ports)})")
                    if len(ext_peers) >= 10:
                        risk += 10
                        reasons.append(f"{len(ext_peers)} external peers")
                    if len(ext_conns) > 3:
                        risk += 10
                        reasons.append(f"{len(ext_conns)} active external connections")

                # 12. LOLBin correlation
                if pname in lolbins:
                    if not has_traffic and (incoming or outgoing):
                        if incoming and outgoing:
                            risk += 20
                            reasons.append("Inbound + outbound communications")
                        elif incoming:
                            risk += 10
                            reasons.append("Inbound traffic detected")
                        else:
                            risk += 10
                            reasons.append("Outbound traffic detected")
                        has_traffic = True
                    if matched_cmds or has_traffic:
                        risk += 20
                        reasons.append("Potential LOLBin execution")

                # Keep candidate for Pass 2 if preliminary score can plausibly cross threshold
                if risk >= 20:
                    candidates.append({
                        "proc": proc,
                        "pid": pid,
                        "name": pname,
                        "path": path,
                        "norm_path": norm_path,
                        "is_system_path": is_system_path,
                        "in_suspicious_loc": in_suspicious_loc,
                        "is_cloud": is_cloud,
                        "risk": risk,
                        "reasons": reasons,
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # --- Pass 2: Candidate-only enrichment (batched signing, modules, entropy, elevation) ---
        candidates.sort(key=lambda c: -c["risk"])
        sig_paths = [
            c["path"]
            for c in candidates
            if c["path"] and not (c["name"] in known_system and c["is_system_path"] and not is_win)
        ]
        sig_map = self._batch_verify_signatures(sig_paths)

        flagged = []
        for cand in candidates:
            proc = cand["proc"]
            pid = cand["pid"]
            pname = cand["name"]
            path = cand["path"]
            norm_path = cand["norm_path"]
            is_system_path = cand["is_system_path"]
            risk = cand["risk"]
            reasons = list(cand["reasons"])

            sig_status = "Not Applicable"
            signer = ""
            if path and (is_win or self.system == "Darwin"):
                key = os.path.normcase(path) if is_win else path
                sig_status, signer = sig_map.get(key, ("Unknown", ""))

                if sig_status == "Valid":
                    risk -= 10
                    reasons.append("Valid digital signature")
                elif sig_status in ("NotSigned", "HashMismatch", "NotTrusted"):
                    risk += 20
                    reasons.append("Invalid digital signature")
                elif sig_status == "Unknown":
                    risk += 10
                    reasons.append("Unknown signature status")

            elevated = self._is_process_elevated(proc)
            if elevated is True:
                if not is_win and cand["in_suspicious_loc"]:
                    risk += 20
                    reasons.append("Root process running from suspicious location")
                else:
                    reasons.append("Elevated process")

            # Candidate-only loaded module & entropy checks for non-valid-signed processes
            if sig_status != "Valid":
                mod_anomalies = self._module_anomalies(proc, suspicious_locations)
                if mod_anomalies:
                    risk += 10
                    reasons.append(f"Module anomalies ({', '.join(mod_anomalies)})")

                if path and not is_system_path and not cand["is_cloud"]:
                    ent = self._file_entropy(path)
                    if ent is not None and ent >= 7.5:
                        risk += 10
                        reasons.append(f"High entropy ({ent:.2f})")

            # Native OS system process risk reduction
            if pid in self._SPECIAL_SYSTEM_PIDS:
                risk = max(risk - 20, 0)
                reasons.append("Special system process")
            elif pname in known_system and is_system_path:
                if not is_win or (sig_status == "Valid" and "microsoft" in signer.lower()):
                    risk = max(risk - 20, 0)
                    reasons.append("Verified system process")

            risk = max(risk, 0)
            if risk >= self.threshold:
                flagged.append({
                    "name": pname,
                    "pid": pid,
                    "risk": risk,
                    "risk_tier": self._risk_tier(risk),
                    "path": path or "Unknown",
                    "elevated": elevated,
                    "signature": sig_status,
                    "reasons": reasons,
                })

        # Deduplicate by process name keeping highest risk
        unique: dict[str, dict] = {}
        for item in flagged:
            key = item["name"]
            if key not in unique or item["risk"] > unique[key]["risk"]:
                unique[key] = item

        ordered = sorted(unique.values(), key=lambda x: (-x["risk"], x["name"]))

        if access_denied_count > 0:
            limitations.append(
                f"Executable path could not be read for {access_denied_count} "
                "protected or other-user processes without elevated privileges."
            )

        tier_counts = {"High": 0, "Medium": 0, "Low": 0, "Very Low": 0}
        for item in ordered:
            tier_counts[item["risk_tier"]] = tier_counts.get(item["risk_tier"], 0) + 1

        return {
            "platform": self.system,
            "hostname": platform.node(),
            "threshold": self.threshold,
            "summary": {
                "scanned_processes": total_scanned,
                "flagged_count": len(ordered),
                "high": tier_counts["High"],
                "medium": tier_counts["Medium"],
                "low": tier_counts["Low"],
                "very_low": tier_counts["Very Low"],
            },
            "findings": ordered,
            "limitations": limitations,
        }

    @classmethod
    def format_report(cls, report: dict) -> str:
        """Format suspicious process findings as Option 3 compact tree cards."""
        findings = report.get("findings") if isinstance(report, dict) else []
        if not findings:
            return "No suspicious activity detected"

        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        try:
            "–├─└─•".encode(encoding)
            sep_ch, branch_mid, branch_end, bullet = "–", "├─", "└─", "•"
        except (UnicodeEncodeError, LookupError):
            sep_ch, branch_mid, branch_end, bullet = "-", "|-", "\\-", "*"

        tier_order = ("High", "Medium", "Low", "Very Low")
        tier_counts = {t: 0 for t in tier_order}
        for item in findings:
            t = item.get("risk_tier") or cls._risk_tier(int(item.get("risk") or 0))
            tier_counts[t] = tier_counts.get(t, 0) + 1

        summary_parts = [f"{t}: {tier_counts[t]}" for t in tier_order if tier_counts[t] > 0]
        header = f"Suspicious Processes Detected: {len(findings)}"
        if summary_parts:
            header += f"  ({' | '.join(summary_parts)})"

        sep = sep_ch * 50
        lines = [header, sep]

        for idx, item in enumerate(findings):
            tier = item.get("risk_tier") or cls._risk_tier(int(item.get("risk") or 0))
            risk = item.get("risk", 0)
            name = item.get("name", "unknown")
            pid = item.get("pid", "N/A")
            path = item.get("path") or "Unknown"
            reasons = item.get("reasons") or []

            lines.append(f"[ {tier} | Risk {risk} ] {name} (PID: {pid})")
            lines.append(f"  {branch_mid} Path: {path}")
            lines.append(f"  {branch_end} Findings:")
            if reasons:
                for reason in reasons:
                    lines.append(f"       {bullet} {reason}")
            else:
                lines.append(f"       {bullet} None")

            if idx != len(findings) - 1:
                lines.append(sep)

        return "\n".join(lines)

    def audit(self):
        """Run the suspicious processes audit and return a structured report."""
        return self.check_suspicious_processes()


SuspiciousProcesses = SuspiciousProcessesAudit

if __name__ == "__main__":
    print(json.dumps(
        SuspiciousProcessesAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
