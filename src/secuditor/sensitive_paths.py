# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform sensitive file and permission exposure audit."""

import fnmatch
import glob
import json
import os
import platform
import re
import stat
import time

__all__ = ["SensitivePaths", "SensitivePathsAudit"]


class SensitivePathsAudit:
    """Scan well-known sensitive locations and staging directories for exposed files."""

    _MAX_DISPLAY = 100

    _SKIP_DIRS = {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".cache",
        "site-packages",
    }

    _SKIP_TEMP_DIR_PREFIXES = (
        "pytest-of-",
        "pip-",
        "npm-",
        "yarn-",
        "go-build",
        "jest_",
        "cargo-",
        "_mei",
    )
    _PY_TEMPFILE_DIR_RE = re.compile(r"^tmp[a-z0-9_]{8}$", re.IGNORECASE)
    _TEMP_DIR_MARKERS = (
        "/appdata/local/temp",
        "/windows/temp",
        "/temp",
        "/tmp",
        "/var/tmp",
    )
    _TEMP_NOISY_EXTS = {".db", ".sqlite", ".sqlite3", ".bak", ".dmp"}
    _MAX_LOW_DB_PER_DIR = 5

    _WEBROOT_MARKERS = (
        "/inetpub/wwwroot",
        "/xampp/htdocs",
        "/www",
        "/htdocs",
        "/nginx/html",
        "/var/www",
    )

    _CRED_KEY_NAMES = {
        "id_rsa",
        "id_dsa",
        "id_ed25519",
        "id_ecdsa",
        "authorized_keys",
        "credentials",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "sitemanager.xml",
        "recentservers.xml",
        "sysprep.xml",
        "shadow",
        "sudoers",
    }
    _CRED_KEY_EXTS = {
        ".pem",
        ".key",
        ".ppk",
        ".pfx",
        ".p12",
        ".jks",
        ".keystore",
    }
    _VAULT_EXTS = {".kdbx", ".keychain", ".keychain-db"}
    _RDP_VPN_EXTS = {".rdp", ".ovpn"}
    _CONFIG_NAMES = {
        ".env",
        "web.config",
        "appsettings.json",
        "config.php",
        "config.json",
        "config",
    }
    _DB_BACKUP_EXTS = {
        ".dit",
        ".mdf",
        ".ldf",
        ".ndf",
        ".edb",
        ".ad",
        ".bak",
        ".bkf",
        ".bkp",
        ".dump",
        ".dmp",
        ".sql",
        ".pst",
        ".ost",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".ibd",
        ".myd",
        ".myi",
        ".frm",
        ".mdb",
        ".accdb",
        ".dbf",
    }
    _SYSTEM_HIVE_NAMES = {"ntds.dit", "sam", "security", "system", "software"}
    _WEBROOT_EXTS = {".php", ".js", ".asp", ".aspx", ".config"}

    _KNOWN_BENIGN_FILES = {
        "photothumb.db",
        "thumbs.db",
        "desktop.ini",
        "iconcache.db",
        "ehthumbs.db",
        ".ds_store",
        "cacert.pem",
    }

    _SENSITIVE_PATTERNS = (
        "*.dit",
        "*.ldf",
        "*.mdf",
        "*.ndf",
        "*.edb",
        "*.ad",
        "*.bak",
        "*.bkf",
        "*.bkp",
        "*.dump",
        "*.dmp",
        "*.sql",
        "*.pst",
        "*.ost",
        "*.sqlite",
        "*.sqlite3",
        "*.db",
        "*.ibd",
        "*.myd",
        "*.myi",
        "*.env",
        "*.kdbx",
        "*.frm",
        "*.mdb",
        "*.accdb",
        "*.dbf",
        "*.pem",
        "*.key",
        "*.ppk",
        "*.jks",
        "*.keystore",
        "*.ovpn",
        "*.rdp",
        "*.pfx",
        "*.p12",
        "unattend*.xml",
    )

    _WEBROOT_SENSITIVE_PATTERNS = (
        "*.config",
        "*.php",
        "*.js",
        "*.asp",
        "*.aspx",
    )

    _WINDOWS_TARGET_TEMPLATES = (
        r"{drive}Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\*.mdf",
        r"{drive}Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\*.ldf",
        r"{drive}Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\*.ndf",
        r"{drive}Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA\*.bak",
        r"{drive}ProgramData\MySQL\MySQL Server*\Data\*.ibd",
        r"{drive}ProgramData\MySQL\MySQL Server*\Data\*.err",
        r"{drive}Program Files\MySQL\MySQL Server*\Data\*",
        r"{drive}xampp\mysql\data\*",
        r"{drive}wamp*\bin\mysql\mysql*\data\*",
        r"{drive}Program Files\PostgreSQL\*\data\*",
        r"{drive}ProgramData\PostgreSQL\*\data\*",
        r"{drive}Program Files\MongoDB\Server\*\data\*",
        r"{drive}data\db\*",
        r"{drive}Program Files\Redis\*",
        r"{drive}redis\data\*",
        r"{drive}Users\*\*.sqlite",
        r"{drive}Users\*\*.db",
        r"{sysdrive}Windows\NTDS\NTDS.dit",
        r"{sysdrive}Windows\NTDS\*.log",
        r"{sysdrive}Windows\NTDS\*.edb",
        r"{sysdrive}Windows\SYSVOL",
        r"{sysdrive}Windows\SYSVOL\domain\Policies",
        r"{sysdrive}Windows\Panther\Unattend.xml",
        r"{sysdrive}Windows\Panther\sysprep.xml",
        r"{drive}Users\*\AppData\Roaming\FileZilla\sitemanager.xml",
        r"{drive}Users\*\AppData\Roaming\FileZilla\recentservers.xml",
        r"{drive}inetpub\wwwroot",
        r"{drive}inetpub\logs\LogFiles\*",
        r"{drive}xampp\htdocs\*",
        r"{drive}xampp\apache\logs\*",
        r"{drive}wamp*\www\*",
        r"{drive}Program Files\Apache*\htdocs\*",
        r"{drive}nginx\html\*",
        r"{drive}Users\*\.env",
        r"{drive}Users\*\*.env",
        r"{drive}Users\*\web.config",
        r"{drive}Users\*\appsettings.json",
        r"{drive}Users\*\config.php",
        r"{drive}Users\*\.ssh\id_rsa",
        r"{drive}Users\*\.ssh\id_dsa",
        r"{drive}Users\*\.ssh\authorized_keys",
        r"{drive}Users\*\.ssh\id_ed25519",
        r"{drive}Users\*\.ssh\id_ecdsa",
        r"{drive}Users\*\.aws\config",
        r"{drive}Users\*\.npmrc",
        r"{drive}Users\*\.pypirc",
        r"{drive}Users\*\.netrc",
        r"{drive}Users\*\.aws\credentials",
        r"{drive}Users\*\.azure\*",
        r"{drive}Users\*\.config\gcloud\*",
        r"{drive}Users\*\.git\config",
        r"{drive}Users\*\.git-credentials",
        r"{drive}ProgramData\Docker\*",
        r"{drive}Users\*\.docker\config.json",
        r"{drive}Users\*\.kube\config",
        r"{drive}Users\*\*.pfx",
        r"{drive}Users\*\*.p12",
        r"{drive}Users\*\*.kdbx",
    )

    _WINDOWS_SEARCH_DIRS = (
        r"{sysdrive}Users\Public",
        r"{sysdrive}Users\*\Desktop",
        r"{sysdrive}Users\*\Documents",
        r"{sysdrive}Users\*\Downloads",
        r"{sysdrive}Windows\Temp",
        r"{sysdrive}Users\*\AppData\Local\Temp",
        r"{sysdrive}Temp",
        r"{sysdrive}inetpub\wwwroot",
        r"{sysdrive}xampp\htdocs",
        r"{sysdrive}wamp*\www",
        r"{sysdrive}Program Files\Apache*\htdocs",
        r"{sysdrive}nginx\html",
        r"{sysdrive}inetpub\logs\LogFiles",
        r"{sysdrive}Windows\Logs",
        r"{sysdrive}Windows\System32\LogFiles",
    )

    _POSIX_HOME_TARGETS = (
        ".ssh/id_rsa",
        ".ssh/id_dsa",
        ".ssh/id_ed25519",
        ".ssh/id_ecdsa",
        ".ssh/authorized_keys",
        ".aws/credentials",
        ".aws/config",
        ".azure/*",
        ".config/gcloud/*",
        ".kube/config",
        ".docker/config.json",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".env",
        "*.env",
        "*.pfx",
        "*.p12",
        "*.kdbx",
        "*.sqlite",
        "*.db",
    )

    _LINUX_SYSTEM_TARGETS = (
        "/etc/shadow",
        "/etc/sudoers",
        "/var/www/html/*",
        "/var/lib/mysql/*",
        "/var/lib/postgresql/*/main/*",
    )

    _MACOS_HOME_EXTRA_TARGETS = (
        "Library/Keychains/*.keychain",
        "Library/Keychains/*.keychain-db",
    )

    def __init__(
        self,
        max_depth=3,
        max_files=25000,
        time_budget=5.0,
        max_display=None,
    ):
        self.system = platform.system()
        self.max_depth = max_depth
        self.max_files = max_files
        self.time_budget = time_budget
        self.max_display = (
            self._MAX_DISPLAY if max_display is None else max_display
        )

    @staticmethod
    def _sys_drive():
        return os.environ.get("SystemDrive", "C:").rstrip("\\/") + "\\"

    @staticmethod
    def _get_fixed_drives():
        drives = []
        DRIVE_FIXED = 3
        get_drive_type = None
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes

                k32 = ctypes.windll.kernel32
                get_drive_type = k32.GetDriveTypeW
                get_drive_type.argtypes = [wintypes.LPCWSTR]
                get_drive_type.restype = wintypes.UINT
            except (ImportError, AttributeError, OSError):
                get_drive_type = None

        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if get_drive_type is not None:
                try:
                    if get_drive_type(drive) == DRIVE_FIXED:
                        drives.append(drive)
                except Exception:
                    continue
            elif os.path.exists(drive):
                drives.append(drive)
        return drives

    def build_sensitive_paths(self):
        """Build OS-appropriate list of sensitive target path patterns."""
        paths = []
        seen = set()

        def _add(candidate):
            key = os.path.normcase(candidate)
            if key not in seen:
                seen.add(key)
                paths.append(candidate)

        if self.system == "Windows":
            sys_drive = self._sys_drive()
            fixed_drives = self._get_fixed_drives() or [sys_drive]
            for tpl in self._WINDOWS_TARGET_TEMPLATES:
                if "{drive}" in tpl:
                    for drive in fixed_drives:
                        _add(tpl.format(drive=drive, sysdrive=sys_drive))
                else:
                    _add(tpl.format(drive=sys_drive, sysdrive=sys_drive))
            return paths

        home = os.path.expanduser("~")
        if home and home != "~":
            for rel in self._POSIX_HOME_TARGETS:
                _add(os.path.join(home, rel))
            if self.system == "Darwin":
                for rel in self._MACOS_HOME_EXTRA_TARGETS:
                    _add(os.path.join(home, rel))

        if self.system == "Linux":
            for sys_path in self._LINUX_SYSTEM_TARGETS:
                _add(sys_path)
        elif self.system == "Darwin":
            _add("/etc/sudoers")

        return paths

    def _default_search_dirs(self):
        if self.system == "Windows":
            return list(self._WINDOWS_SEARCH_DIRS)

        home = os.path.expanduser("~")
        dirs = []
        if home and home != "~":
            dirs.extend([
                os.path.join(home, "Desktop"),
                os.path.join(home, "Documents"),
                os.path.join(home, "Downloads"),
            ])
        dirs.extend(["/tmp", "/var/tmp", "/var/www/html", "/var/www"])
        if self.system == "Darwin":
            dirs.extend([
                "/Users/Shared",
                "/usr/local/var/www",
                "/opt/homebrew/var/www",
            ])
        return dirs

    @staticmethod
    def _is_symlink_or_junction(path_or_entry):
        """Return True for symlinks and NTFS mount points/junctions."""
        try:
            if hasattr(path_or_entry, "is_symlink"):
                if path_or_entry.is_symlink():
                    return True
                is_junc = getattr(path_or_entry, "is_junction", None)
                if callable(is_junc) and is_junc():
                    return True
                st = path_or_entry.stat(follow_symlinks=False)
            else:
                if os.path.islink(path_or_entry):
                    return True
                is_junc = getattr(os.path, "isjunction", None)
                if callable(is_junc) and is_junc(path_or_entry):
                    return True
                st = os.lstat(path_or_entry)
            if getattr(st, "st_reparse_tag", 0) in (0xA0000003, 0xA000000C):
                return True
        except OSError:
            return True
        return False

    @staticmethod
    def _is_cloud_placeholder(path):
        """Return True for Windows cloud-only placeholder files (avoids OneDrive hydration)."""
        try:
            st = os.lstat(path)
            attrs = getattr(st, "st_file_attributes", 0)
            # FILE_ATTRIBUTE_OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS
            return bool(attrs & (0x1000 | 0x00040000 | 0x00400000))
        except OSError:
            return False

    # --- Cross-platform ACL / permission inspection ---

    @staticmethod
    def _inspect_windows_acl(path):
        """Inspect a Windows file DACL via advapi32 ctypes (zero pywin32)."""
        try:
            import ctypes
            from ctypes import wintypes

            SE_FILE_OBJECT = 1
            DACL_SECURITY_INFORMATION = 0x00000004
            AclSizeInformation = 2
            ACCESS_ALLOWED_ACE_TYPE = 0
            ACCESS_DENIED_ACE_TYPE = 1
            ACCESS_ALLOWED_OBJECT_ACE_TYPE = 5
            ACCESS_DENIED_OBJECT_ACE_TYPE = 6
            INHERIT_ONLY_ACE = 0x08

            class ACL_SIZE_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("AceCount", wintypes.DWORD),
                    ("AclBytesInUse", wintypes.DWORD),
                    ("AclBytesFree", wintypes.DWORD),
                ]

            class ACE_HEADER(ctypes.Structure):
                _fields_ = [
                    ("AceType", ctypes.c_ubyte),
                    ("AceFlags", ctypes.c_ubyte),
                    ("AceSize", wintypes.WORD),
                ]

            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            LocalFree = kernel32.LocalFree
            LocalFree.argtypes = [ctypes.c_void_p]
            LocalFree.restype = ctypes.c_void_p

            GetNamedSecurityInfoW = advapi32.GetNamedSecurityInfoW
            GetNamedSecurityInfoW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
            ]
            GetNamedSecurityInfoW.restype = wintypes.DWORD

            GetAclInformation = advapi32.GetAclInformation
            GetAclInformation.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            GetAclInformation.restype = wintypes.BOOL

            GetAce = advapi32.GetAce
            GetAce.argtypes = [
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            GetAce.restype = wintypes.BOOL

            ConvertSidToStringSidW = advapi32.ConvertSidToStringSidW
            ConvertSidToStringSidW.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            ConvertSidToStringSidW.restype = wintypes.BOOL

            dacl_ptr = ctypes.c_void_p()
            sd_ptr = ctypes.c_void_p()
            err = GetNamedSecurityInfoW(
                path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                ctypes.byref(dacl_ptr),
                None,
                ctypes.byref(sd_ptr),
            )
            if err != 0:
                if err == 5:
                    return "private", "Protected"
                return "private", "Private"

            try:
                if not dacl_ptr.value:
                    return "exposed", "Exposed: NULL DACL"

                acl_info = ACL_SIZE_INFORMATION()
                if not GetAclInformation(
                    dacl_ptr,
                    ctypes.byref(acl_info),
                    ctypes.sizeof(acl_info),
                    AclSizeInformation,
                ):
                    return "private", "Private"

                allow_types = {
                    ACCESS_ALLOWED_ACE_TYPE,
                    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                }
                deny_types = {
                    ACCESS_DENIED_ACE_TYPE,
                    ACCESS_DENIED_OBJECT_ACE_TYPE,
                }
                object_types = {
                    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                    ACCESS_DENIED_OBJECT_ACE_TYPE,
                }

                denied_sids = set()
                exposed_label = None
                shared_label = None

                for idx in range(acl_info.AceCount):
                    ace_ptr = ctypes.c_void_p()
                    if (
                        not GetAce(dacl_ptr, idx, ctypes.byref(ace_ptr))
                        or not ace_ptr.value
                    ):
                        continue

                    header = ctypes.cast(
                        ace_ptr, ctypes.POINTER(ACE_HEADER)
                    ).contents
                    ace_type = header.AceType
                    if header.AceFlags & INHERIT_ONLY_ACE:
                        continue
                    if ace_type not in allow_types and ace_type not in deny_types:
                        continue

                    if ace_type in object_types:
                        obj_flags = ctypes.cast(
                            ctypes.c_void_p(ace_ptr.value + 8),
                            ctypes.POINTER(wintypes.DWORD),
                        ).contents.value
                        sid_offset = 12
                        if obj_flags & 0x1:
                            sid_offset += 16
                        if obj_flags & 0x2:
                            sid_offset += 16
                    else:
                        sid_offset = 8

                    if sid_offset >= header.AceSize:
                        continue

                    sid_str_ptr = ctypes.c_void_p()
                    sid_str = None
                    try:
                        if (
                            ConvertSidToStringSidW(
                                ctypes.c_void_p(ace_ptr.value + sid_offset),
                                ctypes.byref(sid_str_ptr),
                            )
                            and sid_str_ptr.value
                        ):
                            sid_str = ctypes.wstring_at(sid_str_ptr.value)
                    finally:
                        if sid_str_ptr.value:
                            LocalFree(sid_str_ptr)

                    if not sid_str:
                        continue

                    if ace_type in deny_types:
                        denied_sids.add(sid_str)
                        continue
                    if sid_str in denied_sids:
                        continue

                    if sid_str == "S-1-1-0":
                        exposed_label = "Exposed: Everyone"
                    elif sid_str == "S-1-5-7" and exposed_label is None:
                        exposed_label = "Exposed: Anonymous"
                    elif sid_str == "S-1-5-32-545" and shared_label is None:
                        shared_label = "Shared: Users"
                    elif sid_str == "S-1-5-11" and shared_label is None:
                        shared_label = "Shared: AuthUsers"

                if exposed_label:
                    return "exposed", exposed_label
                if shared_label:
                    return "shared", shared_label
                return "private", "Private"
            finally:
                if sd_ptr.value:
                    LocalFree(sd_ptr)
        except Exception:
            return "private", "Private"

    @staticmethod
    def _inspect_posix_permissions(path):
        """Inspect POSIX mode bits on Linux/macOS."""
        try:
            mode = stat.S_IMODE(os.lstat(path).st_mode)
            oct_str = oct(mode)
            if mode & stat.S_IWOTH:
                return "exposed", f"Exposed: World-writable ({oct_str})"
            if mode & stat.S_IROTH:
                return "exposed", f"Exposed: World-readable ({oct_str})"
            if mode & (stat.S_IRGRP | stat.S_IWGRP):
                return "shared", f"Shared: Group-accessible ({oct_str})"
            return "private", f"Private ({oct_str})"
        except PermissionError:
            return "private", "Protected"
        except OSError:
            return "private", "Private"

    def inspect_acl(self, path):
        """Return (level, label) for a file across Windows, Linux, and macOS."""
        if self.system == "Windows":
            return self._inspect_windows_acl(path)
        return self._inspect_posix_permissions(path)

    def _inspect_rdp_file(self, path):
        """Read-only inspection of .rdp metadata (capped at 64 KB, skips cloud placeholders)."""
        info = {"skip": False, "has_password": False, "note": ""}
        base_l = os.path.basename(path).lower()
        if self.system == "Windows" and self._is_cloud_placeholder(path):
            return info
        try:
            with open(path, "rb") as fp:
                raw = fp.read(65536)
            if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                text = raw.decode("utf-16", errors="ignore")
            else:
                text = raw.decode("utf-8", errors="ignore")
            text_l = text.lower()

            has_pwd = "password 51:b:" in text_l
            has_user = bool(re.search(r"(?m)^\s*username:s:\S+", text_l))
            has_addr = bool(re.search(r"(?m)^\s*full address:s:\S+", text_l))

            if has_pwd:
                info["has_password"] = True
                info["note"] = "Saved password"
            elif has_user and has_addr:
                info["note"] = "Target & username saved"
            elif has_user:
                info["note"] = "Username saved"
            elif has_addr:
                info["note"] = "Target host saved"
            elif base_l == "default.rdp":
                info["skip"] = True
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return info

    @classmethod
    def _classify_file(cls, path, acl_level, acl_label, rdp_info=None):
        """Classify a matched sensitive file into (risk_tier, category, detail_note)."""
        base_l = os.path.basename(path).lower()
        _, ext_l = os.path.splitext(base_l)
        path_norm = path.replace("\\", "/").lower()

        if (
            base_l in cls._CRED_KEY_NAMES
            or base_l.startswith("unattend")
            or ext_l in cls._CRED_KEY_EXTS
            or "/.ssh/" in path_norm
            or "/.aws/credentials" in path_norm
        ):
            category = "Credentials & Keys"
        elif ext_l in cls._VAULT_EXTS:
            category = "Password Vault"
        elif ext_l in cls._RDP_VPN_EXTS:
            category = "RDP Profile" if ext_l == ".rdp" else "VPN Profile"
        elif (
            ext_l == ".env"
            or base_l in cls._CONFIG_NAMES
            or "/.kube/" in path_norm
            or "/.docker/" in path_norm
            or "/.aws/" in path_norm
            or "/.azure/" in path_norm
            or "/.config/gcloud/" in path_norm
        ):
            category = "Config & Secret"
        elif (
            ext_l in cls._DB_BACKUP_EXTS
            or base_l in cls._SYSTEM_HIVE_NAMES
        ):
            category = "Database & Backup"
        elif ext_l in cls._WEBROOT_EXTS:
            category = "Webroot File"
        else:
            category = "Sensitive File"

        note = (rdp_info or {}).get("note") or ""

        if acl_level == "exposed" or (rdp_info and rdp_info.get("has_password")):
            risk = "High"
        elif acl_level == "shared":
            risk = "Medium"
        elif (
            category == "Credentials & Keys"
            or ext_l == ".env"
            or base_l == ".env"
        ):
            # Protected system files like /etc/shadow stay Low unless exposed/shared.
            if base_l in ("shadow", "sudoers") and acl_label == "Protected":
                risk = "Low"
            else:
                risk = "Medium"
        else:
            risk = "Low"

        return risk, category, note

    def _evaluate_match(self, path, in_temp=False):
        if self._is_symlink_or_junction(path) or not os.path.isfile(path):
            return None

        base_l = os.path.basename(path).lower()
        if base_l in self._KNOWN_BENIGN_FILES:
            return None

        rdp_info = None
        if base_l.endswith(".rdp"):
            rdp_info = self._inspect_rdp_file(path)
            if rdp_info.get("skip"):
                return None

        acl_level, acl_label = self.inspect_acl(path)
        _, ext_l = os.path.splitext(base_l)
        if in_temp and ext_l in self._TEMP_NOISY_EXTS and acl_level == "private":
            return None

        risk, category, note = self._classify_file(
            path, acl_level, acl_label, rdp_info=rdp_info
        )
        finding = {
            "target": path,
            "risk": risk,
            "category": category,
            "acl": acl_label,
        }
        if note:
            finding["note"] = note
        return finding

    def check_sensitive_targets(self):
        """Evaluate known OS-specific sensitive target paths."""
        results = []
        for pattern in self.build_sensitive_paths():
            matches = glob.glob(pattern, recursive=False)
            if not matches and "*" not in pattern and "?" not in pattern:
                matches = [pattern]

            for match in matches:
                if not os.path.exists(match):
                    continue
                item = self._evaluate_match(match)
                if item is not None:
                    results.append(item)
        return results

    def search_for_copies(self, search_dirs=None):
        """Recursively scan staging/webroot dirs with strict depth, file, and time caps."""
        if search_dirs is None:
            search_dirs = self._default_search_dirs()

        found = []
        sys_drive = self._sys_drive() if self.system == "Windows" else "/"
        users_prefix = (
            os.path.normcase(os.path.join(sys_drive, "Users") + "\\")
            if self.system == "Windows"
            else ""
        )
        public_prefix = (
            os.path.normcase(os.path.join(sys_drive, "Users", "Public"))
            if self.system == "Windows"
            else ""
        )

        base_patterns = self._SENSITIVE_PATTERNS
        webroot_patterns = self._WEBROOT_SENSITIVE_PATTERNS
        deadline = time.monotonic() + self.time_budget
        visited_files = 0
        scan_limited = False

        def _is_webroot_dir(dir_path):
            norm = dir_path.replace("\\", "/").rstrip("/").lower()
            return any(
                norm.endswith(m) or (m + "/") in norm
                for m in self._WEBROOT_MARKERS
            )

        def _is_temp_dir(dir_path):
            norm = dir_path.replace("\\", "/").rstrip("/").lower()
            return any(
                norm.endswith(m) or (m + "/") in norm
                for m in self._TEMP_DIR_MARKERS
            )

        def _is_ephemeral_temp_subdir(name_l):
            return name_l.startswith(self._SKIP_TEMP_DIR_PREFIXES) or bool(
                self._PY_TEMPFILE_DIR_RE.match(name_l)
            )

        def _safe_scan(
            base,
            depth,
            skip_user_profiles=False,
            active_patterns=base_patterns,
            in_temp=False,
        ):
            nonlocal visited_files, scan_limited
            if depth > self.max_depth:
                return
            if visited_files >= self.max_files or time.monotonic() > deadline:
                scan_limited = True
                return
            try:
                with os.scandir(base) as entries:
                    for entry in entries:
                        if (
                            visited_files >= self.max_files
                            or time.monotonic() > deadline
                        ):
                            scan_limited = True
                            return
                        try:
                            path = entry.path
                            if (
                                skip_user_profiles
                                and users_prefix
                                and os.path.normcase(path).startswith(users_prefix)
                                and not os.path.normcase(path).startswith(public_prefix)
                            ):
                                continue

                            if self._is_symlink_or_junction(entry):
                                continue

                            name_l = entry.name.lower()
                            if entry.is_file(follow_symlinks=False):
                                visited_files += 1
                                if name_l in self._KNOWN_BENIGN_FILES:
                                    continue
                                for pat in active_patterns:
                                    if fnmatch.fnmatch(name_l, pat):
                                        item = self._evaluate_match(
                                            path, in_temp=in_temp
                                        )
                                        if item is not None:
                                            found.append(item)
                                        break
                            elif entry.is_dir(follow_symlinks=False):
                                if name_l in self._SKIP_DIRS:
                                    continue
                                if in_temp and _is_ephemeral_temp_subdir(name_l):
                                    continue
                                _safe_scan(
                                    path,
                                    depth + 1,
                                    skip_user_profiles=skip_user_profiles,
                                    active_patterns=active_patterns,
                                    in_temp=in_temp,
                                )
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, FileNotFoundError, OSError):
                return

        expanded_dirs = []
        seen_dirs = set()
        for raw_base in search_dirs:
            if not raw_base:
                continue
            base = (
                raw_base.format(sysdrive=sys_drive, drive=sys_drive)
                if "{" in raw_base
                else raw_base
            )
            candidates = (
                glob.glob(base) if ("*" in base or "?" in base) else [base]
            )
            for candidate in candidates:
                if os.path.isdir(candidate) and not self._is_symlink_or_junction(
                    candidate
                ):
                    norm_dir = os.path.normcase(os.path.abspath(candidate))
                    if norm_dir not in seen_dirs:
                        seen_dirs.add(norm_dir)
                        expanded_dirs.append(candidate)

        for target_dir in expanded_dirs:
            if scan_limited:
                break
            target_norm = os.path.normcase(os.path.abspath(target_dir))
            skip_profiles = bool(
                users_prefix and not target_norm.startswith(users_prefix)
            )
            pats = (
                (base_patterns + webroot_patterns)
                if _is_webroot_dir(target_dir)
                else base_patterns
            )
            _safe_scan(
                target_dir,
                0,
                skip_user_profiles=skip_profiles,
                active_patterns=pats,
                in_temp=_is_temp_dir(target_dir),
            )

        return found, scan_limited

    def check_sensitive_paths(self, check_dirs=None):
        """Run targeted and staged-copy scans and return a structured report."""
        targets = self.check_sensitive_targets()
        copies, scan_limited = self.search_for_copies(search_dirs=check_dirs)

        risk_rank = {"High": 0, "Medium": 1, "Low": 2}
        merged = {}
        for item in targets + copies:
            key = os.path.normcase(os.path.abspath(item["target"]))
            cur_rank = risk_rank.get(item.get("risk"), 3)
            if key not in merged or cur_rank < risk_rank.get(
                merged[key].get("risk"), 3
            ):
                merged[key] = item

        ordered_all = sorted(
            merged.values(),
            key=lambda x: (risk_rank.get(x.get("risk"), 3), x["target"].lower()),
        )

        # Cap Low-risk Database & Backup findings per directory to prevent noise floods.
        low_db_per_dir: dict[str, int] = {}
        ordered = []
        for item in ordered_all:
            if (
                item.get("risk") == "Low"
                and item.get("category") == "Database & Backup"
            ):
                parent_key = os.path.normcase(os.path.dirname(item["target"]))
                count = low_db_per_dir.get(parent_key, 0)
                if count >= self._MAX_LOW_DB_PER_DIR:
                    continue
                low_db_per_dir[parent_key] = count + 1
            ordered.append(item)

        high_cnt = sum(1 for x in ordered if x.get("risk") == "High")
        med_cnt = sum(1 for x in ordered if x.get("risk") == "Medium")
        low_cnt = sum(1 for x in ordered if x.get("risk") == "Low")
        shown = ordered[: self.max_display]

        return {
            "platform": self.system,
            "hostname": platform.node(),
            "summary": {
                "total_count": len(ordered),
                "displayed_count": len(shown),
                "high": high_cnt,
                "medium": med_cnt,
                "low": low_cnt,
                "truncated": len(ordered) > len(shown),
                "scan_limited": scan_limited,
            },
            "findings": shown,
            "notes": [
                "Findings report file paths and permission metadata only; file secrets are never extracted.",
                "Review paths before sharing reports externally, as they may contain local usernames or directory names.",
                "Recursive scans are bounded by depth, file count, and time limits for safety and performance.",
            ],
        }

    def audit(self, check_dirs=None):
        """Run the sensitive paths audit and return a structured report."""
        return self.check_sensitive_paths(check_dirs=check_dirs)


SensitivePaths = SensitivePathsAudit

if __name__ == "__main__":
    print(json.dumps(
        SensitivePathsAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
