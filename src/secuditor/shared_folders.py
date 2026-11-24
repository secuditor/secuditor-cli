# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform shared folder and network export exposure audit."""

import configparser
import json
import os
import platform
import re
import shutil
import socket
import stat

from ._utils import find_powershell, run_command, run_powershell

__all__ = ["SharedFolders", "SharedFoldersAudit"]


class SharedFoldersAudit:
    """Enumerate active network shares/exports and inspect access permissions."""

    _SKIP_ADMIN_SHARES = {"ADMIN$", "IPC$"}

    def __init__(self, timeout=8.0):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        return run_command(args, timeout=self.timeout)

    # --- Windows Win32 ctypes share & DACL helpers ---

    @staticmethod
    def _windows_dacl_permissions(folder_path: str) -> tuple[list[str], bool]:
        """Inspect a Windows folder DACL via advapi32 ctypes (no pywin32)."""
        perms: list[str] = []
        everyone_detected = False

        if not folder_path:
            return ["(No local path)"], False

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

            FILE_ALL_ACCESS = 0x001F01FF
            FILE_GENERIC_READ = 0x00120089
            FILE_GENERIC_WRITE = 0x00120116
            FILE_GENERIC_EXECUTE = 0x001200A0
            GENERIC_ALL = 0x10000000
            GENERIC_EXECUTE = 0x20000000
            GENERIC_WRITE = 0x40000000
            GENERIC_READ = 0x80000000

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

            LookupAccountSidW = advapi32.LookupAccountSidW
            LookupAccountSidW.argtypes = [
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
            ]
            LookupAccountSidW.restype = wintypes.BOOL

            def _sid_to_str(sid_ptr):
                str_ptr = ctypes.c_void_p()
                try:
                    if (
                        ConvertSidToStringSidW(sid_ptr, ctypes.byref(str_ptr))
                        and str_ptr.value
                    ):
                        return ctypes.wstring_at(str_ptr.value)
                finally:
                    if str_ptr.value:
                        LocalFree(str_ptr)
                return None

            def _resolve_sid(sid_ptr, fallback):
                name_len = wintypes.DWORD(0)
                dom_len = wintypes.DWORD(0)
                sid_use = wintypes.DWORD(0)
                LookupAccountSidW(
                    None,
                    sid_ptr,
                    None,
                    ctypes.byref(name_len),
                    None,
                    ctypes.byref(dom_len),
                    ctypes.byref(sid_use),
                )
                if name_len.value == 0:
                    return fallback
                name_buf = ctypes.create_unicode_buffer(name_len.value)
                dom_buf = ctypes.create_unicode_buffer(max(dom_len.value, 1))
                if LookupAccountSidW(
                    None,
                    sid_ptr,
                    name_buf,
                    ctypes.byref(name_len),
                    dom_buf,
                    ctypes.byref(dom_len),
                    ctypes.byref(sid_use),
                ):
                    return (
                        f"{dom_buf.value}\\{name_buf.value}"
                        if dom_buf.value
                        else name_buf.value
                    )
                return fallback

            dacl_ptr = ctypes.c_void_p()
            sd_ptr = ctypes.c_void_p()
            err = GetNamedSecurityInfoW(
                folder_path,
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
                    return ["(Access denied)"], False
                return [f"(Unable to read ACL: error {err})"], False

            try:
                if not dacl_ptr.value:
                    return [
                        "NULL DACL (Unrestricted Everyone Full Control)"
                    ], True

                acl_info = ACL_SIZE_INFORMATION()
                if not GetAclInformation(
                    dacl_ptr,
                    ctypes.byref(acl_info),
                    ctypes.sizeof(acl_info),
                    AclSizeInformation,
                ):
                    return ["(Unable to inspect ACL)"], False

                denied_sids = set()
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

                for idx in range(acl_info.AceCount):
                    ace_ptr = ctypes.c_void_p()
                    if not GetAce(dacl_ptr, idx, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                        continue

                    header = ctypes.cast(
                        ace_ptr, ctypes.POINTER(ACE_HEADER)
                    ).contents
                    ace_type = header.AceType
                    ace_flags = header.AceFlags
                    if ace_type not in allow_types and ace_type not in deny_types:
                        continue
                    if ace_flags & INHERIT_ONLY_ACE:
                        continue

                    access_mask = ctypes.cast(
                        ctypes.c_void_p(ace_ptr.value + 4),
                        ctypes.POINTER(wintypes.DWORD),
                    ).contents.value

                    if ace_type in object_types:
                        obj_flags = ctypes.cast(
                            ctypes.c_void_p(ace_ptr.value + 8),
                            ctypes.POINTER(wintypes.DWORD),
                        ).contents.value
                        sid_offset = 12
                        if obj_flags & 0x1:  # ACE_OBJECT_TYPE_PRESENT
                            sid_offset += 16
                        if obj_flags & 0x2:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                            sid_offset += 16
                    else:
                        sid_offset = 8

                    if sid_offset >= header.AceSize:
                        continue
                    sid_ptr = ctypes.c_void_p(ace_ptr.value + sid_offset)
                    sid_str = _sid_to_str(sid_ptr)
                    if not sid_str:
                        continue
                    account = _resolve_sid(sid_ptr, sid_str)

                    if ace_type in deny_types:
                        denied_sids.add(sid_str)
                        if sid_str != "S-1-5-18":
                            perms.append(f"{account}: Denied")
                        continue

                    # Skip LocalSystem (S-1-5-18); preserve ANONYMOUS LOGON & Authenticated Users.
                    if sid_str == "S-1-5-18":
                        continue

                    if (
                        sid_str in ("S-1-1-0", "S-1-5-7")
                        and sid_str not in denied_sids
                    ):
                        everyone_detected = True

                    rights = []
                    if (
                        (access_mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS
                        or bool(access_mask & GENERIC_ALL)
                    ):
                        rights = ["Full Control"]
                    else:
                        if (
                            (access_mask & FILE_GENERIC_READ)
                            == FILE_GENERIC_READ
                            or bool(access_mask & GENERIC_READ)
                        ):
                            rights.append("Read")
                        if (
                            (access_mask & FILE_GENERIC_WRITE)
                            == FILE_GENERIC_WRITE
                            or bool(access_mask & GENERIC_WRITE)
                        ):
                            rights.append("Write")
                        if (
                            (access_mask & FILE_GENERIC_EXECUTE)
                            == FILE_GENERIC_EXECUTE
                            or bool(access_mask & GENERIC_EXECUTE)
                        ):
                            rights.append("Execute")

                    perms.append(
                        f"{account}: {', '.join(rights) if rights else 'Special Permissions'}"
                    )
            finally:
                if sd_ptr.value:
                    LocalFree(sd_ptr)

        except PermissionError:
            perms.append("(Access denied)")
        except Exception as exc:
            perms.append(f"(Unable to read ACL: {exc})")

        return perms, everyone_detected

    def _windows_shares_netapi(self):
        """Enumerate local SMB shares via netapi32.NetShareEnum (level 2)."""
        try:
            import ctypes
            from ctypes import wintypes

            class SHARE_INFO_2(ctypes.Structure):
                _fields_ = [
                    ("shi2_netname", wintypes.LPWSTR),
                    ("shi2_type", wintypes.DWORD),
                    ("shi2_remark", wintypes.LPWSTR),
                    ("shi2_permissions", wintypes.DWORD),
                    ("shi2_max_uses", wintypes.DWORD),
                    ("shi2_current_uses", wintypes.DWORD),
                    ("shi2_path", wintypes.LPWSTR),
                    ("shi2_passwd", wintypes.LPWSTR),
                ]

            netapi32 = ctypes.windll.netapi32

            NetApiBufferFree = netapi32.NetApiBufferFree
            NetApiBufferFree.argtypes = [ctypes.c_void_p]
            NetApiBufferFree.restype = wintypes.DWORD

            NetShareEnum = netapi32.NetShareEnum
            NetShareEnum.argtypes = [
                wintypes.LPWSTR,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
            ]
            NetShareEnum.restype = wintypes.DWORD

            MAX_PREFERRED_LENGTH = 0xFFFFFFFF
            ERROR_MORE_DATA = 234

            raw_shares = []
            resume = wintypes.DWORD(0)
            while True:
                buf = ctypes.c_void_p()
                entries_read = wintypes.DWORD(0)
                total_entries = wintypes.DWORD(0)
                status = NetShareEnum(
                    None,
                    2,
                    ctypes.byref(buf),
                    MAX_PREFERRED_LENGTH,
                    ctypes.byref(entries_read),
                    ctypes.byref(total_entries),
                    ctypes.byref(resume),
                )
                try:
                    if status not in (0, ERROR_MORE_DATA):
                        return None
                    if buf.value and entries_read.value:
                        arr = ctypes.cast(buf, ctypes.POINTER(SHARE_INFO_2))
                        for idx in range(entries_read.value):
                            entry = arr[idx]
                            raw_shares.append({
                                "Name": entry.shi2_netname or "",
                                "Path": entry.shi2_path or "",
                                "Description": entry.shi2_remark or "",
                            })
                finally:
                    if buf.value:
                        NetApiBufferFree(buf)
                if status != ERROR_MORE_DATA:
                    break

            return raw_shares
        except (ImportError, AttributeError, OSError):
            return None

    def _windows_shares(self):
        raw_shares = self._windows_shares_netapi()
        if raw_shares is None and find_powershell():
            data = run_powershell(
                "Get-CimInstance Win32_Share -ErrorAction SilentlyContinue "
                "| Select-Object Name,Path,Description | ConvertTo-Json -Compress",
                timeout=self.timeout,
                parse_json=True,
            )
            if isinstance(data, dict):
                raw_shares = [data]
            elif isinstance(data, list):
                raw_shares = data
            else:
                raw_shares = []

        shares = []
        for item in raw_shares or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("Name") or "").strip()
            if not name or name.upper() in self._SKIP_ADMIN_SHARES:
                continue
            path = str(item.get("Path") or "").strip()
            desc = str(item.get("Description") or "").strip()
            if path:
                permissions, everyone_flag = self._windows_dacl_permissions(path)
            else:
                permissions = ["(No local path)"]
                everyone_flag = False

            shares.append({
                "name": name,
                "path": path or None,
                "protocol": "SMB",
                "description": desc or "None",
                "admin_share": name.endswith("$"),
                "everyone_accessible": everyone_flag,
                "permissions": permissions,
            })

        return shares

    # --- POSIX filesystem permission helper ---

    @staticmethod
    def _posix_path_permissions(path: str | None) -> tuple[list[str], bool]:
        if not path:
            return ["(No local path)"], False
        try:
            mode = os.stat(path).st_mode
            perms = [f"POSIX mode: {oct(stat.S_IMODE(mode))}"]
            world_readable = bool(mode & stat.S_IROTH)
            world_writable = bool(mode & stat.S_IWOTH)
            if world_writable:
                perms.append("Others: Read/Write (world-writable)")
            elif world_readable:
                perms.append("Others: Read")
            return perms, world_writable
        except PermissionError:
            return ["(Access denied)"], False
        except OSError:
            return ["(Path not found)"], False

    # --- Linux Samba & NFS shares ---

    def _linux_shares(self):
        shares = []

        # 1. Samba shares (/etc/samba/smb.conf or testparm -s)
        smb_text = None
        if shutil.which("testparm"):
            smb_text = self._run(["testparm", "-s"])
        if not smb_text:
            try:
                with open(
                    "/etc/samba/smb.conf", encoding="utf-8", errors="replace"
                ) as f:
                    smb_text = f.read()
            except OSError:
                smb_text = None

        if smb_text:
            parser = configparser.ConfigParser(
                interpolation=None, strict=False
            )
            try:
                parser.read_string(smb_text)
            except configparser.Error:
                parser = None

            if parser is not None:
                for section in parser.sections():
                    sec_l = section.strip().lower()
                    if sec_l in ("global", "printers", "print$"):
                        continue
                    sec = parser[section]
                    path = (sec.get("path") or "").strip()
                    comment = (sec.get("comment") or "").strip()
                    guest_ok = (
                        (sec.get("guest ok") or sec.get("public") or "")
                        .strip()
                        .lower()
                        in ("yes", "true", "1")
                    )
                    read_only = (
                        (sec.get("read only") or "yes").strip().lower()
                        in ("yes", "true", "1")
                    )
                    writable = (
                        (sec.get("writable") or sec.get("writeable") or "")
                        .strip()
                        .lower()
                        in ("yes", "true", "1")
                    )
                    valid_users = (sec.get("valid users") or "").strip()

                    fs_perms, world_writable = self._posix_path_permissions(
                        path
                    )
                    perms = list(fs_perms)
                    perms.append(
                        "SMB Access: Read/Write"
                        if (writable or not read_only)
                        else "SMB Access: Read-Only"
                    )
                    if guest_ok:
                        perms.append("Guest Access: Allowed (Everyone)")
                    if valid_users:
                        perms.append(f"Valid Users: {valid_users}")

                    shares.append({
                        "name": section.strip(),
                        "path": path or None,
                        "protocol": "SMB",
                        "description": comment or "None",
                        "admin_share": section.strip().endswith("$"),
                        "everyone_accessible": guest_ok or world_writable,
                        "permissions": perms,
                    })

        # 2. NFS exports (/etc/exports)
        try:
            with open("/etc/exports", encoding="utf-8", errors="replace") as f:
                for raw_line in f:
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if not parts:
                        continue
                    export_path = parts[0].strip('"')
                    clients = parts[1:]
                    exposed = any(
                        c.startswith("*")
                        or "no_root_squash" in c.lower()
                        or "(rw" in c.lower() and c.startswith("*")
                        for c in clients
                    )
                    fs_perms, world_writable = self._posix_path_permissions(
                        export_path
                    )
                    perms = list(fs_perms)
                    if clients:
                        perms.append(f"NFS Clients: {' '.join(clients)}")
                    shares.append({
                        "name": export_path,
                        "path": export_path,
                        "protocol": "NFS",
                        "description": "NFS Export",
                        "admin_share": False,
                        "everyone_accessible": exposed or world_writable,
                        "permissions": perms,
                    })
        except OSError:
            pass

        return shares

    # --- macOS shares ---

    def _macos_shares(self):
        shares = []
        output = self._run(["sharing", "-l"])
        if not output:
            return shares

        blocks = re.split(r"\n\s*\n", output.strip())
        for block in blocks:
            kv = {}
            for line in block.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                kv[k.strip().lower()] = v.strip()

            name = kv.get("name") or kv.get("smb name")
            path = kv.get("path")
            if not name and not path:
                continue

            smb_shared = kv.get("smb shared", "").lower() in ("1", "yes", "true")
            guest_access = kv.get("smb guest access", "").lower() in (
                "1",
                "yes",
                "true",
            ) or kv.get("guest access", "").lower() in ("1", "yes", "true")

            fs_perms, world_writable = self._posix_path_permissions(path)
            perms = list(fs_perms)
            if guest_access:
                perms.append("Guest Access: Allowed (Everyone)")

            shares.append({
                "name": name or path,
                "path": path or None,
                "protocol": "SMB" if smb_shared else "Share",
                "description": "macOS File Share",
                "admin_share": bool(name and name.endswith("$")),
                "everyone_accessible": guest_access or world_writable,
                "permissions": perms,
            })

        return shares

    def get_shared_folders(self):
        """Return structured shared folder exposure inventory."""
        if self.system == "Windows":
            shares = self._windows_shares()
        elif self.system == "Linux":
            shares = self._linux_shares()
        elif self.system == "Darwin":
            shares = self._macos_shares()
        else:
            shares = []

        exposed = sum(
            1
            for s in shares
            if s.get("everyone_accessible") and not s.get("admin_share")
        )

        return {
            "platform": self.system,
            "hostname": socket.gethostname(),
            "count": len(shares),
            "exposed_count": exposed,
            "shares": shares,
            "notes": [
                "Default Windows ADMIN$ and IPC$ shares are excluded.",
                "Some share permissions may require elevated privileges to inspect.",
            ],
        }

    def audit(self):
        """Run the shared folders audit and return a structured report."""
        return self.get_shared_folders()


SharedFolders = SharedFoldersAudit

if __name__ == "__main__":
    print(json.dumps(
        SharedFoldersAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
