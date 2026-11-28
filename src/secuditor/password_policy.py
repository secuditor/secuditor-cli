# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform local password policy discovery."""

from datetime import datetime, timezone
import glob
import os
import platform
import plistlib
import re
import shutil
import tempfile

from ._utils import read_registry_value, run_command, run_powershell

__all__ = ["PasswordPolicy", "PasswordPolicyAudit"]

_TIMEQ_FOREVER = 0xFFFFFFFF
_UF_PASSWD_NOTREQD = 0x0020
_UF_DONT_EXPIRE_PASSWD = 0x10000


class PasswordPolicyAudit:
    """Read available password policy settings without modifying the system."""

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        return run_command(args, timeout=self.timeout)

    @staticmethod
    def _setting(value=None, status="unknown", source=None):
        return {
            "value": value,
            "status": status,
        }

    def _base_report(self):
        names = [
            "minimum_length",
            "maximum_age_days",
            "minimum_age_days",
            "password_history",
            "complexity",
            "lockout_threshold",
            "lockout_duration_minutes",
            "lockout_reset_minutes",
            "account_expiration",
            "password_expires",
            "password_required",
            "pin_or_biometrics",
        ]

        return {
            "platform": self.system,
            "scope": "local",
            "settings": {
                name: self._setting()
                for name in names
            },
            "limitations": [],
        }

    @staticmethod
    def _seconds_to_days(seconds):
        if seconds in (0, _TIMEQ_FOREVER):
            return "never"
        days = seconds / 86400
        return int(days) if days.is_integer() else round(days, 2)

    @staticmethod
    def _seconds_to_minutes(seconds):
        if seconds == _TIMEQ_FOREVER:
            return "never"
        mins = seconds / 60
        return int(mins) if mins.is_integer() else round(mins, 2)

    def _windows_netapi_policy(self, report):
        """Query local or domain password/lockout policy via Win32 netapi32."""
        try:
            import ctypes
            from ctypes import wintypes
        except ImportError:
            return False

        class USER_MODALS_INFO_0(ctypes.Structure):
            _fields_ = [
                ("usrmod0_min_passwd_len", wintypes.DWORD),
                ("usrmod0_max_passwd_age", wintypes.DWORD),
                ("usrmod0_min_passwd_age", wintypes.DWORD),
                ("usrmod0_force_logoff", wintypes.DWORD),
                ("usrmod0_password_hist_len", wintypes.DWORD),
            ]

        class USER_MODALS_INFO_3(ctypes.Structure):
            _fields_ = [
                ("usrmod3_lockout_duration", wintypes.DWORD),
                ("usrmod3_lockout_observation_window", wintypes.DWORD),
                ("usrmod3_lockout_threshold", wintypes.DWORD),
            ]

        class USER_INFO_2(ctypes.Structure):
            _fields_ = [
                ("usri2_name", wintypes.LPWSTR),
                ("usri2_password", wintypes.LPWSTR),
                ("usri2_password_age", wintypes.DWORD),
                ("usri2_priv", wintypes.DWORD),
                ("usri2_home_dir", wintypes.LPWSTR),
                ("usri2_comment", wintypes.LPWSTR),
                ("usri2_flags", wintypes.DWORD),
                ("usri2_script_path", wintypes.LPWSTR),
                ("usri2_auth_flags", wintypes.DWORD),
                ("usri2_full_name", wintypes.LPWSTR),
                ("usri2_usr_comment", wintypes.LPWSTR),
                ("usri2_parms", wintypes.LPWSTR),
                ("usri2_workstations", wintypes.LPWSTR),
                ("usri2_last_logon", wintypes.DWORD),
                ("usri2_last_logoff", wintypes.DWORD),
                ("usri2_acct_expires", wintypes.DWORD),
                ("usri2_max_storage", wintypes.DWORD),
                ("usri2_units_per_week", wintypes.DWORD),
                ("usri2_logon_hours", ctypes.c_void_p),
                ("usri2_bad_pw_count", wintypes.DWORD),
                ("usri2_num_logons", wintypes.DWORD),
                ("usri2_logon_server", wintypes.LPWSTR),
                ("usri2_country_code", wintypes.DWORD),
                ("usri2_code_page", wintypes.DWORD),
            ]

        try:
            netapi32 = ctypes.windll.netapi32
        except (AttributeError, OSError):
            return False

        NetApiBufferFree = netapi32.NetApiBufferFree
        NetApiBufferFree.argtypes = [ctypes.c_void_p]
        NetApiBufferFree.restype = wintypes.DWORD

        NetGetJoinInformation = netapi32.NetGetJoinInformation
        NetGetJoinInformation.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_int),
        ]
        NetGetJoinInformation.restype = wintypes.DWORD

        NetGetDCName = netapi32.NetGetDCName
        NetGetDCName.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        NetGetDCName.restype = wintypes.DWORD

        NetUserModalsGet = netapi32.NetUserModalsGet
        NetUserModalsGet.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        NetUserModalsGet.restype = wintypes.DWORD

        NetUserGetInfo = netapi32.NetUserGetInfo
        NetUserGetInfo.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        NetUserGetInfo.restype = wintypes.DWORD

        # Check whether the host is joined to an AD domain.
        is_domain_joined = False
        join_name_buf = ctypes.c_void_p()
        join_status = ctypes.c_int()
        try:
            if NetGetJoinInformation(
                None, ctypes.byref(join_name_buf), ctypes.byref(join_status)
            ) == 0:
                is_domain_joined = join_status.value == 3
        finally:
            if join_name_buf:
                NetApiBufferFree(join_name_buf)

        target_server = None
        dc_buf = ctypes.c_void_p()
        if is_domain_joined:
            try:
                if NetGetDCName(None, None, ctypes.byref(dc_buf)) == 0 and dc_buf:
                    target_server = ctypes.wstring_at(dc_buf.value)
                    report["scope"] = "domain"
            finally:
                if dc_buf:
                    NetApiBufferFree(dc_buf)

            if not target_server:
                report["limitations"].append(
                    "Domain controller was unreachable; effective domain "
                    "password policy could not be queried via NetAPI."
                )

        populated = False
        max_passwd_age = None
        if not (is_domain_joined and not target_server):
            modals0_buf = ctypes.c_void_p()
            try:
                if NetUserModalsGet(
                    target_server, 0, ctypes.byref(modals0_buf)
                ) == 0 and modals0_buf:
                    info0 = ctypes.cast(
                        modals0_buf, ctypes.POINTER(USER_MODALS_INFO_0)
                    ).contents
                    max_passwd_age = int(info0.usrmod0_max_passwd_age)
                    report["settings"]["minimum_length"] = self._setting(
                        int(info0.usrmod0_min_passwd_len), "detected"
                    )
                    report["settings"]["maximum_age_days"] = self._setting(
                        self._seconds_to_days(max_passwd_age),
                        "detected",
                    )
                    report["settings"]["minimum_age_days"] = self._setting(
                        int(info0.usrmod0_min_passwd_age // 86400),
                        "detected",
                    )
                    hist = int(info0.usrmod0_password_hist_len)
                    report["settings"]["password_history"] = self._setting(
                        "none" if hist == 0 else hist, "detected"
                    )
                    populated = True
            finally:
                if modals0_buf:
                    NetApiBufferFree(modals0_buf)

            modals3_buf = ctypes.c_void_p()
            try:
                if NetUserModalsGet(
                    target_server, 3, ctypes.byref(modals3_buf)
                ) == 0 and modals3_buf:
                    info3 = ctypes.cast(
                        modals3_buf, ctypes.POINTER(USER_MODALS_INFO_3)
                    ).contents
                    threshold = int(info3.usrmod3_lockout_threshold)
                    duration = int(info3.usrmod3_lockout_duration)
                    obs_window = int(info3.usrmod3_lockout_observation_window)

                    report["settings"]["lockout_threshold"] = self._setting(
                        threshold, "detected"
                    )
                    if threshold == 0:
                        dur_val = "not_applicable"
                        reset_val = "not_applicable"
                    else:
                        if duration in (0, _TIMEQ_FOREVER):
                            dur_val = "until_admin_unlocks"
                        else:
                            dur_val = self._seconds_to_minutes(duration)
                        reset_val = self._seconds_to_minutes(obs_window)

                    report["settings"]["lockout_duration_minutes"] = (
                        self._setting(dur_val, "detected")
                    )
                    report["settings"]["lockout_reset_minutes"] = (
                        self._setting(reset_val, "detected")
                    )
                    populated = True
            finally:
                if modals3_buf:
                    NetApiBufferFree(modals3_buf)

        # Query current account flags and expiration.
        try:
            import getpass

            username = getpass.getuser()
            user_domain = os.environ.get("USERDOMAIN", "").strip()
            computer_name = os.environ.get("COMPUTERNAME", "").strip()

            acct_domain = user_domain
            acct_name = username
            if "\\" in username:
                acct_domain, acct_name = username.split("\\", 1)
                acct_domain = acct_domain.strip()

            is_local = not acct_domain or (
                computer_name
                and acct_domain.casefold() == computer_name.casefold()
            )
            is_cloud = acct_domain.casefold() in ("azuread", "microsoftaccount")

            acct_server = None
            query_allowed = is_local
            if not is_local and is_domain_joined and not is_cloud:
                acct_dc_buf = ctypes.c_void_p()
                try:
                    if NetGetDCName(
                        None, acct_domain, ctypes.byref(acct_dc_buf)
                    ) == 0 and acct_dc_buf:
                        acct_server = ctypes.wstring_at(acct_dc_buf.value)
                    else:
                        acct_server = target_server
                finally:
                    if acct_dc_buf:
                        NetApiBufferFree(acct_dc_buf)
                query_allowed = bool(acct_server)

            if query_allowed and acct_name:
                user2_buf = ctypes.c_void_p()
                try:
                    if NetUserGetInfo(
                        acct_server, acct_name, 2, ctypes.byref(user2_buf)
                    ) == 0 and user2_buf:
                        info2 = ctypes.cast(
                            user2_buf, ctypes.POINTER(USER_INFO_2)
                        ).contents
                        flags = int(info2.usri2_flags)
                        report["settings"]["password_required"] = self._setting(
                            not bool(flags & _UF_PASSWD_NOTREQD), "detected"
                        )
                        acct_never_expires = bool(
                            flags & _UF_DONT_EXPIRE_PASSWD
                        )
                        if acct_never_expires or max_passwd_age in (
                            0,
                            _TIMEQ_FOREVER,
                        ):
                            report["settings"]["password_expires"] = (
                                self._setting(False, "detected")
                            )
                        elif max_passwd_age is not None and max_passwd_age > 0:
                            report["settings"]["password_expires"] = (
                                self._setting(True, "detected")
                            )
                        acct_exp = int(info2.usri2_acct_expires)
                        if acct_exp == _TIMEQ_FOREVER:
                            exp_val = "never"
                        else:
                            exp_val = datetime.fromtimestamp(
                                acct_exp, tz=timezone.utc
                            ).strftime("%Y-%m-%d")
                        report["settings"]["account_expiration"] = (
                            self._setting(exp_val, "detected")
                        )
                finally:
                    if user2_buf:
                        NetApiBufferFree(user2_buf)
        except OSError:
            pass

        return populated

    @staticmethod
    def _windows_is_admin():
        """Return True if the current process is elevated on Windows."""
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (ImportError, AttributeError, OSError):
            return False

    @staticmethod
    def _windows_current_user_sid():
        """Return the current process user SID string via Win32 token APIs."""
        try:
            import ctypes
            from ctypes import wintypes

            TOKEN_QUERY = 0x0008
            TokenUser = 1

            class SID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("Sid", ctypes.c_void_p),
                    ("Attributes", wintypes.DWORD),
                ]

            class TOKEN_USER(ctypes.Structure):
                _fields_ = [("User", SID_AND_ATTRIBUTES)]

            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            GetCurrentProcess = kernel32.GetCurrentProcess
            GetCurrentProcess.restype = wintypes.HANDLE

            CloseHandle = kernel32.CloseHandle
            CloseHandle.argtypes = [wintypes.HANDLE]
            CloseHandle.restype = wintypes.BOOL

            LocalFree = kernel32.LocalFree
            LocalFree.argtypes = [ctypes.c_void_p]
            LocalFree.restype = ctypes.c_void_p

            OpenProcessToken = advapi32.OpenProcessToken
            OpenProcessToken.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            OpenProcessToken.restype = wintypes.BOOL

            GetTokenInformation = advapi32.GetTokenInformation
            GetTokenInformation.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            GetTokenInformation.restype = wintypes.BOOL

            ConvertSidToStringSidW = advapi32.ConvertSidToStringSidW
            ConvertSidToStringSidW.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            ConvertSidToStringSidW.restype = wintypes.BOOL

            tok = wintypes.HANDLE()
            if not OpenProcessToken(
                GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)
            ):
                return None

            try:
                buf_len = wintypes.DWORD(0)
                GetTokenInformation(
                    tok, TokenUser, None, 0, ctypes.byref(buf_len)
                )
                if buf_len.value == 0:
                    return None
                buf = ctypes.create_string_buffer(buf_len.value)
                if not GetTokenInformation(
                    tok,
                    TokenUser,
                    buf,
                    buf_len.value,
                    ctypes.byref(buf_len),
                ):
                    return None
                token_user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
                sid_str_ptr = ctypes.c_void_p()
                try:
                    if (
                        ConvertSidToStringSidW(
                            token_user.User.Sid, ctypes.byref(sid_str_ptr)
                        )
                        and sid_str_ptr.value
                    ):
                        return ctypes.wstring_at(sid_str_ptr.value)
                finally:
                    if sid_str_ptr.value:
                        LocalFree(sid_str_ptr)
            finally:
                CloseHandle(tok)
        except (ImportError, AttributeError, OSError):
            pass
        return None

    def _windows_hello_pin(self):
        """Check Windows Hello (PIN / Biometrics) for the current user without admin rights."""
        user_sid = self._windows_current_user_sid()
        if not user_sid:
            return None

        factors = []

        # Windows Hello PIN (NGC Credential Provider / LogonUI NgcPin)
        pin_active = False
        ngc_path = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication"
            rf"\Credential Providers\{{D6886603-9D2F-4EB2-B667-1971041FA96B}}\{user_sid}"
        )
        logon_creds = read_registry_value("HKLM", ngc_path, "LogonCredsAvailable")
        try:
            if logon_creds is not None and int(logon_creds) == 1:
                pin_active = True
        except (TypeError, ValueError):
            pass

        if not pin_active:
            pin_cred_path = (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication"
                rf"\LogonUI\NgcPin\Credentials\{user_sid}"
            )
            enc_pwd = read_registry_value(
                "HKLM", pin_cred_path, "EncryptedPassword"
            )
            if enc_pwd:
                pin_active = True

        if pin_active:
            factors.append("PIN")

        # Windows Hello Biometrics (WinBio EnrolledFactors bitmask)
        bio_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\{user_sid}"
        raw_mask = read_registry_value("HKLM", bio_path, "EnrolledFactors")
        try:
            mask = int(raw_mask) if raw_mask is not None else 0
            if mask > 0:
                bio_found = False
                if mask & 0x02:
                    factors.append("Face")
                    bio_found = True
                if mask & 0x08:
                    factors.append("Fingerprint")
                    bio_found = True
                if mask & 0x10:
                    factors.append("Iris")
                    bio_found = True
                if not bio_found:
                    factors.append("Biometrics")
        except (TypeError, ValueError):
            pass

        if factors:
            return f"Enabled ({', '.join(factors)})"
        return "Not Configured"

    def _windows_domain_complexity(self):
        """Query Active Directory default domain password complexity without admin rights."""
        ps_cmd = (
            "try { "
            "$nc = ([ADSI]'LDAP://RootDSE').defaultNamingContext; "
            "if ($nc) { ([ADSI]('LDAP://' + $nc)).pwdProperties.Value } "
            "} catch {}"
        )
        out = run_powershell(ps_cmd, timeout=self.timeout, parse_json=False)
        if not out:
            return None
        try:
            return bool(int(out.strip()) & 0x00000001)
        except ValueError:
            return None

    def _audit_windows(self, report):
        # Prefer locale-independent Win32 NetAPI, falling back to `net accounts`.
        if not self._windows_netapi_policy(report):
            output = self._run(["net.exe", "accounts"])

            if output is None:
                report["limitations"].append(
                    "Unable to retrieve account policy via NetAPI or net accounts."
                )
            else:
                patterns = {
                    "minimum_length": (
                        r"Minimum password length:?\s+(\d+)"
                    ),
                    "maximum_age_days": (
                        r"Maximum password age(?:\s+\(days\))?:?\s+"
                        r"(\d+|Unlimited|Never)"
                    ),
                    "minimum_age_days": (
                        r"Minimum password age(?:\s+\(days\))?:?\s+(\d+)"
                    ),
                    "password_history": (
                        r"Length of password history maintained:?\s+(\d+|None)"
                    ),
                    "lockout_threshold": (
                        r"Lockout threshold:?\s+(\d+|Never)"
                    ),
                    "lockout_duration_minutes": (
                        r"Lockout duration \(minutes\):?\s+(\d+|Never)"
                    ),
                    "lockout_reset_minutes": (
                        r"Lockout observation window \(minutes\):?\s+"
                        r"(\d+|Never)"
                    ),
                }

                for key, pattern in patterns.items():
                    match = re.search(pattern, output, re.IGNORECASE)
                    if not match:
                        continue

                    raw = match.group(1).strip()
                    if raw.isdigit():
                        value = int(raw)
                    elif raw.lower() in ("never", "unlimited", "none"):
                        value = raw.lower()
                    else:
                        continue

                    report["settings"][key] = self._setting(value, "detected")

        # Non-admin Windows Hello / PIN & Biometrics detection.
        hello_status = self._windows_hello_pin()
        if hello_status is not None:
            report["settings"]["pin_or_biometrics"] = self._setting(
                hello_status, "detected"
            )

        # Password complexity: prefer non-admin AD LDAP on domain-joined hosts,
        # otherwise use secedit when elevated.
        complexity_resolved = False
        if report.get("scope") == "domain":
            dom_comp = self._windows_domain_complexity()
            if dom_comp is not None:
                report["settings"]["complexity"] = self._setting(
                    dom_comp, "detected"
                )
                complexity_resolved = True

        if not complexity_resolved:
            policy_text = None
            if self._windows_is_admin():
                try:
                    with tempfile.TemporaryDirectory(
                        prefix="secuditor_policy_"
                    ) as tmpdir:
                        temp_path = os.path.join(tmpdir, "policy.inf")
                        output = self._run([
                            "secedit.exe",
                            "/export",
                            "/cfg",
                            temp_path,
                            "/areas",
                            "SECURITYPOLICY",
                        ])

                        if output is not None and os.path.isfile(temp_path):
                            for encoding in ("utf-16", "utf-8-sig"):
                                try:
                                    with open(
                                        temp_path, encoding=encoding
                                    ) as file:
                                        policy_text = file.read()
                                    break
                                except (UnicodeError, OSError):
                                    continue
                except OSError:
                    pass

            if policy_text:
                match = re.search(
                    r"^\s*PasswordComplexity\s*=\s*(\d+)",
                    policy_text,
                    re.MULTILINE | re.IGNORECASE,
                )
                if match:
                    enabled = match.group(1) == "1"
                    report["settings"]["complexity"] = self._setting(
                        enabled, "detected"
                    )
                else:
                    report["limitations"].append(
                        "Password complexity was not present in the "
                        "exported security policy."
                    )
            else:
                report["limitations"].append(
                    "Password complexity could not be retrieved; "
                    "secedit may require elevated privileges."
                )

        report["limitations"].append(
            "Results may reflect local or domain-applied account policy; "
            "this module does not independently verify effective domain "
            "policy or every user-specific override."
        )

    def _audit_linux(self, report):
        # login.defs supplies defaults; PAM and other authentication
        # providers may override them.
        login_defs = {}

        try:
            with open(
                "/etc/login.defs", encoding="utf-8", errors="replace"
            ) as file:
                for line in file:
                    line = line.split("#", 1)[0].strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        login_defs[parts[0].upper()] = parts[1]
        except OSError:
            report["limitations"].append(
                "Unable to read /etc/login.defs."
            )

        mapping = {
            "PASS_MIN_LEN": "minimum_length",
            "PASS_MAX_DAYS": "maximum_age_days",
            "PASS_MIN_DAYS": "minimum_age_days",
        }

        for source_key, target_key in mapping.items():
            raw = login_defs.get(source_key)
            if raw is not None and raw.lstrip("-").isdigit():
                report["settings"][target_key] = self._setting(
                    int(raw), "detected"
                )

        # Linux password complexity and lockout are usually enforced by PAM
        # modules (pam_pwquality, pam_passwdqc, pam_faillock).
        pam_files = [
            "/etc/pam.d/common-password",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/pam.d/passwd",
        ]

        found_pam = False
        complexity_options = []
        faillock_options = {}
        bio_modules = []
        pam_minlen = None
        pam_unix_minlen = None

        for path in pam_files:
            try:
                with open(
                    path, encoding="utf-8", errors="replace"
                ) as file:
                    content = file.read()
            except OSError:
                continue

            found_pam = True
            for line in content.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue

                if re.search(
                    r"\bpam_(pwquality|passwdqc|cracklib)\.so\b",
                    line,
                ):
                    complexity_options.append({
                        "file": path,
                        "configuration": line,
                    })
                    ml = re.search(r"\bminlen\s*=\s*(\d+)", line)
                    if ml:
                        pam_minlen = int(ml.group(1))
                elif re.search(r"\bpam_unix\.so\b", line):
                    ml = re.search(r"\bminlen\s*=\s*(\d+)", line)
                    if ml:
                        pam_unix_minlen = int(ml.group(1))

                if re.search(r"\bpam_faillock\.so\b", line):
                    for opt in ("deny", "unlock_time", "fail_interval"):
                        m = re.search(rf"\b{opt}\s*=\s*(\d+)", line)
                        if m:
                            faillock_options[opt] = int(m.group(1))

                if re.search(r"\bpam_fprintd\.so\b", line) and "Fingerprint" not in bio_modules:
                    bio_modules.append("Fingerprint")
                if re.search(r"\bpam_u2f\.so\b", line) and "U2F/FIDO2" not in bio_modules:
                    bio_modules.append("U2F/FIDO2")

        if bio_modules:
            report["settings"]["pin_or_biometrics"] = self._setting(
                f"Enabled ({', '.join(bio_modules)})", "detected"
            )
        elif found_pam:
            report["settings"]["pin_or_biometrics"] = self._setting(
                "Not Configured", "detected"
            )

        # Read /etc/security/pwquality.conf and drop-ins for minlen/credits.
        pwquality_cfg = {}
        pwq_paths = ["/etc/security/pwquality.conf"]
        try:
            pwq_paths.extend(sorted(glob.glob("/etc/security/pwquality.conf.d/*.conf")))
        except OSError:
            pass
        for pwq_path in pwq_paths:
            try:
                with open(
                    pwq_path,
                    encoding="utf-8",
                    errors="replace",
                ) as file:
                    for line in file:
                        line = line.split("#", 1)[0].strip()
                        if "=" not in line:
                            continue
                        key, val = [part.strip() for part in line.split("=", 1)]
                        if val.lstrip("-").isdigit():
                            pwquality_cfg[key] = int(val)
            except OSError:
                continue

        if "minlen" in pwquality_cfg:
            report["settings"]["minimum_length"] = self._setting(
                pwquality_cfg["minlen"], "detected"
            )
        elif pam_minlen is not None:
            report["settings"]["minimum_length"] = self._setting(
                pam_minlen, "detected"
            )
        elif pam_unix_minlen is not None and report["settings"]["minimum_length"]["value"] is None:
            report["settings"]["minimum_length"] = self._setting(
                pam_unix_minlen, "detected"
            )

        pwquality_complexity = {
            key: pwquality_cfg[key]
            for key in ("dcredit", "ucredit", "lcredit", "ocredit", "minclass")
            if key in pwquality_cfg
        }
        if complexity_options or pwquality_complexity:
            value = {
                "pam": complexity_options,
                "pwquality": pwquality_complexity,
            } if pwquality_complexity else complexity_options
            report["settings"]["complexity"] = self._setting(
                value, "partially_detected"
            )
        elif found_pam:
            report["settings"]["complexity"] = self._setting(
                False, "detected"
            )

        # Read /etc/security/faillock.conf (overrides/supplements PAM args).
        try:
            with open(
                "/etc/security/faillock.conf",
                encoding="utf-8",
                errors="replace",
            ) as file:
                for line in file:
                    line = line.split("#", 1)[0].strip()
                    if "=" not in line:
                        continue
                    key, val = [part.strip() for part in line.split("=", 1)]
                    if key in ("deny", "unlock_time", "fail_interval") and val.isdigit():
                        faillock_options.setdefault(key, int(val))
        except OSError:
            pass

        if "deny" in faillock_options:
            report["settings"]["lockout_threshold"] = self._setting(
                faillock_options["deny"], "detected"
            )
        if "unlock_time" in faillock_options:
            unlock_sec = faillock_options["unlock_time"]
            report["settings"]["lockout_duration_minutes"] = self._setting(
                "never" if unlock_sec == 0 else round(unlock_sec / 60, 2),
                "detected",
            )
        if "fail_interval" in faillock_options:
            report["settings"]["lockout_reset_minutes"] = self._setting(
                round(faillock_options["fail_interval"] / 60, 2),
                "detected",
            )

        import getpass
        current_user = getpass.getuser()
        safe_user = (
            bool(current_user)
            and not current_user.startswith("-")
        )

        # `chage -l` provides aging and account expiration data.
        chage = shutil.which("chage")
        if chage and safe_user:
            output = self._run([chage, "-l", current_user])
            if output:
                report["current_user"] = {
                    "username": current_user,
                    "password_aging": output,
                }
                for line in output.splitlines():
                    if ":" not in line:
                        continue
                    label, val = line.split(":", 1)
                    norm_label = label.strip().lower()
                    cleaned = val.strip()
                    if norm_label == "account expires" and cleaned:
                        report["settings"]["account_expiration"] = (
                            self._setting(
                                "never"
                                if cleaned.lower() == "never"
                                else cleaned,
                                "detected",
                            )
                        )
                    elif norm_label == "password expires" and cleaned:
                        report["settings"]["password_expires"] = self._setting(
                            cleaned.lower() != "never", "detected"
                        )
            else:
                report["limitations"].append(
                    "Unable to retrieve current-user aging information."
                )

        # `passwd -S` checks whether a password is set/required when permitted.
        passwd_bin = shutil.which("passwd")
        if passwd_bin and safe_user:
            output = self._run([passwd_bin, "-S", current_user])
            if output:
                parts = output.split()
                if len(parts) >= 2:
                    code = parts[1].upper()
                    if code in ("P", "PS", "L", "LK"):
                        report["settings"]["password_required"] = self._setting(
                            True, "detected"
                        )
                    elif code == "NP":
                        report["settings"]["password_required"] = self._setting(
                            False, "detected"
                        )

        report["limitations"].append(
            "Linux policy can also be controlled by PAM, LDAP, Active "
            "Directory, or other identity providers. login.defs values "
            "are defaults and do not necessarily represent effective policy."
        )

    def _audit_macos(self, report):
        # Try modern account policies plist first, then legacy global policy.
        account_policies = self._run(["pwpolicy", "-getaccountpolicies"])
        if account_policies and "<plist" in account_policies:
            try:
                xml_start = account_policies.index("<?xml")
                plist_data = plistlib.loads(
                    account_policies[xml_start:].encode("utf-8")
                )
                report["global_policy"] = {
                    "value": plist_data,
                    "status": "detected",
                }
            except (ValueError, plistlib.InvalidFileException):
                pass

        # macOS legacy global policy query support varies by release and account.
        output = self._run(["pwpolicy", "-getglobalpolicy"])

        if output:
            if "global_policy" not in report:
                report["global_policy"] = {
                    "value": output,
                    "status": "detected",
                }

            patterns = {
                "minimum_length": (
                    r"(?:minChars|minLength)\s*=\s*(\d+)"
                ),
                "maximum_age_days": (
                    r"(?:maxMinutesUntilChangePassword)\s*=\s*(\d+)"
                ),
                "password_history": (
                    r"(?:usingHistory)\s*=\s*(\d+)"
                ),
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    value = int(match.group(1))
                    if key == "maximum_age_days":
                        value = round(value / 1440, 2)
                    report["settings"][key] = self._setting(value, "detected")
        elif "global_policy" not in report:
            report["global_policy"] = self._setting(None, "unavailable")

        # Check Touch ID status via bioutil when available on macOS.
        if shutil.which("bioutil"):
            bio_out = self._run(["bioutil", "-r"])
            if bio_out:
                m = re.search(
                    r"Touch ID for unlock:\s*(\d+)", bio_out, re.IGNORECASE
                )
                if m:
                    report["settings"]["pin_or_biometrics"] = self._setting(
                        "Enabled (Touch ID)"
                        if m.group(1) == "1"
                        else "Not Configured",
                        "detected",
                    )

        report["limitations"].append(
            "macOS password policy retrieval depends on account type, "
            "OS version, and permissions. Unknown values are not treated "
            "as disabled."
        )

    def audit(self):
        report = self._base_report()

        if self.system == "Windows":
            self._audit_windows(report)
        elif self.system == "Linux":
            self._audit_linux(report)
        elif self.system == "Darwin":
            self._audit_macos(report)
        else:
            report["limitations"].append(
                "This operating system is not supported."
            )

        return report


PasswordPolicy = PasswordPolicyAudit

if __name__ == "__main__":
    import json

    print(json.dumps(
        PasswordPolicyAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
