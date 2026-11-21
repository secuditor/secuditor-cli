# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform local password policy discovery."""

from datetime import datetime, timezone
import os
import platform
import plistlib
import re
import shutil
import tempfile

from ._utils import run_command

__all__ = ["PasswordPolicy", "PasswordPolicyAudit"]

_TIMEQ_FOREVER = 0xFFFFFFFF
_UF_PASSWD_NOTREQD = 0x0020


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
            "password_required",
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
        if not (is_domain_joined and not target_server):
            modals0_buf = ctypes.c_void_p()
            try:
                if NetUserModalsGet(
                    target_server, 0, ctypes.byref(modals0_buf)
                ) == 0 and modals0_buf:
                    info0 = ctypes.cast(
                        modals0_buf, ctypes.POINTER(USER_MODALS_INFO_0)
                    ).contents
                    report["settings"]["minimum_length"] = self._setting(
                        int(info0.usrmod0_min_passwd_len), "detected"
                    )
                    report["settings"]["maximum_age_days"] = self._setting(
                        self._seconds_to_days(info0.usrmod0_max_passwd_age),
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
                    report["settings"]["lockout_threshold"] = self._setting(
                        int(info3.usrmod3_lockout_threshold), "detected"
                    )
                    report["settings"]["lockout_duration_minutes"] = (
                        self._setting(
                            self._seconds_to_minutes(
                                info3.usrmod3_lockout_duration
                            ),
                            "detected",
                        )
                    )
                    report["settings"]["lockout_reset_minutes"] = (
                        self._setting(
                            self._seconds_to_minutes(
                                info3.usrmod3_lockout_observation_window
                            ),
                            "detected",
                        )
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

        # Export security policy into an isolated temporary directory to inspect
        # PasswordComplexity. This typically requires elevated privileges.
        policy_text = None
        try:
            with tempfile.TemporaryDirectory(prefix="secuditor_policy_") as tmpdir:
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
                            with open(temp_path, encoding=encoding) as file:
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
                    r"\bpam_(pwquality|passwdqc)\.so\b",
                    line,
                ):
                    complexity_options.append({
                        "file": path,
                        "configuration": line,
                    })

                if re.search(r"\bpam_faillock\.so\b", line):
                    for opt in ("deny", "unlock_time", "fail_interval"):
                        m = re.search(rf"\b{opt}\s*=\s*(\d+)", line)
                        if m:
                            faillock_options[opt] = int(m.group(1))

        # Read /etc/security/pwquality.conf for minlen and credit settings.
        pwquality_cfg = {}
        try:
            with open(
                "/etc/security/pwquality.conf",
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
            pass

        if "minlen" in pwquality_cfg:
            report["settings"]["minimum_length"] = self._setting(
                pwquality_cfg["minlen"], "detected"
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
                None, "unknown"
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
                    if label.strip().lower() == "account expires":
                        cleaned = val.strip()
                        if cleaned:
                            report["settings"]["account_expiration"] = (
                                self._setting(
                                    "never"
                                    if cleaned.lower() == "never"
                                    else cleaned,
                                    "detected",
                                )
                            )
                        break
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
