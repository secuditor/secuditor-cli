
# Secuditor – Copyright (c) 2026 Menahem Levinski

"""Cross-platform local password policy discovery."""

import os
import platform
import re
import shutil
import subprocess


__all__ = ["PasswordPolicyAudit"]


class PasswordPolicyAudit:
    """Read available password policy settings without modifying the system."""

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def _setting(value=None, status="unknown", source=None):
        return {
            "value": value,
            "status": status,
            "source": source,
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

    def _audit_windows(self, report):
        # `net accounts` exposes several local/domain account policy values.
        # Output labels can be localized, so only recognized labels are parsed.
        output = self._run(["net.exe", "accounts"])

        if output is None:
            report["limitations"].append(
                "Unable to retrieve account policy using net accounts."
            )
        else:
            patterns = {
                "minimum_length": (
                    r"Minimum password length\s+(\d+)"
                ),
                "maximum_age_days": (
                    r"Maximum password age\s+(\d+|Unlimited|Never)"
                ),
                "minimum_age_days": (
                    r"Minimum password age\s+(\d+)"
                ),
                "password_history": (
                    r"Length of password history maintained\s+(\d+)"
                ),
                "lockout_threshold": (
                    r"Lockout threshold\s+(\d+|Never)"
                ),
                "lockout_duration_minutes": (
                    r"Lockout duration \(minutes\)\s+(\d+|Never)"
                ),
                "lockout_reset_minutes": (
                    r"Lockout observation window \(minutes\)\s+(\d+|Never)"
                ),
            }

            for key, pattern in patterns.items():
                match = re.search(
                    pattern, output, re.IGNORECASE
                )
                if not match:
                    continue

                raw = match.group(1).strip()
                if raw.isdigit():
                    value = int(raw)
                elif raw.lower() in ("never", "unlimited"):
                    value = raw.lower()
                else:
                    continue

                report["settings"][key] = self._setting(
                    value, "detected", "net accounts"
                )

        # Export security policy to a temporary file to inspect the
        # password-complexity setting. This can fail without sufficient rights.
        # Do not leave the exported policy file behind.
        import tempfile

        policy_text = None
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                prefix="secuditor_policy_",
                suffix=".inf",
                delete=False,
            ) as temp_file:
                temp_path = temp_file.name

            output = self._run([
                "secedit.exe",
                "/export",
                "/cfg",
                temp_path,
                "/areas",
                "SECURITYPOLICY",
            ])

            if output is not None and os.path.isfile(temp_path):
                try:
                    with open(
                        temp_path, encoding="utf-16"
                    ) as file:
                        policy_text = file.read()
                except (UnicodeError, OSError):
                    try:
                        with open(
                            temp_path, encoding="utf-8-sig"
                        ) as file:
                            policy_text = file.read()
                    except (UnicodeError, OSError):
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
                        enabled,
                        "detected",
                        "secedit",
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

        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

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
            "PASS_WARN_AGE": None,
        }

        for source_key, target_key in mapping.items():
            if target_key is None:
                continue

            raw = login_defs.get(source_key)
            if raw is not None and raw.lstrip("-").isdigit():
                report["settings"][target_key] = self._setting(
                    int(raw), "detected", "/etc/login.defs"
                )

        # Linux password complexity is usually enforced by PAM modules
        # such as pam_pwquality or pam_passwdqc, not login.defs alone.
        pam_files = [
            "/etc/pam.d/common-password",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/pam.d/passwd",
        ]

        found_pam = False
        complexity_options = []

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

        if complexity_options:
            report["settings"]["complexity"] = self._setting(
                complexity_options,
                "partially_detected",
                "PAM configuration",
            )
        elif found_pam:
            report["settings"]["complexity"] = self._setting(
                None,
                "unknown",
                "PAM configuration",
            )

        # `chage -l` provides aging data for the current account.
        chage = shutil.which("chage")
        if chage:
            import getpass

            output = self._run([chage, "-l", getpass.getuser()])
            if output:
                report["current_user"] = {
                    "username": getpass.getuser(),
                    "password_aging": output,
                    "source": "chage",
                }
            else:
                report["limitations"].append(
                    "Unable to retrieve current-user aging information."
                )

        report["limitations"].append(
            "Linux policy can also be controlled by PAM, LDAP, Active "
            "Directory, or other identity providers. login.defs values "
            "are defaults and do not necessarily represent effective policy."
        )

    def _audit_macos(self, report):
        # macOS password policy query support varies by release and account.
        output = self._run(["pwpolicy", "-getglobalpolicy"])

        if output:
            report["global_policy"] = {
                "value": output,
                "status": "detected",
                "source": "pwpolicy",
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
                match = re.search(
                    pattern, output, re.IGNORECASE
                )
                if match:
                    value = int(match.group(1))

                    # Apple's maxMinutesUntilChangePassword is in minutes,
                    # so convert to days for the shared report.
                    if key == "maximum_age_days":
                        value = round(value / 1440, 2)

                    report["settings"][key] = self._setting(
                        value, "detected", "pwpolicy"
                    )
        else:
            report["global_policy"] = self._setting(
                None, "unavailable", "pwpolicy"
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


if __name__ == "__main__":
    import json

    print(json.dumps(
        PasswordPolicyAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
