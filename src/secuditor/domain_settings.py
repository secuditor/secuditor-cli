# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform domain affiliation and identity configuration discovery."""

import json
import platform
import shutil

from ._utils import read_registry_value, run_command, run_powershell

__all__ = ["DomainAudit", "DomainSettingsAudit"]

class DomainSettingsAudit:
    """Discover domain affiliation, local users, and related settings."""

    WINDOWS_ROLES = {
        0: "Standalone Workstation",
        1: "Member Workstation",
        2: "Standalone Server",
        3: "Member Server",
        4: "Backup Domain Controller",
        5: "Primary Domain Controller",
    }

    def __init__(self, timeout=8):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        return run_command(args, timeout=self.timeout)

    def _powershell(self, command):
        return run_powershell(command, timeout=self.timeout, parse_json=True)

    @staticmethod
    def _unknown():
        return {
            "status": "unknown",
            "value": None,
            "source": None,
        }

    def _base_report(self):
        return {
            "platform": self.system,
            "hostname": platform.node(),
            "current_user": None,
            "affiliation": self._unknown(),
            "domain_role": self._unknown(),
            "laps": self._unknown(),
            "ntlm_policy": self._unknown(),
            "ntp": self._unknown(),
            "users": {
                "status": "unknown",
                "privileged": [],
                "regular": [],
            },
            "limitations": [],
        }

    def _windows_registry_value(self, path, name):
        return read_registry_value("HKLM", path, name)

    def _windows_affiliation(self, report):
        # CIM is used to retrieve computer domain membership and role.
        computer = self._powershell(
            "Get-CimInstance Win32_ComputerSystem | "
            "Select-Object Name,Domain,PartOfDomain,DomainRole | "
            "ConvertTo-Json -Compress"
        )
        domain = None

        if isinstance(computer, dict):
            joined = computer.get("PartOfDomain")
            domain = computer.get("Domain")

            if joined is True:
                report["affiliation"] = {
                    "status": "detected",
                    "value": {
                        "type": "Active Directory domain",
                        "name": domain,
                    },
                    "source": "Win32_ComputerSystem",
                }
            elif joined is False:
                report["affiliation"] = {
                    "status": "detected",
                    "value": {
                        "type": "workgroup or standalone",
                        "name": domain,
                    },
                    "source": "Win32_ComputerSystem",
                }

            role = computer.get("DomainRole")
            if isinstance(role, int):
                report["domain_role"] = {
                    "status": "detected",
                    "value": self.WINDOWS_ROLES.get(
                        role, f"Unknown ({role})"
                    ),
                    "source": "Win32_ComputerSystem",
                }

        # Entra ID and hybrid join are independent signals.
        dsreg = self._run(["dsregcmd.exe", "/status"])
        if dsreg:
            flags = {}
            for line in dsreg.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                flags[key.strip()] = value.strip()

            entra_joined = flags.get("AzureAdJoined", "").upper() == "YES"
            domain_joined = flags.get("DomainJoined", "").upper() == "YES"

            if entra_joined or domain_joined:
                if entra_joined and domain_joined:
                    join_type = "hybrid Entra ID and Active Directory"
                elif entra_joined:
                    join_type = "Microsoft Entra ID"
                else:
                    join_type = "Active Directory"

                report["affiliation"] = {
                    "status": "detected",
                    "value": {
                        "type": join_type,
                        "name": (
                            (flags.get("DomainName") or domain)
                            if domain_joined else
                            (flags.get("TenantName") or domain)
                        ),
                        "entra_joined": entra_joined,
                        "domain_joined": domain_joined,
                    },
                    "source": "dsregcmd",
                }

        self._windows_users(report)
        self._windows_laps(report)
        self._windows_ntlm(report)
        self._windows_ntp(report)

    @staticmethod
    def _extract_sid(sid):
        if isinstance(sid, dict):
            value = sid.get("Value")
            return str(value) if value is not None else None
        if sid is None:
            return None
        return str(sid)

    def _windows_users(self, report):
        # Get-LocalUser and Get-LocalGroupMember may be unavailable
        # on some Windows editions or in constrained environments.
        users = self._powershell(
            "Get-LocalUser | Select-Object Name,Enabled,"
            "@{Name='SID';Expression={$_.SID.Value}} "
            "| ConvertTo-Json -Compress"
        )

        admins = self._powershell(
            "Get-LocalGroupMember -Group 'Administrators' "
            "| Select-Object Name,"
            "@{Name='SID';Expression={$_.SID.Value}},PrincipalSource "
            "| ConvertTo-Json -Compress"
        )

        if users is None:
            report["limitations"].append(
                "Local user enumeration was unavailable."
            )
            return

        if isinstance(users, dict):
            users = [users]
        if not isinstance(users, list):
            return

        if isinstance(admins, dict):
            admins = [admins]
        if not isinstance(admins, list):
            admins = []

        admin_sids = set()
        for item in admins:
            if not isinstance(item, dict):
                continue
            sid = self._extract_sid(item.get("SID"))
            if sid:
                admin_sids.add(sid)

        for user in users:
            if not isinstance(user, dict):
                continue

            sid = self._extract_sid(user.get("SID"))
            item = {
                "name": user.get("Name"),
                "enabled": user.get("Enabled"),
                "sid": sid,
                "administrator_member": (
                    sid is not None and sid in admin_sids
                ),
            }

            if item["administrator_member"]:
                report["users"]["privileged"].append(item)
            else:
                report["users"]["regular"].append(item)

        report["users"]["status"] = "detected"

    def _windows_laps(self, report):
        # Legacy LAPS policy and Windows LAPS policy are distinct.
        legacy_path = (
            r"SOFTWARE\Policies\Microsoft Services\AdmPwd"
        )
        windows_laps_path = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
        )

        legacy = self._windows_registry_value(
            legacy_path, "AdmPwdEnabled"
        )
        backup = self._windows_registry_value(
            windows_laps_path, "BackupDirectory"
        )

        policies = []

        if legacy is not None:
            policies.append({
                "product": "Legacy Microsoft LAPS",
                "configured": bool(legacy),
            })

        if backup is not None:
            policies.append({
                "product": "Windows LAPS",
                "backup_directory": backup,
                "configured": backup in (1, 2),
            })

        if policies:
            report["laps"] = {
                "status": "detected",
                "value": policies,
                "source": "Windows registry",
            }
        else:
            report["laps"] = {
                "status": "unknown",
                "value": None,
                "source": "Windows registry",
            }
            report["limitations"].append(
                "No recognized LAPS policy values were found. "
                "This does not prove that LAPS is absent or unconfigured."
            )

    def _windows_ntlm(self, report):
        lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
        msv = lsa + r"\MSV1_0"

        lm_level = self._windows_registry_value(
            lsa, "LmCompatibilityLevel"
        )
        no_lm_hash = self._windows_registry_value(
            lsa, "NoLMHash"
        )
        audit = self._windows_registry_value(
            msv, "AuditReceivingNTLMTraffic"
        )

        if lm_level is None:
            report["ntlm_policy"] = {
                "status": "unknown",
                "value": None,
                "source": "Windows registry",
            }
            return

        descriptions = {
            0: "Send LM and NTLM responses",
            1: "Send LM and NTLM; use NTLMv2 session security if negotiated",
            2: "Send NTLM response only",
            3: "Send NTLMv2 response only",
            4: "Send NTLMv2; refuse LM",
            5: "Send NTLMv2; refuse LM and NTLM",
        }

        report["ntlm_policy"] = {
            "status": "detected",
            "value": {
                "lm_compatibility_level": lm_level,
                "description": descriptions.get(
                    lm_level, "Unknown configuration"
                ),
                "no_lm_hash": no_lm_hash,
                "audit_receiving_ntlm_traffic": audit,
            },
            "source": "Windows registry",
        }

    def _windows_ntp(self, report):
        output = self._run(["w32tm.exe", "/query", "/status"])

        if output:
            report["ntp"] = {
                "status": "detected",
                "value": output,
                "source": "w32tm",
            }
        else:
            report["ntp"] = {
                "status": "unavailable",
                "value": None,
                "source": "w32tm",
            }

    def _linux_affiliation(self, report):
        # realm list detects configured realm membership when realmd
        # is installed and can access the relevant configuration.
        realm = self._run(["realm", "list"]) if shutil.which("realm") else None

        if realm:
            report["affiliation"] = {
                "status": "detected",
                "value": {
                    "type": "configured realm",
                    "details": realm,
                },
                "source": "realm list",
            }
        else:
            report["affiliation"] = {
                "status": "unknown",
                "value": None,
                "source": "realmd",
            }
            report["limitations"].append(
                "No realm membership was returned. This does not rule "
                "out LDAP, SSSD, Winbind, or other directory integration."
            )

        self._linux_users(report)
        self._linux_ntp(report)

        report["ntlm_policy"] = {
            "status": "not_applicable",
            "value": None,
            "source": None,
        }
        report["laps"] = {
            "status": "not_applicable",
            "value": None,
            "source": None,
        }

    def _linux_users(self, report):
        try:
            import pwd

            users = []
            excluded_names = {"nobody", "nfsnobody"}

            for entry in pwd.getpwall():
                if (
                    entry.pw_uid == 0
                    or (
                        entry.pw_uid >= 1000
                        and entry.pw_uid != 65534
                        and entry.pw_name not in excluded_names
                    )
                ):
                    users.append({
                        "name": entry.pw_name,
                        "uid": entry.pw_uid,
                        "gid": entry.pw_gid,
                        "home": entry.pw_dir,
                        "shell": entry.pw_shell,
                    })

            privileged_names = {"root"}
            privileged_gids = set()
            for group_name in ("sudo", "wheel"):
                try:
                    import grp
                    group = grp.getgrnam(group_name)
                    privileged_names.update(group.gr_mem)
                    privileged_gids.add(group.gr_gid)
                except (KeyError, ImportError):
                    continue

            for user in users:
                is_privileged = (
                    user["name"] in privileged_names
                    or user["uid"] == 0
                    or user["gid"] in privileged_gids
                )
                user_record = {
                    "name": user["name"],
                    "uid": user["uid"],
                    "home": user["home"],
                    "shell": user["shell"],
                }
                if is_privileged:
                    report["users"]["privileged"].append(user_record)
                else:
                    report["users"]["regular"].append(user_record)

            report["users"]["status"] = "detected"
            report["limitations"].append(
                "Linux privilege discovery checks root UID and direct "
                "membership in sudo/wheel. It does not resolve all "
                "nested directory groups or sudoers rules."
            )

        except (OSError, AttributeError):
            report["limitations"].append(
                "Unable to enumerate local users."
            )

    def _linux_ntp(self, report):
        for command in (
            ["timedatectl", "show-timesync", "--all"],
            ["chronyc", "tracking"],
            ["ntpq", "-pn"],
        ):
            executable = shutil.which(command[0])
            if not executable:
                continue

            output = self._run(command)
            if output:
                report["ntp"] = {
                    "status": "detected",
                    "value": output,
                    "source": command[0],
                }
                return

        report["ntp"] = {
            "status": "unknown",
            "value": None,
            "source": None,
        }

    def _macos_affiliation(self, report):
        output = self._run(["dsconfigad", "-show"])

        if output:
            report["affiliation"] = {
                "status": "detected",
                "value": {
                    "type": "Active Directory binding",
                    "details": output,
                },
                "source": "dsconfigad",
            }
        else:
            report["affiliation"] = {
                "status": "unknown",
                "value": None,
                "source": "dsconfigad",
            }
            report["limitations"].append(
                "Active Directory binding was not confirmed. Other "
                "directory services may still be configured."
            )

        self._macos_users(report)

        report["laps"] = {
            "status": "not_applicable",
            "value": None,
            "source": None,
        }
        report["ntlm_policy"] = {
            "status": "not_applicable",
            "value": None,
            "source": None,
        }

        # Inspect local macOS NTP configuration without making outbound queries.
        ntp_server = self._run(["systemsetup", "-getnetworktimeserver"])
        ntp_enabled = self._run(["systemsetup", "-getusingnetworktime"])
        ntp_details = "\n".join(
            part for part in (ntp_enabled, ntp_server) if part
        )
        report["ntp"] = {
            "status": "detected" if ntp_details else "unknown",
            "value": ntp_details or None,
            "source": "systemsetup" if ntp_details else None,
        }

    def _macos_users(self, report):
        # dscl lists local directory records; group membership checks
        # identify direct members of the local admin group.
        output = self._run([
            "dscl", ".", "-list", "/Users"
        ])

        if output is None:
            report["limitations"].append(
                "Unable to enumerate local directory users."
            )
            return

        admins_output = self._run([
            "dscl", ".", "-read", "/Groups/admin", "GroupMembership"
        ])
        admins = set()

        if admins_output:
            parts = admins_output.split(":", 1)
            if len(parts) == 2:
                admins.update(parts[1].split())

        for name in output.splitlines():
            name = name.strip()
            if not name:
                continue

            item = {"name": name}

            if name in admins or name == "root":
                report["users"]["privileged"].append(item)
            else:
                report["users"]["regular"].append(item)

        report["users"]["status"] = "detected"
        report["limitations"].append(
            "macOS privilege discovery uses direct local admin-group "
            "membership and does not resolve every directory or nested "
            "group privilege."
        )

    def audit(self):
        report = self._base_report()

        try:
            import getpass
            report["current_user"] = getpass.getuser()
        except (ImportError, OSError):
            pass

        if self.system == "Windows":
            self._windows_affiliation(report)
        elif self.system == "Linux":
            self._linux_affiliation(report)
        elif self.system == "Darwin":
            self._macos_affiliation(report)
        else:
            report["limitations"].append(
                "This operating system is not supported."
            )

        return report


DomainAudit = DomainSettingsAudit

if __name__ == "__main__":
    print(json.dumps(
        DomainSettingsAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
