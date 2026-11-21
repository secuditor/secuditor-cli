import builtins
import io
import os
import socket
import types
import unittest
from unittest.mock import patch

from secuditor import (
    DomainAudit,
    InstalledApps,
    NetworkSettings,
    PasswordPolicy,
    SystemSettings,
)
from secuditor._utils import _sanitize_path_env, _system_exe


class TestUtils(unittest.TestCase):
    def test_system_exe_leaves_non_builtin_untouched(self):
        self.assertEqual(_system_exe("custom_tool"), "custom_tool")

    def test_sanitize_path_strips_relative_and_dot_segments(self):
        abs_dir = os.path.abspath("/usr/bin")
        raw = os.pathsep.join(["", ".", "relative/bin", abs_dir])
        self.assertEqual(_sanitize_path_env(raw), abs_dir)


class TestDomainAudit(unittest.TestCase):
    def test_windows_affiliation_preserves_casing_and_schema(self):
        audit = DomainAudit()
        audit.system = "Windows"
        report = audit._base_report()

        ps_responses = [
            {
                "Name": "WORKSTATION1",
                "Domain": "corp.example.com",
                "PartOfDomain": True,
                "DomainRole": 1,
            },
            [],
            [],
        ]
        run_responses = [
            "AzureAdJoined : YES\nDomainJoined : YES\nDomainName : Corp.Example.Com\n",
            "Leap Indicator: 0",
        ]

        with (
            patch.object(audit, "_windows_join_info", return_value=(None, None)),
            patch.object(audit, "_powershell", side_effect=ps_responses),
            patch.object(audit, "_run", side_effect=run_responses),
            patch.object(audit, "_windows_registry_value", return_value=None),
        ):
            audit._windows_affiliation(report)

        self.assertEqual(report["affiliation"]["status"], "detected")
        self.assertEqual(
            report["affiliation"]["value"]["type"],
            "hybrid Entra ID and Active Directory",
        )
        self.assertEqual(
            report["affiliation"]["value"]["name"],
            "Corp.Example.Com",
        )
        self.assertEqual(report["domain_role"]["value"], "Member Workstation")

    def test_windows_users_handles_dict_sid_without_unhashable_error(self):
        audit = DomainAudit()
        audit.system = "Windows"
        report = audit._base_report()

        users_payload = [
            {
                "Name": "Administrator",
                "Enabled": True,
                "SID": {"BinaryLength": 28, "Value": "S-1-5-21-100-500"},
            },
            {
                "Name": "StandardUser",
                "Enabled": True,
                "SID": {"BinaryLength": 28, "Value": "S-1-5-21-100-1001"},
            },
        ]
        admins_payload = [
            {
                "Name": "PC\\Administrator",
                "SID": {"BinaryLength": 28, "Value": "S-1-5-21-100-500"},
                "PrincipalSource": 1,
            }
        ]

        with patch.object(
            audit,
            "_powershell",
            side_effect=[users_payload, admins_payload],
        ):
            audit._windows_users(report)

        self.assertEqual(report["users"]["status"], "detected")
        self.assertEqual(len(report["users"]["privileged"]), 1)
        self.assertEqual(report["users"]["privileged"][0]["name"], "Administrator")
        self.assertEqual(report["users"]["privileged"][0]["sid"], "S-1-5-21-100-500")
        self.assertEqual(len(report["users"]["regular"]), 1)
        self.assertEqual(report["users"]["regular"][0]["name"], "StandardUser")

    def test_windows_laps_ntlm_and_ntp_enrichments(self):
        audit = DomainAudit()
        audit.system = "Windows"
        report = audit._base_report()

        reg_map = {
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS", "BackupDirectory"): 1,
            (r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictReceivingNTLMTraffic"): 2,
            (r"SYSTEM\CurrentControlSet\Control\Lsa", "BlockNtlmv1SSO"): 1,
        }

        def fake_reg(path, name):
            return reg_map.get((path, name))

        with (
            patch.object(audit, "_windows_registry_value", side_effect=fake_reg),
            patch.object(audit, "_run", side_effect=[None, "STATE : 4 RUNNING"]),
        ):
            audit._windows_laps(report)
            audit._windows_ntlm(report)
            audit._windows_ntp(report)

        self.assertEqual(report["laps"]["status"], "detected")
        self.assertTrue(report["laps"]["value"][0]["configured"])
        self.assertEqual(report["ntlm_policy"]["status"], "detected")
        self.assertEqual(
            report["ntlm_policy"]["value"]["restrict_receiving_ntlm_traffic"],
            2,
        )
        self.assertEqual(report["ntlm_policy"]["value"]["block_ntlmv1_sso"], 1)
        self.assertEqual(report["ntp"]["status"], "detected")
        self.assertIn("Running", report["ntp"]["value"])

    def test_windows_users_net_fallback_rejects_switches_and_localized_footer(self):
        audit = DomainAudit()
        audit.system = "Windows"
        report = audit._base_report()

        net_user_list = (
            "User accounts for \\\\HOST\n"
            "-------------------------------------------------------------------------------\n"
            "Administrator            /add                     Guest                    \n"
            "La commande s'est terminee correctement.\n"
        )
        admin_detail = (
            "User name                    Administrator\n"
            "Account active               Yes\n"
            "Local Group Memberships      *Administrators\n"
        )
        guest_detail = (
            "User name                    Guest\n"
            "Account active               No\n"
            "Local Group Memberships      *Guests\n"
        )

        with patch.object(
            audit,
            "_run",
            side_effect=[net_user_list, admin_detail, guest_detail],
        ) as mock_run:
            ok = audit._windows_users_net_fallback(report)

        self.assertTrue(ok)
        self.assertEqual(mock_run.call_count, 3)
        self.assertEqual(report["users"]["privileged"][0]["name"], "Administrator")
        self.assertEqual(report["users"]["regular"][0]["name"], "Guest")


class TestInstalledAppsAudit(unittest.TestCase):
    def test_linux_collects_dpkg_and_flatpak_without_source_or_scope(self):
        audit = InstalledApps()
        audit.system = "Linux"

        def fake_which(cmd):
            return f"/usr/bin/{cmd}" if cmd in ("dpkg-query", "flatpak") else None

        def fake_run(args):
            if args[0] == "dpkg-query":
                return "bash\t5.2\n"
            if args[0] == "flatpak":
                return "org.mozilla.firefox\t130.0\n"
            return None

        with (
            patch("shutil.which", side_effect=fake_which),
            patch.object(audit, "_run", side_effect=fake_run),
        ):
            report = audit.audit()

        self.assertEqual(report["count"], 2)
        for app in report["applications"]:
            self.assertNotIn("source", app)
            self.assertNotIn("scope", app)

    def test_linux_collects_pacman_and_snap(self):
        audit = InstalledApps()
        audit.system = "Linux"

        def fake_which(cmd):
            return f"/usr/bin/{cmd}" if cmd in ("pacman", "snap") else None

        def fake_run(args):
            if args[0] == "pacman":
                return "git 2.47.0-1\n"
            if args[0] == "snap":
                return "Name  Version  Rev  Tracking\ncode  1.95.0  100  latest/stable\n"
            return None

        with (
            patch("shutil.which", side_effect=fake_which),
            patch.object(audit, "_run", side_effect=fake_run),
        ):
            report = audit.audit()

        names = [app["name"] for app in report["applications"]]
        self.assertEqual(names, ["code", "git"])


class TestNetworkSettingsAudit(unittest.TestCase):
    def test_per_adapter_dns_and_dhcp_do_not_leak_and_filter_fec0_dns(self):
        audit = NetworkSettings()
        audit.system = "Windows"

        fake_addrs = {
            "Ethernet": [
                types.SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                )
            ],
            "Loopback": [
                types.SimpleNamespace(
                    family=socket.AF_INET,
                    address="127.0.0.1",
                    netmask="255.0.0.0",
                )
            ],
        }
        fake_stats = {
            "Ethernet": types.SimpleNamespace(isup=True),
            "Loopback": types.SimpleNamespace(isup=True),
        }
        ps_payload = {
            "routes": [{"InterfaceAlias": "Ethernet", "NextHop": "192.168.1.1"}],
            "dns": [
                {
                    "InterfaceAlias": "Ethernet",
                    "ServerAddresses": [
                        "1.1.1.1",
                        "fec0:0:0:ffff::1",
                        "fec0:0:0:ffff::2",
                        "fec0:0:0:ffff::3",
                    ],
                },
                {
                    "InterfaceAlias": "Loopback",
                    "ServerAddresses": ["fec0:0:0:ffff::1"],
                },
            ],
            "dhcp": [
                {
                    "Alias": "Ethernet",
                    "Description": "Intel NIC",
                    "DHCPServer": "192.168.1.1",
                }
            ],
            "wifi": [],
        }

        with (
            patch("psutil.net_if_addrs", return_value=fake_addrs),
            patch("psutil.net_if_stats", return_value=fake_stats),
            patch("secuditor.network_settings.run_powershell", return_value=ps_payload),
            patch("secuditor.network_settings.run_command_result", return_value=(0, "", "")),
        ):
            report = audit.audit()

        by_name = {item["name"]: item for item in report["adapters"]}
        self.assertEqual(by_name["Ethernet"]["gateways"], ["192.168.1.1"])
        self.assertEqual(by_name["Ethernet"]["dns_servers"], ["1.1.1.1"])
        self.assertEqual(by_name["Ethernet"]["dhcp_servers"], {"Intel NIC": ["192.168.1.1"]})
        self.assertEqual(by_name["Loopback"]["dns_servers"], [])
        self.assertEqual(by_name["Loopback"]["dhcp_servers"], {})

    def test_rejects_placeholder_macs_and_reports_wifi_location_block(self):
        self.assertEqual(NetworkSettings().timeout, 8.0)
        self.assertIsNone(NetworkSettings._normalize_mac("00:00:00:00:00:00"))
        self.assertIsNone(NetworkSettings._normalize_mac("FF-FF-FF-FF-FF-FF"))
        self.assertEqual(
            NetworkSettings._normalize_mac("AA-BB-CC-DD-EE-FF"),
            "aa:bb:cc:dd:ee:ff",
        )

        audit = NetworkSettings()
        audit.system = "Windows"
        with patch(
            "secuditor.network_settings.run_command_result",
            return_value=(1, "", "Location permission is required"),
        ):
            wifi = audit._wifi_info(ps_wifi=[{"Name": "Wi-Fi", "Status": "Up"}])

        self.assertEqual(
            wifi,
            [{
                "name": "Wi-Fi",
                "status": "up",
                "ssid": None,
                "note": "Location permission required",
            }],
        )


class TestPasswordPolicyAudit(unittest.TestCase):
    def test_windows_net_accounts_fallback_parses_none_history_and_omits_source(self):
        audit = PasswordPolicy()
        audit.system = "Windows"
        report = audit._base_report()

        sample_output = (
            "Minimum password length: 12\n"
            "Maximum password age (days): 90\n"
            "Minimum password age (days): 1\n"
            "Length of password history maintained: None\n"
            "Lockout threshold: 5\n"
            "Lockout duration (minutes): 15\n"
            "Lockout observation window (minutes): 15\n"
        )

        with (
            patch.object(audit, "_windows_netapi_policy", return_value=False),
            patch.object(audit, "_run", side_effect=[sample_output, None]),
        ):
            audit._audit_windows(report)

        self.assertEqual(report["settings"]["minimum_length"]["value"], 12)
        self.assertEqual(report["settings"]["password_history"]["value"], "none")
        self.assertEqual(report["settings"]["lockout_threshold"]["value"], 5)
        for setting in report["settings"].values():
            self.assertNotIn("source", setting)

    def test_linux_faillock_and_chage_parsing(self):
        audit = PasswordPolicy()
        audit.system = "Linux"
        report = audit._base_report()

        fake_files = {
            "/etc/login.defs": "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n",
            "/etc/security/pwquality.conf": "minlen = 14\ndcredit = -1\n",
            "/etc/security/faillock.conf": "deny = 5\nunlock_time = 900\nfail_interval = 600\n",
        }
        real_open = builtins.open

        def fake_open(path, *args, **kwargs):
            if path in fake_files:
                return io.StringIO(fake_files[path])
            if path.startswith("/etc/"):
                raise OSError("missing")
            return real_open(path, *args, **kwargs)

        def fake_run(args):
            if args[0].endswith("chage"):
                return "Last password change\t\t: Nov 01, 2026\nAccount expires\t\t\t: never\n"
            if args[0].endswith("passwd"):
                return "alice P 11/01/2026 1 90 7 -1\n"
            return None

        with (
            patch("builtins.open", side_effect=fake_open),
            patch("shutil.which", side_effect=lambda c: f"/usr/bin/{c}"),
            patch("getpass.getuser", return_value="alice"),
            patch.object(audit, "_run", side_effect=fake_run),
        ):
            audit._audit_linux(report)

        self.assertEqual(report["settings"]["minimum_length"]["value"], 14)
        self.assertEqual(report["settings"]["lockout_threshold"]["value"], 5)
        self.assertEqual(report["settings"]["lockout_duration_minutes"]["value"], 15)
        self.assertEqual(report["settings"]["lockout_reset_minutes"]["value"], 10)
        self.assertEqual(report["settings"]["account_expiration"]["value"], "never")
        self.assertIs(report["settings"]["password_required"]["value"], True)


class TestSystemSettingsAudit(unittest.TestCase):
    def test_hardware_report_excludes_network_adapters_and_deduplicates(self):
        audit = SystemSettings()
        audit.system = "Windows"

        payload = {
            "Printers": ["Microsoft Print to PDF", "Microsoft Print to PDF"],
            "Cameras": ["Integrated Webcam"],
            "Bluetooth Devices": [],
            "USB Devices": None,
            "Biometric Devices": [],
        }

        with (
            patch("secuditor.system_settings.find_powershell", return_value="powershell.exe"),
            patch("secuditor.system_settings.run_powershell", return_value=payload) as mock_ps,
        ):
            report = audit.get_hardware_report()

        self.assertEqual(mock_ps.call_count, 1)
        self.assertNotIn("Network Adapters", report)
        self.assertIn("Hardware", report)
        self.assertEqual(report["Hardware"]["Printers"]["devices"], ["Microsoft Print to PDF"])
        self.assertEqual(report["Hardware"]["Cameras"]["devices"], ["Integrated Webcam"])
        self.assertEqual(report["Hardware"]["USB Devices"]["devices"], [])

    def test_windows_11_os_name_detection(self):
        audit = SystemSettings()
        audit.system = "Windows"

        reg = {
            "ProductName": "Windows 10 Pro",
            "EditionID": "Professional",
            "DisplayVersion": "24H2",
            "CurrentBuildNumber": "26100",
        }
        with patch(
            "secuditor.system_settings.read_registry_value",
            side_effect=lambda _r, _p, name: reg.get(name),
        ):
            self.assertEqual(audit._windows_os_name(), "Windows 11 Pro (24H2)")


if __name__ == "__main__":
    unittest.main()
