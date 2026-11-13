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


class TestInstalledAppsAudit(unittest.TestCase):
    def test_linux_collects_dpkg_and_flatpak_without_source_or_scope(self):
        audit = InstalledApps()
        audit.system = "Linux"

        def fake_run(args):
            if args[0] == "dpkg-query":
                return "bash\t5.2\n"
            if args[0] == "flatpak":
                return "org.mozilla.firefox\t130.0\n"
            return None

        with patch.object(audit, "_run", side_effect=fake_run):
            report = audit.audit()

        self.assertEqual(report["count"], 2)
        for app in report["applications"]:
            self.assertNotIn("source", app)
            self.assertNotIn("scope", app)


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
        ps_dns = [
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
        ]

        with (
            patch("psutil.net_if_addrs", return_value=fake_addrs),
            patch("psutil.net_if_stats", return_value=fake_stats),
            patch.object(audit, "_default_gateways", return_value={"Ethernet": ["192.168.1.1"]}),
            patch("secuditor.network_settings.run_powershell", side_effect=[
                ps_dns,
                [{"Alias": "Ethernet", "Description": "Intel NIC", "DHCPServer": "192.168.1.1"}],
            ]),
            patch.object(audit, "_wifi_info", return_value=None),
        ):
            report = audit.audit()

        by_name = {item["name"]: item for item in report["adapters"]}
        self.assertEqual(by_name["Ethernet"]["dns_servers"], ["1.1.1.1"])
        self.assertEqual(by_name["Ethernet"]["dhcp_servers"], {"Intel NIC": ["192.168.1.1"]})
        self.assertEqual(by_name["Loopback"]["dns_servers"], [])
        self.assertEqual(by_name["Loopback"]["dhcp_servers"], {})


class TestPasswordPolicyAudit(unittest.TestCase):
    def test_windows_net_accounts_parses_none_history_and_omits_source(self):
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

        with patch.object(audit, "_run", side_effect=[sample_output, None]):
            audit._audit_windows(report)

        self.assertEqual(report["settings"]["minimum_length"]["value"], 12)
        self.assertEqual(report["settings"]["password_history"]["value"], "none")
        self.assertEqual(report["settings"]["lockout_threshold"]["value"], 5)
        for setting in report["settings"].values():
            self.assertNotIn("source", setting)


class TestSystemSettingsAudit(unittest.TestCase):
    def test_hardware_report_excludes_network_adapters(self):
        audit = SystemSettings()
        audit.system = "Windows"

        payload = {
            "Printers": "Microsoft Print to PDF",
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


if __name__ == "__main__":
    unittest.main()
