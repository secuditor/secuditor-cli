import builtins
from datetime import datetime, timedelta, timezone
import io
import os
import socket
import ssl
import types
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from secuditor import (
    DomainAudit,
    GatewayDiscovery,
    InstalledApps,
    NetworkSettings,
    PasswordPolicy,
    RemoteAccessSettings,
    SSLInterception,
    SecurityAudit,
    SensitivePaths,
    SharedFolders,
    SuspiciousProcesses,
    SuspiciousProxy,
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
            patch.object(audit, "_windows_users_netapi", return_value=False),
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

        with (
            patch.object(audit, "_is_windows_domain_controller", return_value=False),
            patch.object(audit, "_windows_users_netapi", return_value=False),
            patch.object(
                audit,
                "_powershell",
                side_effect=[users_payload, admins_payload],
            ),
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

    def test_windows_users_skipped_on_domain_controller(self):
        audit = DomainAudit()
        audit.system = "Windows"
        report = audit._base_report()

        with (
            patch.object(audit, "_is_windows_domain_controller", return_value=True),
            patch.object(audit, "_windows_users_netapi") as mock_netapi,
            patch.object(audit, "_powershell") as mock_ps,
        ):
            audit._windows_users(report)

        self.assertEqual(report["users"]["status"], "not_applicable")
        mock_netapi.assert_not_called()
        mock_ps.assert_not_called()

    def test_ntlm_verdict_hardened_rules(self):
        # NoLMHash == 0 always flagged first
        self.assertIn(
            "Warning",
            DomainAudit._ntlm_verdict(5, 0, 2, restrict_sending=2, restrict_receiving=2),
        )
        # Blocking requires BOTH sending and receiving == 2
        self.assertIn(
            "Critical",
            DomainAudit._ntlm_verdict(2, 1, None, restrict_sending=2, restrict_receiving=0),
        )
        self.assertIn(
            "Strong",
            DomainAudit._ntlm_verdict(2, 1, 2, restrict_sending=2, restrict_receiving=2),
        )
        # Level 2 is Weak, Level 4 is Moderate, Level 5 is Strong
        self.assertIn("Critical", DomainAudit._ntlm_verdict(2, 1, None))
        self.assertIn("Moderate", DomainAudit._ntlm_verdict(4, 1, None))
        self.assertIn("Strong", DomainAudit._ntlm_verdict(5, 1, 2))


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
            patch.object(audit, "_windows_hello_pin", return_value="Enabled (PIN, Fingerprint)"),
            patch.object(audit, "_windows_is_admin", return_value=False),
            patch.object(audit, "_run", side_effect=[sample_output, None]),
        ):
            audit._audit_windows(report)

        self.assertEqual(report["settings"]["minimum_length"]["value"], 12)
        self.assertEqual(report["settings"]["password_history"]["value"], "none")
        self.assertEqual(report["settings"]["lockout_threshold"]["value"], 5)
        self.assertEqual(
            report["settings"]["pin_or_biometrics"]["value"],
            "Enabled (PIN, Fingerprint)",
        )
        for setting in report["settings"].values():
            self.assertNotIn("source", setting)

    def test_windows_hello_pin_and_domain_complexity_helpers(self):
        audit = PasswordPolicy()
        audit.system = "Windows"
        sid = "S-1-5-21-100-1001"
        reg_values = {
            (
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication"
                rf"\Credential Providers\{{D6886603-9D2F-4EB2-B667-1971041FA96B}}\{sid}",
                "LogonCredsAvailable",
            ): 1,
            (
                "HKLM",
                rf"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\{sid}",
                "EnrolledFactors",
            ): 0x0A,  # Face (0x02) + Fingerprint (0x08)
        }
        with (
            patch.object(audit, "_windows_current_user_sid", return_value=sid),
            patch(
                "secuditor.password_policy.read_registry_value",
                side_effect=lambda r, p, n: reg_values.get((r, p, n)),
            ),
        ):
            self.assertEqual(
                audit._windows_hello_pin(),
                "Enabled (PIN, Face, Fingerprint)",
            )

        with patch(
            "secuditor.password_policy.run_powershell",
            return_value="1",
        ):
            self.assertIs(audit._windows_domain_complexity(), True)

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

    def test_parse_windows_hardware_cim_filters_virtual_gpus_and_maps_memory(self):
        payload = {
            "bios": "F.24",
            "memory": [
                {"ConfiguredClockSpeed": 4800, "SMBIOSMemoryType": 34},
                {"ConfiguredClockSpeed": 4800, "SMBIOSMemoryType": 34},
            ],
            "gpus": [
                {
                    "AdapterCompatibility": "Microsoft",
                    "Name": "Microsoft Basic Display Adapter",
                },
                {
                    "AdapterCompatibility": "NVIDIA",
                    "Name": "NVIDIA GeForce RTX 4070",
                },
            ],
        }
        parsed = SystemSettings._parse_windows_hardware_cim(payload)
        self.assertEqual(parsed["firmware_version"], "F.24")
        self.assertEqual(parsed["memory_type"], "DDR5")
        self.assertEqual(parsed["memory_speed"], "4800 MHz")
        self.assertEqual(parsed["gpu_manufacturer"], "NVIDIA")
        self.assertEqual(parsed["gpu_model"], "NVIDIA GeForce RTX 4070")


class TestSSLInterceptionAudit(unittest.TestCase):
    @staticmethod
    def _build_test_der(issuer_org: str, san_dns: str) -> bytes:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, san_dns),
        ])
        issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{issuer_org} Root CA"),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san_dns)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_public_trusted_certificate_not_detected(self):
        der = self._build_test_der("Google Trust Services", "*.google.com")
        audit = SSLInterception()

        with (
            patch.object(
                audit,
                "_fetch_peer_cert",
                return_value=(der, "TLSv1.3", "142.250.1.1"),
            ),
            patch.object(audit, "_verify_public_chain", return_value=True) as mock_pub,
        ):
            result = audit.audit("www.google.com", 443)

        self.assertEqual(result["verdict"], "Not Detected")
        self.assertFalse(result["ssl_interception_detected"])
        self.assertEqual(result["key_type"], "ECC")
        self.assertEqual(result["key_bits"], 256)
        self.assertEqual(result["tls_version"], "TLSv1.3")
        mock_pub.assert_called_once()
        self.assertEqual(mock_pub.call_args.kwargs["connect_host"], "142.250.1.1")
        self.assertEqual(
            mock_pub.call_args.kwargs["expected_fingerprint"],
            result["fingerprint_sha256"],
        )

    def test_stage2_fingerprint_mismatch_and_unavailable_public_ca_returns_unknown(self):
        der_stage1 = self._build_test_der("Google Trust Services", "*.google.com")
        der_stage2 = self._build_test_der("Google Trust Services", "*.google.com")
        audit = SSLInterception()

        with patch.object(
            audit,
            "_fetch_peer_cert",
            side_effect=[
                (der_stage1, "TLSv1.3", "142.250.1.1"),
                (der_stage2, "TLSv1.3", "142.250.1.1"),
            ],
        ):
            result = audit.audit("www.google.com", 443)

        # Even though issuer matches a public CA name, Stage-1/Stage-2 mismatch
        # must stay inconclusive (Unknown) rather than trusting name matching.
        self.assertEqual(result["verdict"], "Unknown")
        self.assertFalse(result["ssl_interception_detected"])
        self.assertEqual(
            result["interception_reason"],
            "Public CA verification unavailable",
        )

    def test_enterprise_firewall_issuer_classified_as_likely_legitimate(self):
        der = self._build_test_der("Zscaler", "www.google.com")
        audit = SSLInterception()

        with (
            patch.object(
                audit,
                "_fetch_peer_cert",
                return_value=(der, "TLSv1.3", "10.0.0.1"),
            ),
            patch.object(audit, "_verify_public_chain", return_value=False),
        ):
            result = audit.audit("www.google.com", 443)

        self.assertEqual(result["verdict"], "Likely Legitimate")
        self.assertTrue(result["ssl_interception_detected"])
        self.assertTrue(result["interception_legit"])
        self.assertIn("Zscaler", result["interception_reason"])
        self.assertIn("name match", result["interception_reason"])

    def test_untrusted_certificate_classified_as_suspicious(self):
        der = self._build_test_der("Unknown Corp", "www.google.com")
        audit = SSLInterception()

        def fake_fetch(_host, _port, ctx, connect_host=None):
            if ctx.verify_mode == ssl.CERT_REQUIRED:
                raise ssl.SSLCertVerificationError("self-signed certificate")
            return der, "TLSv1.3", "10.0.0.2"

        with patch.object(audit, "_fetch_peer_cert", side_effect=fake_fetch):
            result = audit.audit("www.google.com", 443)

        self.assertEqual(result["verdict"], "Suspicious")
        self.assertTrue(result["ssl_interception_detected"])
        self.assertFalse(result["interception_legit"])


class TestEndpointSecurityAudit(unittest.TestCase):
    def test_windows_audit_decodes_av_bitlocker_shell_and_hvci(self):
        audit = SecurityAudit()
        audit.system = "Windows"

        ps_bundle = {
            "defender": {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
            },
            "av": [
                {"displayName": "Windows Defender", "productState": 397568},
                {"displayName": "CrowdStrike Falcon", "productState": 266240},
            ],
            "fw": [],
            "dep": 3,
            "dg_running": [1],
            "exec_policy": "RemoteSigned",
            "bitlocker": {"source": "shell", "values": [1]},
            "sb_wmi": True,
        }
        reg_map = {
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled"): 1,
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"): 1,
            ("HKLM", r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start"): 4,
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"): 255,
        }

        with (
            patch.object(audit, "_windows_ps_bundle", return_value=ps_bundle),
            patch.object(audit, "_windows_firewall_managed_by", return_value={"managed": False, "product_name": None}),
            patch.object(audit, "_windows_firewall_state", return_value="On"),
            patch.object(audit, "_windows_auto_screen_lock", return_value="Default (Sleep lock enabled)"),
            patch.object(audit, "_windows_macro_policy", return_value=["Disabled (With notification)"]),
            patch.object(audit, "_windows_defender_asr", return_value="Not Configured"),
            patch.object(audit, "_windows_uac", return_value="Prompt for consent (Non-Windows binaries)"),
            patch.object(audit, "_windows_anonymous_access", return_value="Restricted"),
            patch.object(audit, "_windows_efs_scan", return_value="No encrypted files"),
            patch.object(audit, "_windows_system_restore", return_value="Enabled"),
            patch("secuditor.endpoint_security.read_registry_value", side_effect=lambda r, p, n: reg_map.get((r, p, n))),
        ):
            report = audit.audit()

        checks = report["checks"]
        self.assertEqual(checks["Windows Defender"], ["Windows Defender (Active)"])
        self.assertEqual(checks["Endpoint Protection"], ["CrowdStrike Falcon (Active)"])
        self.assertEqual(checks["Host-based Firewall"], "Windows Firewall (On)")
        self.assertEqual(checks["Core Isolation"], "Disabled (Configured, not running)")
        self.assertEqual(checks["Data Execution Prevention"], "Enabled (Opt Out)")
        self.assertEqual(checks["BitLocker Drive Encryption"], "Enabled")
        self.assertEqual(checks["UEFI Secure Boot"], "Enabled")
        self.assertEqual(checks["Removable Storage"], "Disabled")
        self.assertEqual(checks["USB AutoRun"], "Disabled")

    def test_windows_defender_inactive_without_rtp_and_3p_firewall_via_sc2(self):
        audit = SecurityAudit()
        audit.system = "Windows"

        ps_bundle = {
            "defender": {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": False,
            },
            "av": [],
            "fw": [
                {"displayName": "ESET Firewall", "productState": 266240},
            ],
        }

        with (
            patch.object(audit, "_windows_ps_bundle", return_value=ps_bundle),
            patch.object(audit, "_windows_auto_screen_lock", return_value="Default"),
            patch.object(audit, "_windows_macro_policy", return_value=["Default"]),
            patch.object(audit, "_windows_defender_asr", return_value="Not Configured"),
            patch.object(audit, "_windows_uac", return_value="Default"),
            patch.object(audit, "_windows_anonymous_access", return_value="Restricted"),
            patch.object(audit, "_windows_efs_scan", return_value="No encrypted files"),
            patch.object(audit, "_windows_system_restore", return_value="Enabled"),
            patch("secuditor.endpoint_security.read_registry_value", return_value=None),
        ):
            report = audit.audit()

        checks = report["checks"]
        self.assertEqual(checks["Windows Defender"], ["Windows Defender (Inactive)"])
        self.assertEqual(checks["Host-based Firewall"], "ESET Firewall (On)")

    def test_windows_firewall_state_reports_off_when_mpssvc_stopped(self):
        audit = SecurityAudit()
        audit.system = "Windows"
        with patch.object(audit, "_run", return_value="STATE              : 1  STOPPED"):
            self.assertEqual(audit._windows_firewall_state(), "Off")

    def test_linux_audit_reports_mac_firewall_aslr_and_luks(self):
        audit = SecurityAudit()
        audit.system = "Linux"

        fake_files = {
            "/sys/module/apparmor/parameters/enabled": "Y\n",
            "/proc/sys/kernel/randomize_va_space": "2\n",
        }
        real_open = builtins.open

        def fake_open(path, *args, **kwargs):
            if path in fake_files:
                return io.StringIO(fake_files[path])
            return real_open(path, *args, **kwargs)

        def fake_run(cmd):
            if cmd[0] == "ufw":
                return "Status: active\n"
            if cmd[0] == "lsblk":
                return '{"blockdevices":[{"name":"sda2","type":"crypt","fstype":"crypto_LUKS"}]}'
            return None

        with (
            patch("os.path.isfile", side_effect=lambda p: p in fake_files),
            patch("os.path.isdir", return_value=False),
            patch("builtins.open", side_effect=fake_open),
            patch("shutil.which", side_effect=lambda c: f"/usr/bin/{c}" if c in ("ufw", "lsblk", "timeshift") else None),
            patch("psutil.process_iter", return_value=[]),
            patch("glob.glob", return_value=[]),
            patch.object(audit, "_run", side_effect=fake_run),
        ):
            report = audit.audit()

        checks = report["checks"]
        self.assertEqual(checks["Mandatory Access Control"], "AppArmor (Enabled)")
        self.assertEqual(checks["Host-based Firewall"], "UFW (On)")
        self.assertEqual(checks["Kernel Hardening (ASLR)"], "Enabled (Full ASLR)")
        self.assertEqual(checks["Disk Encryption"], "Enabled (LUKS/dm-crypt)")
        self.assertEqual(checks["UEFI Secure Boot"], "Unsupported")
        self.assertEqual(checks["System Snapshots"], "Available (Timeshift)")


class TestSuspiciousProxyAudit(unittest.TestCase):
    def test_windows_no_proxy_detected(self):
        audit = SuspiciousProxy()
        audit.system = "Windows"

        with (
            patch.object(
                audit,
                "_collect_wininet",
                return_value={
                    "manual": None,
                    "raw_manual": "",
                    "pac": None,
                    "autodetect": False,
                    "policy_enforced": False,
                },
            ),
            patch.object(audit, "_collect_winhttp", return_value=("Direct Access", "")),
            patch.object(audit, "_collect_env_proxies", return_value={}),
            patch.object(audit, "_collect_portproxy_rules", return_value=[]),
        ):
            report = audit.audit()

        self.assertEqual(report["analysis"]["verdict"], "Not Detected")
        self.assertFalse(report["analysis"]["proxy_detected"])
        self.assertEqual(report["configuration"]["winhttp_proxy"], "Direct Access")

    def test_windows_tunnel_listener_and_insecure_pac_flagged_suspicious(self):
        audit = SuspiciousProxy()
        audit.system = "Windows"

        fake_listener = {
            "pid": 4321,
            "name": "chisel.exe",
            "path": r"C:\Users\alice\Downloads\chisel.exe",
            "signature": "NotSigned",
            "signer": "",
        }
        with (
            patch.object(
                audit,
                "_collect_wininet",
                return_value={
                    "manual": "socks=127.0.0.1:9050",
                    "raw_manual": "socks=127.0.0.1:9050",
                    "pac": "http://198.51.100.5/proxy.pac",
                    "autodetect": False,
                    "policy_enforced": False,
                },
            ),
            patch.object(audit, "_collect_winhttp", return_value=("Direct Access", "")),
            patch.object(audit, "_collect_env_proxies", return_value={}),
            patch.object(audit, "_collect_portproxy_rules", return_value=["0.0.0.0:8080 -> 10.0.0.5:80"]),
            patch.object(audit, "_find_listener_for_port", return_value=fake_listener),
        ):
            report = audit.audit()

        self.assertEqual(report["analysis"]["verdict"], "Suspicious")
        self.assertTrue(report["analysis"]["proxy_detected"])
        joined = " | ".join(report["analysis"]["triggers"])
        self.assertIn("SOCKS/Tor", joined)
        self.assertIn("Tunnel/MITM tool", joined)
        self.assertIn("suspicious path", joined)
        self.assertIn("Unencrypted HTTP PAC URL", joined)
        self.assertIn("IP-literal PAC host", joined)
        self.assertIn("Active netsh portproxy rule", joined)

    def test_macos_scutil_proxy_parsing(self):
        audit = SuspiciousProxy()
        audit.system = "Darwin"

        scutil_output = (
            "<dictionary> {\n"
            "  HTTPEnable : 1\n"
            "  HTTPProxy : 93.184.216.34\n"
            "  HTTPPort : 8080\n"
            "  ProxyAutoDiscoveryEnable : 0\n"
            "}\n"
        )
        with (
            patch.object(audit, "_run", return_value=scutil_output),
            patch.object(audit, "_collect_env_proxies", return_value={}),
        ):
            report = audit.audit()

        self.assertEqual(report["analysis"]["verdict"], "Suspicious")
        self.assertIn("Public IP proxy target (93.184.216.34)", report["analysis"]["triggers"])
        self.assertNotIn("winhttp_proxy", report["configuration"])


class TestRemoteAccessAudit(unittest.TestCase):
    def test_windows_audit_evaluates_rdp_smb_winrm_dcom_and_bluetooth(self):
        audit = RemoteAccessSettings()
        audit.system = "Windows"

        ps_bundle = {
            "fw_profiles": [True, True, True],
            "winrm_listeners": {"ok": True, "keys": ["Transport=HTTP"]},
            "smb2": {
                "Service": {"Status": "Running", "StartType": "Automatic"},
                "Config": {
                    "EnableSMB2Protocol": True,
                    "RequireSecuritySignature": True,
                    "EncryptData": False,
                    "RejectUnencryptedAccess": True,
                    "EnableStrictNameChecking": True,
                    "EnableAuthenticateUserSharing": False,
                    "NullSessionShares": [],
                },
                "RestrictNullSessAccess": 1,
            },
            "rsync": None,
            "upnp": {"State": "Stopped", "StartMode": "Manual"},
            "bluetooth": {
                "QuerySucceeded": True,
                "Devices": [
                    {
                        "Status": "OK",
                        "InstanceId": "USB\\VID_8087&PID_0029\\5&1",
                        "Present": True,
                        "ProblemCode": None,
                        "DriverIsSigned": True,
                    }
                ],
            },
        }
        reg_map = {
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"): 0,
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication"): 1,
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "MinEncryptionLevel"): 3,
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp"): 0,
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa\pku2u", "AllowOnlineID"): 0,
            ("HKLM", r"SOFTWARE\Microsoft\Ole", "EnableDCOM"): "Y",
            ("HKLM", r"SOFTWARE\Microsoft\Ole", "LegacyAuthenticationLevel"): 5,
            ("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"): 0,
            ("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"): 4,
        }

        def fake_run_raw(args):
            svc = args[2] if len(args) > 2 else ""
            if svc == "RemoteRegistry":
                return "SERVICE_NAME: RemoteRegistry\nSTART_TYPE : 4 DISABLED"
            if svc == "WinRM":
                return "SERVICE_NAME: WinRM\nSTART_TYPE : 4 DISABLED"
            if svc == "Spooler":
                return "SERVICE_NAME: Spooler\nSTATE : 1 STOPPED"
            return ""

        with (
            patch.object(audit, "_windows_ps_bundle", return_value=ps_bundle),
            patch.object(audit, "_windows_is_admin", return_value=False),
            patch.object(audit, "_windows_os_build", return_value=22631),
            patch.object(audit, "_windows_winrm_ports", return_value=[]),
            patch.object(audit, "_windows_ftp_service", return_value="Not Detected"),
            patch.object(
                audit,
                "_query_bluetooth_win32_state",
                return_value={
                    "active_radios": 1,
                    "connectable": True,
                    "discoverable": False,
                    "connected_count": 1,
                    "paired_count": 1,
                    "unauthenticated_connected": 0,
                },
            ),
            patch.object(
                audit,
                "_query_bluetooth_exposure_extras",
                return_value={
                    "nearby_sharing_everyone": False,
                    "pan_active": False,
                    "file_transfer_active": False,
                    "policy_hardened": True,
                },
            ),
            patch.object(audit, "_run_raw", side_effect=fake_run_raw),
            patch.object(audit, "_run", return_value="   NetBIOS over Tcpip. . . . . . . . : Disabled"),
            patch("secuditor.remote_access.read_registry_value", side_effect=lambda r, p, n: reg_map.get((r, p, n))),
        ):
            report = audit.audit()

        checks = report["checks"]
        self.assertEqual(checks["Remote Desktop"], "Enabled, Low Risk (Default settings)")
        self.assertEqual(checks["Remote Registry"], "Disabled")
        self.assertEqual(checks["Remote Assistance"], "Disabled")
        self.assertEqual(checks["WinRM"], "Disabled")
        self.assertEqual(checks["PowerShell Remoting"], "Disabled")
        self.assertEqual(checks["SMB1"], "Disabled")
        self.assertEqual(checks["SMB2"], "Enabled, Low Risk (Signing/Encryption enforced)")
        self.assertEqual(checks["PKU2U Authentication"], "Disabled")
        self.assertEqual(checks["DCOM"], "Enabled, Low Risk (Secured authentication)")
        self.assertEqual(checks["NetBIOS"], "Disabled")
        self.assertEqual(checks["UPnPHost"], "Stopped")
        self.assertIn("Enabled, Low Risk", checks["Bluetooth"])

    def test_linux_audit_detects_ssh_root_login_cups_and_bluetooth(self):
        audit = RemoteAccessSettings()
        audit.system = "Linux"

        with (
            patch.object(
                audit,
                "_listening_ports_and_addrs",
                return_value=({22: {"0.0.0.0"}, 631: {"127.0.0.1"}}, set()),
            ),
            patch("psutil.process_iter", return_value=[]),
            patch.object(
                audit,
                "_parse_sshd_config",
                return_value={"permitrootlogin": "yes"},
            ),
            patch("shutil.which", side_effect=lambda c: f"/usr/bin/{c}" if c == "bluetoothctl" else None),
            patch.object(audit, "_run", return_value="Controller AA:BB\n\tPowered: yes\n\tDiscoverable: yes\n"),
        ):
            report = audit.audit()

        checks = report["checks"]
        self.assertIn("High Risk", checks["SSH Service"])
        self.assertEqual(checks["Print Service (CUPS)"], "Enabled, Low Risk (Loopback only)")
        self.assertEqual(checks["Bluetooth"], "Enabled, Exposure Detected (Discoverable)")


class TestSharedFoldersAudit(unittest.TestCase):
    def test_windows_shares_skips_admin_ipc_and_counts_exposed(self):
        audit = SharedFolders()
        audit.system = "Windows"

        raw_shares = [
            {"Name": "ADMIN$", "Path": r"C:\Windows", "Description": "Remote Admin"},
            {"Name": "IPC$", "Path": "", "Description": "Remote IPC"},
            {"Name": "C$", "Path": "C:\\", "Description": "Default share"},
            {"Name": "PublicDocs", "Path": r"D:\PublicDocs", "Description": "Team docs"},
        ]

        def fake_dacl(path):
            if path == r"D:\PublicDocs":
                return ["Everyone: Read, Write"], True
            return ["BUILTIN\\Administrators: Full Control"], False

        with (
            patch.object(audit, "_windows_shares_netapi", return_value=raw_shares),
            patch.object(audit, "_windows_dacl_permissions", side_effect=fake_dacl),
        ):
            report = audit.audit()

        self.assertEqual(report["count"], 2)
        self.assertEqual(report["exposed_count"], 1)
        by_name = {s["name"]: s for s in report["shares"]}
        self.assertNotIn("ADMIN$", by_name)
        self.assertNotIn("IPC$", by_name)
        self.assertTrue(by_name["C$"]["admin_share"])
        self.assertTrue(by_name["PublicDocs"]["everyone_accessible"])

    def test_linux_parses_samba_and_nfs_exports(self):
        audit = SharedFolders()
        audit.system = "Linux"

        smb_conf = (
            "[global]\nworkgroup = WORKGROUP\n"
            "[shared]\npath = /srv/shared\ncomment = Team share\nguest ok = yes\nread only = no\n"
        )
        exports_txt = "/srv/nfs *(rw,sync,no_root_squash)\n"
        real_open = builtins.open

        def fake_open(path, *args, **kwargs):
            if path == "/etc/samba/smb.conf":
                return io.StringIO(smb_conf)
            if path == "/etc/exports":
                return io.StringIO(exports_txt)
            return real_open(path, *args, **kwargs)

        with (
            patch("shutil.which", return_value=None),
            patch("builtins.open", side_effect=fake_open),
            patch.object(audit, "_posix_path_permissions", return_value=(["POSIX mode: 0o755"], False)),
        ):
            report = audit.audit()

        self.assertEqual(report["count"], 2)
        self.assertEqual(report["exposed_count"], 2)
        protocols = {s["name"]: s["protocol"] for s in report["shares"]}
        self.assertEqual(protocols["shared"], "SMB")
        self.assertEqual(protocols["/srv/nfs"], "NFS")


class TestGatewayDiscoveryAudit(unittest.TestCase):
    def test_vendor_oui_virtual_mac_and_classification(self):
        audit = GatewayDiscovery()
        self.assertEqual(audit.lookup_vendor("90-6C-AC-11-22-33"), "Fortinet (Firewall)")
        self.assertEqual(audit.lookup_vendor("02:11:22:33:44:55"), "Virtual/Software MAC")
        self.assertEqual(
            audit.lookup_vendor("00:00:0C:AA:BB:CC", fingerprint_text="Cisco ASA"),
            "Cisco Systems (Firewall)",
        )
        self.assertEqual(
            audit.lookup_vendor("00:11:22:33:44:55", ping_reply="Reply from 192.168.1.1: bytes=32 time=1ms TTL=64"),
            "Likely Linux/Unix device",
        )

    def test_detect_gateway_device_offline_mocked(self):
        audit = GatewayDiscovery()
        audit.system = "Windows"

        with (
            patch.object(audit, "get_default_gateway", return_value={"IPv4": "192.168.1.1", "IPv6": None}),
            patch.object(audit, "ping_device", return_value="Reply from 192.168.1.1: bytes=32 time=1ms TTL=64"),
            patch.object(audit, "get_mac_from_arp", return_value="90:6c:ac:aa:bb:cc"),
            patch.object(audit, "check_http_access", return_value=("HTTPS Responding (Self-Signed/Untrusted Cert)", "FortiGate")),
            patch.object(audit, "_active_interface_info", return_value=("192.168.1.50", "192.168.1.0/24", "1500 bytes")),
            patch.object(audit, "detect_management_ports", return_value="HTTPS (443)"),
            patch.object(audit, "get_external_ip", return_value="93.184.216.34"),
            patch.object(audit, "get_proxy_configuration", return_value="No Proxy Detected"),
            patch.object(audit, "detect_vpn", return_value="Not Detected"),
        ):
            report = audit.audit()

        self.assertEqual(report["gateway"]["ip"], "192.168.1.1")
        self.assertEqual(report["gateway"]["vendor"], "Fortinet (Firewall)")
        self.assertEqual(report["gateway"]["network_cidr"], "192.168.1.0/24")
        self.assertEqual(report["gateway"]["mtu"], "1500 bytes")
        self.assertEqual(report["exposure"]["management_ports"], "HTTPS (443)")
        self.assertEqual(report["connectivity"]["nat"], "Detected")
        self.assertEqual(report["connectivity"]["public_ip"], "93.184.216.34")


class TestSensitivePathsAudit(unittest.TestCase):
    def test_classify_posix_permissions_and_rdp_inspection(self):
        import tempfile

        audit = SensitivePaths()
        audit.system = "Linux"

        with patch("os.lstat", return_value=types.SimpleNamespace(st_mode=0o100644)):
            lvl, lbl = audit.inspect_acl("/home/alice/.ssh/id_rsa")
            self.assertEqual(lvl, "exposed")
            self.assertIn("World-readable", lbl)
            risk, cat, _ = audit._classify_file("/home/alice/.ssh/id_rsa", lvl, lbl)
            self.assertEqual((risk, cat), ("High", "Credentials & Keys"))

        with patch("os.lstat", return_value=types.SimpleNamespace(st_mode=0o100640)):
            lvl, lbl = audit.inspect_acl("/home/alice/.aws/credentials")
            self.assertEqual(lvl, "shared")
            self.assertIn("Group-accessible", lbl)

        with patch("os.lstat", return_value=types.SimpleNamespace(st_mode=0o100600)):
            lvl, lbl = audit.inspect_acl("/home/alice/.env")
            self.assertEqual(lvl, "private")
            risk, cat, _ = audit._classify_file("/home/alice/.env", lvl, lbl)
            self.assertEqual((risk, cat), ("Medium", "Config & Secret"))

        with tempfile.TemporaryDirectory() as tmpdir:
            default_rdp = os.path.join(tmpdir, "Default.rdp")
            with open(default_rdp, "w", encoding="utf-8") as f:
                f.write("screen mode id:i:2\n")
            self.assertTrue(audit._inspect_rdp_file(default_rdp)["skip"])

            saved_rdp = os.path.join(tmpdir, "server.rdp")
            with open(saved_rdp, "w", encoding="utf-8") as f:
                f.write("full address:s:10.0.0.5\npassword 51:b:01000000\n")
            info = audit._inspect_rdp_file(saved_rdp)
            self.assertFalse(info["skip"])
            self.assertTrue(info["has_password"])
            self.assertEqual(info["note"], "Saved password")

    def test_search_for_copies_skips_dev_dirs_benign_files_and_ranks_findings(self):
        import tempfile

        audit = SensitivePaths()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "node_modules"))
            with open(os.path.join(tmpdir, "node_modules", "ignored.env"), "w", encoding="utf-8") as f:
                f.write("SECRET=1\n")
            with open(os.path.join(tmpdir, "thumbs.db"), "w", encoding="utf-8") as f:
                f.write("benign\n")
            env_path = os.path.join(tmpdir, "app.env")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write("KEY=1\n")
            rdp_path = os.path.join(tmpdir, "prod.rdp")
            with open(rdp_path, "w", encoding="utf-8") as f:
                f.write("full address:s:10.0.0.10\npassword 51:b:deadbeef\n")

            with (
                patch.object(audit, "check_sensitive_targets", return_value=[]),
                patch.object(audit, "inspect_acl", return_value=("private", "Private")),
            ):
                report = audit.audit(check_dirs=[tmpdir])

        self.assertEqual(report["summary"]["total_count"], 2)
        self.assertEqual(report["summary"]["high"], 1)
        self.assertEqual(report["summary"]["medium"], 1)
        self.assertEqual(report["findings"][0]["target"], rdp_path)
        self.assertEqual(report["findings"][0]["risk"], "High")
        self.assertEqual(report["findings"][1]["target"], env_path)
        self.assertEqual(report["findings"][1]["risk"], "Medium")

    def test_temp_db_noise_and_ephemeral_test_dirs_filtered(self):
        import tempfile

        audit = SensitivePaths()
        with tempfile.TemporaryDirectory() as root:
            temp_root = os.path.join(root, "Temp")
            os.makedirs(os.path.join(temp_root, "pytest-of-User", "pytest-1"))
            os.makedirs(os.path.join(temp_root, "tmp__zz6avo"))
            os.makedirs(os.path.join(temp_root, "AppCache"))

            # Ephemeral test dirs should be skipped completely
            with open(os.path.join(temp_root, "pytest-of-User", "pytest-1", "a.db"), "w") as f:
                f.write("x")
            with open(os.path.join(temp_root, "tmp__zz6avo", "b.db"), "w") as f:
                f.write("x")
            # Private .db in Temp should be skipped; Exposed .db in Temp MUST be kept
            priv_db = os.path.join(temp_root, "AppCache", "cache.db")
            exp_db = os.path.join(temp_root, "AppCache", "exposed.db")
            env_file = os.path.join(temp_root, "AppCache", "leaked.env")
            for p in (priv_db, exp_db, env_file):
                with open(p, "w") as f:
                    f.write("x")

            def fake_acl(path):
                if os.path.basename(path) == "exposed.db":
                    return "exposed", "Exposed: Everyone"
                return "private", "Private"

            with (
                patch.object(audit, "check_sensitive_targets", return_value=[]),
                patch.object(audit, "inspect_acl", side_effect=fake_acl),
            ):
                report = audit.audit(check_dirs=[temp_root])

        targets = [f["target"] for f in report["findings"]]
        self.assertEqual(len(targets), 2)
        self.assertIn(exp_db, targets)
        self.assertIn(env_file, targets)
        self.assertNotIn(priv_db, targets)


class TestSuspiciousProcessesAudit(unittest.TestCase):
    def test_windows_risk_threshold_60_and_tree_card_format(self):
        audit = SuspiciousProcesses()
        audit.system = "Windows"

        class FakeProc:
            def __init__(self, pid, name, cmdline, exe_path, parent_name=None):
                self.pid = pid
                self.info = {"pid": pid, "name": name, "cmdline": cmdline}
                self._exe = exe_path
                self._parent_name = parent_name

            def exe(self):
                return self._exe

            def parent(self):
                if not self._parent_name:
                    return None
                return types.SimpleNamespace(
                    name=lambda: self._parent_name,
                    create_time=lambda: 100.0,
                )

            def create_time(self):
                return 200.0

            def children(self):
                return []

            def memory_maps(self):
                return []

        bad_proc = FakeProc(
            pid=4321,
            name="svch0st.exe",
            cmdline=["svch0st.exe", "-enc", "SQBFAFgA"],
            exe_path=r"C:\Users\alice\Downloads\svch0st.exe",
        )
        benign_proc = FakeProc(
            pid=1000,
            name="notepad.exe",
            cmdline=["notepad.exe"],
            exe_path=r"C:\Windows\System32\notepad.exe",
        )

        with (
            patch("psutil.process_iter", return_value=[bad_proc, benign_proc]),
            patch("psutil.net_connections", return_value=[]),
            patch.object(
                audit,
                "_preload_windows_persistence",
                return_value=(set(), set(), set(), set(), set()),
            ),
            patch.object(
                audit,
                "_windows_file_attrs_and_drive",
                return_value=(False, False, "C:", False),
            ),
            patch.object(audit, "_windows_motw_zone", return_value="3"),
            patch.object(
                audit,
                "_batch_verify_signatures",
                return_value={
                    os.path.normcase(r"C:\Users\alice\Downloads\svch0st.exe"): (
                        "NotSigned",
                        "",
                    )
                },
            ),
            patch.object(audit, "_is_process_elevated", return_value=False),
            patch.object(audit, "_file_entropy", return_value=None),
        ):
            report = audit.audit()

        self.assertEqual(report["threshold"], 60)
        self.assertEqual(report["summary"]["flagged_count"], 1)
        self.assertEqual(report["summary"]["high"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["name"], "svch0st.exe")
        self.assertGreaterEqual(finding["risk"], 90)
        self.assertEqual(finding["risk_tier"], "High")

        rendered = SuspiciousProcesses.format_report(report)
        self.assertIn("Suspicious Processes Detected: 1  (High: 1)", rendered)
        self.assertIn(f"[ High | Risk {finding['risk']} ] svch0st.exe (PID: 4321)", rendered)
        self.assertIn("Path: C:\\Users\\alice\\Downloads\\svch0st.exe", rendered)
        self.assertIn("Findings:", rendered)

    def test_linux_deleted_root_binary_in_tmp_flagged_and_clean_format(self):
        audit = SuspiciousProcesses()
        audit.system = "Linux"

        class FakeLinuxProc:
            def __init__(self):
                self.pid = 7777
                self.info = {
                    "pid": 7777,
                    "name": "payload",
                    "cmdline": ["/tmp/payload", "bash", "-i"],
                }

            def exe(self):
                return "/tmp/payload (deleted)"

            def parent(self):
                return types.SimpleNamespace(name=lambda: "nginx")

            def children(self):
                return []

            def memory_maps(self):
                return []

            def uids(self):
                return types.SimpleNamespace(effective=0)

        with (
            patch("psutil.process_iter", return_value=[FakeLinuxProc()]),
            patch("psutil.net_connections", return_value=[]),
            patch.object(audit, "_preload_posix_persistence", return_value=set()),
            patch.object(audit, "_file_entropy", return_value=None),
        ):
            report = audit.audit()

        self.assertEqual(report["summary"]["flagged_count"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["name"], "payload")
        self.assertGreaterEqual(finding["risk"], 60)
        self.assertIn("Deleted executable on disk", finding["reasons"])
        self.assertIn("Root process running from suspicious location", finding["reasons"])

        self.assertEqual(
            SuspiciousProcesses.format_report({"findings": []}),
            "No suspicious activity detected",
        )


class TestSummaryReport(unittest.TestCase):
    def test_build_and_format_summary_report_windows_and_linux(self):
        from datetime import datetime
        from secuditor.summary_report import (
            build_summary_report,
            format_summary_report,
        )

        win_results = {
            "system_settings": {"system": {"hostname": "CORE-DEV64", "platform": "Windows"}},
            "endpoint_security": {
                "platform": "Windows",
                "hostname": "CORE-DEV64",
                "checks": {
                    "Windows Defender": ["Windows Defender (Inactive)"],
                    "Endpoint Protection": ["AVG Antivirus (Active)"],
                    "Host-based Firewall": "AVG Antivirus (On)",
                    "Auto Screen Lock": "Default (Sleep lock enabled)",
                    "UAC Elevation": "Prompt for consent (Non-Windows binaries)",
                    "Core Isolation": "Enabled",
                    "UEFI Secure Boot": "Enabled",
                    "System Restore": "Disabled",
                    "BitLocker Drive Encryption": "Disabled",
                },
            },
            "gateway_discovery": {
                "gateway": {"ip": "192.168.1.1", "vendor": "Fortinet (Firewall)"},
                "exposure": {"management_ports": "HTTPS (443)"},
            },
            "domain_settings": {
                "platform": "Windows",
                "affiliation": {"status": "detected", "value": {"type": "workgroup or standalone", "name": "WORKGROUP"}},
                "laps": {"status": "unknown", "value": None},
                "ntlm_policy": {"status": "detected", "value": {"verdict": "Moderate, NTLMv2 is used but not enforced"}},
            },
            "password_policy": {
                "settings": {
                    "minimum_length": {"value": 0, "status": "detected"},
                    "password_required": {"value": False, "status": "detected"},
                    "lockout_threshold": {"value": 10, "status": "detected"},
                }
            },
            "remote_access": {
                "platform": "Windows",
                "checks": {
                    "Bluetooth": "Disabled (Hardware disabled)",
                    "PowerShell Remoting": "Disabled",
                    "RPC Print Spooler": "Enabled, Low Risk (Restricted access)",
                    "SMB1": "Disabled",
                    "SMB2": "Enabled, Moderate Risk (Signing/Encryption not required)",
                    "FTP Service": "Not Detected",
                    "DCOM": "Enabled, Hardened by Patch",
                    "WinRM": "Enabled, Low Risk (No port listeners)",
                    "Remote Desktop": "Disabled",
                },
            },
            "shared_folders": {"count": 2, "exposed_count": 1},
            "sensitive_paths": {"summary": {"total_count": 2, "high": 0, "medium": 0, "low": 2}},
            "suspicious_proxy": {"analysis": {"verdict": "Not Detected"}},
            "ssl_interception": {"verdict": "Not Detected"},
            "suspicious_processes": {"summary": {"flagged_count": 1}},
        }

        summary = build_summary_report(
            win_results, timestamp=datetime(2026, 11, 27, 10, 35, 41)
        )
        self.assertEqual(summary["hostname"], "CORE-DEV64")
        self.assertEqual(summary["counts"]["fail"], 6)
        self.assertGreater(summary["counts"]["pass"], 15)

        by_elem = {r["element"]: r for r in summary["rows"]}
        self.assertEqual(by_elem["Endpoint Protection"]["result"], "Pass")
        self.assertEqual(by_elem["System Restore"]["result"], "Fail")
        self.assertIn("T1490", by_elem["System Restore"]["mitre"])
        self.assertEqual(by_elem["Shared Folders"]["result"], "Fail")
        self.assertEqual(by_elem["Suspicious Activity"]["result"], "Fail")
        self.assertIn("T1055", by_elem["Suspicious Activity"]["mitre"])

        table = format_summary_report(summary)
        self.assertIn("Summary Report", table)
        self.assertIn("CORE-DEV64", table)
        self.assertIn("2026-11-27 10:35:41", table)
        self.assertIn("MITRE ATT&CK", table)
        self.assertIn("T1055 (Process Anomaly)", table)


if __name__ == "__main__":
    unittest.main()
