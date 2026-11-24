import contextlib
import io
import json
import unittest
from unittest.mock import patch

from secuditor.cli import build_parser, main, print_results


class TestCLI(unittest.TestCase):
    def test_cli_accepts_audit_flags(self):
        cases = [
            ("-dsa", "dsa"),
            ("-end", "end"),
            ("-rem", "rem"),
            ("-smb", "smb"),
            ("-net", "net"),
            ("-gds", "gds"),
            ("-app", "app"),
            ("-pwd", "pwd"),
            ("-prx", "prx"),
            ("-ssl", "ssl"),
            ("-com", "com"),
            ("-all", "all"),
            ("--domain", "dsa"),
            ("--endpoint", "end"),
            ("--remote", "rem"),
            ("--shares", "smb"),
            ("--network", "net"),
            ("--gateway", "gds"),
            ("--apps", "app"),
            ("--password", "pwd"),
            ("--proxy", "prx"),
            ("--ssl", "ssl"),
            ("--system", "com"),
            ("--all", "all"),
        ]
        parser = build_parser()
        for flag, expected in cases:
            with self.subTest(flag=flag):
                args = parser.parse_args([flag])
                self.assertEqual(args.audit, expected)
                self.assertFalse(args.json)

    def test_json_option(self):
        args = build_parser().parse_args(["-net", "--json"])
        self.assertEqual(args.audit, "net")
        self.assertTrue(args.json)

    def test_requires_exactly_one_audit_flag(self):
        parser = build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args([])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-dsa", "-net"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-pas"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-sys"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-d"])

    def test_main_invokes_audit_and_prints_json(self):
        class FakeAudit:
            def audit(self):
                return {"platform": "TestOS", "ok": True}

        stdout = io.StringIO()
        with patch("secuditor.cli.import_module") as mock_import:
            mock_import.return_value.DomainAudit = FakeAudit
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["-dsa", "--json"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"platform": "TestOS", "ok": True},
        )

    def test_main_all_runs_all_audits_in_requested_order(self):
        called_order = []

        def fake_import(module_name, package=None):
            called_order.append(module_name)

            class FakeAudit:
                def audit(self):
                    return {"module": module_name}

            mod = type("FakeMod", (), {})()
            for _, cls_name, _ in [
                (".domain_settings", "DomainAudit", ""),
                (".endpoint_security", "SecurityAudit", ""),
                (".remote_access", "RemoteAccessSettings", ""),
                (".shared_folders", "SharedFolders", ""),
                (".network_settings", "NetworkSettings", ""),
                (".gateway_discovery", "GatewayDiscovery", ""),
                (".installed_apps", "InstalledApps", ""),
                (".password_policy", "PasswordPolicy", ""),
                (".ssl_interception", "SSLInterception", ""),
                (".suspicious_proxy", "SuspiciousProxy", ""),
                (".system_settings", "SystemSettings", ""),
            ]:
                setattr(mod, cls_name, FakeAudit)
            return mod

        stdout = io.StringIO()
        with patch("secuditor.cli.import_module", side_effect=fake_import):
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["-all", "--json"])

        self.assertEqual(exit_code, 0)
        expected_modules = [
            ".system_settings",
            ".endpoint_security",
            ".remote_access",
            ".shared_folders",
            ".network_settings",
            ".gateway_discovery",
            ".installed_apps",
            ".domain_settings",
            ".password_policy",
            ".suspicious_proxy",
            ".ssl_interception",
        ]
        self.assertEqual(called_order, expected_modules)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            list(payload.keys()),
            [m.lstrip(".") for m in expected_modules],
        )

    def test_print_results_formats_inline_list_dicts_multiline_and_acronyms(self):
        sample = {
            "adapters": [
                {
                    "name": "Ethernet 2",
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "addresses": [
                        {"ip": "192.168.1.10", "version": 4},
                    ],
                }
            ],
            "ntp": {"value": "Line 1\nLine 2"},
            "hardware": {"Hardware": {"Printers": {"status": "available", "devices": []}}},
        }
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            print_results("Sample", sample, as_json=False)
        rendered = stdout.getvalue()
        self.assertIn("  - Name: Ethernet 2", rendered)
        self.assertIn("    MAC Address: aa:bb:cc:dd:ee:ff", rendered)
        self.assertIn("      - IP: 192.168.1.10", rendered)
        self.assertIn("    Line 1\n    Line 2", rendered)
        self.assertIn("Hardware:\n  Printers:", rendered)


if __name__ == "__main__":
    unittest.main()
