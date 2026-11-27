import contextlib
import io
import json
import os
import tempfile
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
            ("-pth", "pth"),
            ("-prc", "prc"),
            ("-net", "net"),
            ("-dgm", "dgm"),
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
            ("--paths", "pth"),
            ("--processes", "prc"),
            ("--network", "net"),
            ("--gateway", "dgm"),
            ("--apps", "app"),
            ("--password", "pwd"),
            ("--proxy", "prx"),
            ("--intercep", "ssl"),
            ("--system", "com"),
            ("--audit", "all"),
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
        self.assertIsNone(args.output)

    def test_output_option(self):
        parser = build_parser()
        args_short = parser.parse_args(["-all", "--json", "-o", "audit.json"])
        self.assertEqual(args_short.audit, "all")
        self.assertTrue(args_short.json)
        self.assertEqual(args_short.output, "audit.json")

        args_long = parser.parse_args(["-end", "--output", "reports/end.txt"])
        self.assertEqual(args_long.audit, "end")
        self.assertFalse(args_long.json)
        self.assertEqual(args_long.output, "reports/end.txt")

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
                (".sensitive_paths", "SensitivePaths", ""),
                (".suspicious_processes", "SuspiciousProcesses", ""),
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
            ".sensitive_paths",
            ".suspicious_processes",
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
        self.assertNotIn("summary_report", payload)

    def test_main_all_plain_text_prints_summary_report_at_end(self):
        def fake_import(module_name, package=None):
            class FakeAudit:
                def audit(self):
                    return {"platform": "Windows", "hostname": "TESTHOST"}

            mod = type("FakeMod", (), {})()
            for _, cls_name, _ in [
                (".domain_settings", "DomainAudit", ""),
                (".endpoint_security", "SecurityAudit", ""),
                (".remote_access", "RemoteAccessSettings", ""),
                (".shared_folders", "SharedFolders", ""),
                (".sensitive_paths", "SensitivePaths", ""),
                (".suspicious_processes", "SuspiciousProcesses", ""),
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
                exit_code = main(["-all"])

        self.assertEqual(exit_code, 0)
        rendered = stdout.getvalue()
        idx_ssl = rendered.rfind("Secuditor SSL Interception Audit")
        idx_summary = rendered.rfind("Summary Report")
        self.assertGreater(idx_ssl, 0)
        self.assertGreater(idx_summary, idx_ssl)
        self.assertIn("Security Element", rendered[idx_summary:])
        self.assertIn("MITRE ATT&CK", rendered[idx_summary:])

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

    def test_main_output_writes_json_file_and_creates_parent_dirs(self):
        class FakeAudit:
            def audit(self):
                return {"platform": "TestOS", "ok": True, "dash": "–"}

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "nested", "dir", "domain.json")
            stdout = io.StringIO()
            with patch("secuditor.cli.import_module") as mock_import:
                mock_import.return_value.DomainAudit = FakeAudit
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["-dsa", "--json", "-o", out_path])

            self.assertEqual(exit_code, 0)
            self.assertIn("Report saved to:", stdout.getvalue())
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved, {"platform": "TestOS", "ok": True, "dash": "–"})

    def test_main_all_output_writes_plain_text_with_summary_report(self):
        def fake_import(module_name, package=None):
            class FakeAudit:
                def audit(self):
                    return {"platform": "Windows", "hostname": "TESTHOST"}

            mod = type("FakeMod", (), {})()
            for _, cls_name, _ in [
                (".domain_settings", "DomainAudit", ""),
                (".endpoint_security", "SecurityAudit", ""),
                (".remote_access", "RemoteAccessSettings", ""),
                (".shared_folders", "SharedFolders", ""),
                (".sensitive_paths", "SensitivePaths", ""),
                (".suspicious_processes", "SuspiciousProcesses", ""),
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

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "full_audit.txt")
            stdout = io.StringIO()
            with patch("secuditor.cli.import_module", side_effect=fake_import):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["-all", "--output", out_path])

            self.assertEqual(exit_code, 0)
            self.assertIn("Report saved to:", stdout.getvalue())
            with open(out_path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("Secuditor SSL Interception Audit", content)
            self.assertIn("Summary Report – TESTHOST", content)
            self.assertIn("MITRE ATT&CK", content)

    def test_main_output_rejects_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stderr = io.StringIO()
            with patch("secuditor.cli.import_module") as mock_import:
                with contextlib.redirect_stderr(stderr):
                    exit_code = main(["-dsa", "-o", tmpdir])

            self.assertEqual(exit_code, 1)
            self.assertIn("Output path is a directory", stderr.getvalue())
            mock_import.assert_not_called()


if __name__ == "__main__":
    unittest.main()
