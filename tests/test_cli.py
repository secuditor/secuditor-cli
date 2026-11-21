import contextlib
import io
import json
import unittest
from unittest.mock import patch

from secuditor.cli import build_parser, main


class TestCLI(unittest.TestCase):
    def test_cli_accepts_audit_flags(self):
        cases = [
            ("-dsa", "dsa"),
            ("-app", "app"),
            ("-pwd", "pwd"),
            ("-sys", "sys"),
            ("-net", "net"),
            ("--domain", "dsa"),
            ("--apps", "app"),
            ("--password", "pwd"),
            ("--system", "sys"),
            ("--network", "net"),
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
                parser.parse_args(["-end"])
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


if __name__ == "__main__":
    unittest.main()
