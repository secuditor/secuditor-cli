# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Command-line interface for Secuditor CLI."""

import argparse
from collections.abc import Sequence
from importlib import import_module
import json
import sys

from . import __version__

_AUDIT_SPECS = {
    "com": (".system_settings", "SystemSettings", "System Settings Audit"),
    "end": (".endpoint_security", "SecurityAudit", "Endpoint Security Audit"),
    "net": (".network_settings", "NetworkSettings", "Network Settings Audit"),
    "app": (".installed_apps", "InstalledApps", "Installed Applications Audit"),
    "dsa": (".domain_settings", "DomainAudit", "Domain Settings Audit"),
    "pwd": (".password_policy", "PasswordPolicy", "Password Policy Audit"),
    "ssl": (".ssl_interception", "SSLInterception", "SSL Interception Audit"),
}

_ALL_ORDER = ("com", "end", "net", "app", "dsa", "pwd", "ssl")


class FullAudit:
    """Run all Secuditor audit modules in the standard execution order."""

    def audit(self) -> dict:
        results = {}
        for key in _ALL_ORDER:
            module_name, class_name, _ = _AUDIT_SPECS[key]
            section_key = module_name.lstrip(".")
            try:
                module = import_module(module_name, package=__package__)
                audit_class = getattr(module, class_name)
                results[section_key] = audit_class().audit()
            except Exception as exc:
                results[section_key] = {"error": str(exc)}
        return results


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="secuditor",
        description="Cross-platform security diagnostics and auditing toolkit.",
        allow_abbrev=False,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-com",
        "--system",
        dest="audit",
        action="store_const",
        const="com",
        help="Audit system settings",
    )
    group.add_argument(
        "-end",
        "--endpoint",
        dest="audit",
        action="store_const",
        const="end",
        help="Audit endpoint security",
    )
    group.add_argument(
        "-net",
        "--network",
        dest="audit",
        action="store_const",
        const="net",
        help="Audit network settings",
    )
    group.add_argument(
        "-app",
        "--apps",
        dest="audit",
        action="store_const",
        const="app",
        help="Audit installed applications",
    )
    group.add_argument(
        "-dsa",
        "--domain",
        dest="audit",
        action="store_const",
        const="dsa",
        help="Audit domain settings",
    )
    group.add_argument(
        "-pwd",
        "--password",
        dest="audit",
        action="store_const",
        const="pwd",
        help="Audit password policy",
    )
    group.add_argument(
        "-ssl",
        "--ssl",
        dest="audit",
        action="store_const",
        const="ssl",
        help="Audit SSL/TLS interception",
    )
    group.add_argument(
        "-all",
        "--all",
        dest="audit",
        action="store_const",
        const="all",
        help="Run all audits in sequence",
    )

    return parser


_SECTION_DIVIDER_KEYS = {
    "Resources",
    "Disks",
    "hardware",
    "adapters",
    "errors",
    "notes",
    "checks",
    "Auto Screen Lock",
    "Core Isolation",
    "Kernel Hardening (ASLR)",
    "System Integrity Protection",
    "Encrypted File System",
    "Disk Encryption",
    "FileVault Disk Encryption",
    "affiliation",
    "laps",
    "ntlm_policy",
    "ntp",
    "users",
    "limitations",
    "settings",
    "lockout_threshold",
    "account_expiration",
    "global_policy",
    "fingerprint_sha256",
    "ssl_interception_detected",
}


def _print_value(value, indent: int = 0, parent_key: str | None = None) -> None:
    """Print nested dicts/lists in a readable plain-text layout."""
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            print(f"{prefix}(none)")
            return
        for key, item in value.items():
            if key in _SECTION_DIVIDER_KEYS and indent in (0, 2):
                print("–" * 50)
            label = str(key).replace("_", " ").title()
            if isinstance(item, (dict, list, tuple)):
                print(f"{prefix}{label}:")
                _print_value(item, indent + 2, parent_key=str(key))
            else:
                print(f"{prefix}{label}: {item}")
    elif isinstance(value, (list, tuple)):
        if not value:
            print(f"{prefix}(none)")
            return
        for idx, item in enumerate(value):
            if idx > 0 and parent_key == "adapters":
                print("–" * 50)
            if isinstance(item, (dict, list, tuple)):
                print(f"{prefix}-")
                _print_value(item, indent + 2, parent_key=parent_key)
            else:
                print(f"{prefix}- {item}")
    else:
        print(f"{prefix}{value}")


def print_results(title: str, results, as_json: bool = False) -> None:
    """Print audit results in text or JSON format."""
    if as_json:
        print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
        return

    print(f"\nSecuditor {title}")
    print("=" * 50)
    _print_value(results)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected audit command."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.audit == "all":
            if args.json:
                print(
                    json.dumps(
                        FullAudit().audit(),
                        indent=2,
                        default=str,
                        ensure_ascii=False,
                    )
                )
            else:
                for key in _ALL_ORDER:
                    module_name, class_name, title = _AUDIT_SPECS[key]
                    try:
                        module = import_module(module_name, package=__package__)
                        audit_class = getattr(module, class_name)
                        results = audit_class().audit()
                    except Exception as exc:
                        results = {"error": str(exc)}
                    print_results(title, results, as_json=False)
            return 0

        module_name, class_name, title = _AUDIT_SPECS[args.audit]
        module = import_module(module_name, package=__package__)
        audit_class = getattr(module, class_name)
        results = audit_class().audit()
        print_results(title, results, args.json)
        return 0

    except KeyboardInterrupt:
        print("\nAudit cancelled.", file=sys.stderr)
        return 130

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
