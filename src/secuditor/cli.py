# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Command-line interface for Secuditor CLI."""

import argparse
from collections.abc import Sequence
from importlib import import_module
import json
import sys

from . import __version__

_AUDIT_SPECS = {
    "dsa": (".domain_settings", "DomainAudit", "Domain Settings Audit"),
    "end": (".endpoint_security", "SecurityAudit", "Endpoint Security Audit"),
    "app": (".installed_apps", "InstalledApps", "Installed Applications Audit"),
    "pwd": (".password_policy", "PasswordPolicy", "Password Policy Audit"),
    "ssl": (".ssl_interception", "SSLInterception", "SSL Interception Audit"),
    "sys": (".system_settings", "SystemSettings", "System Settings Audit"),
    "net": (".network_settings", "NetworkSettings", "Network Settings Audit"),
}


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
        "-dsa",
        "--domain",
        dest="audit",
        action="store_const",
        const="dsa",
        help="Audit domain settings",
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
        "-app",
        "--apps",
        dest="audit",
        action="store_const",
        const="app",
        help="Audit installed applications",
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
        "-sys",
        "--system",
        dest="audit",
        action="store_const",
        const="sys",
        help="Audit system settings",
    )
    group.add_argument(
        "-net",
        "--network",
        dest="audit",
        action="store_const",
        const="net",
        help="Audit network settings",
    )

    return parser


def _print_value(value, indent: int = 0) -> None:
    """Print nested dicts/lists in a readable plain-text layout."""
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            print(f"{prefix}(none)")
            return
        for key, item in value.items():
            label = str(key).replace("_", " ").title()
            if isinstance(item, (dict, list, tuple)):
                print(f"{prefix}{label}:")
                _print_value(item, indent + 2)
            else:
                print(f"{prefix}{label}: {item}")
    elif isinstance(value, (list, tuple)):
        if not value:
            print(f"{prefix}(none)")
            return
        for item in value:
            if isinstance(item, (dict, list, tuple)):
                print(f"{prefix}-")
                _print_value(item, indent + 2)
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

    module_name, class_name, title = _AUDIT_SPECS[args.audit]

    try:
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
