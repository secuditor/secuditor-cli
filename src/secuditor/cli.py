# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Command-line interface for Secuditor CLI."""

import argparse
import json
import sys

from . import (
    __version__,
    DomainAudit,
    SecurityAudit,
    InstalledApps,
    LanDiscovery,
    NetworkSettings,
    PasswordPolicy,
    RemoteAccess,
    ServerRole,
    SystemSettings,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="secuditor",
        description="Cross-platform security diagnostics and auditing toolkit.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    commands = {
        "domain": "Audit domain settings",
        "endpoint": "Audit endpoint security",
        "apps": "Audit installed applications",
        "lan": "Discover devices on the local network",
        "network": "Audit network settings",
        "password": "Audit password policy",
        "remote": "Audit remote access configuration",
        "server": "Audit server roles and features",
        "system": "Audit system settings",
    }

    for name, description in commands.items():
        subparsers.add_parser(name, help=description)

    for name in ("domain", "endpoint", "apps", "lan", "network",
                 "password", "remote", "server", "system"):
        subparsers.choices[name].add_argument(
            "--json",
            action="store_true",
            help="Output results as JSON",
        )

    return parser


def print_results(title: str, results, as_json: bool = False) -> None:
    """Print audit results in text or JSON format."""
    if as_json:
        print(json.dumps(results, indent=2, default=str))
        return

    print(f"\nSecuditor {title}")
    print("=" * 50)

    if isinstance(results, dict):
        for key, value in results.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
    elif isinstance(results, (list, tuple)):
        for item in results:
            print(f"- {item}")
    else:
        print(results)


def main() -> int:
    """Run the selected audit command."""
    parser = build_parser()
    args = parser.parse_args()

    audit_classes = {
        "domain": (DomainAudit, "Domain Settings Audit"),
        "endpoint": (SecurityAudit, "Endpoint Security Audit"),
        "apps": (InstalledApps, "Installed Applications Audit"),
        "lan": (LanDiscovery, "LAN Discovery"),
        "network": (NetworkSettings, "Network Settings Audit"),
        "password": (PasswordPolicy, "Password Policy Audit"),
        "remote": (RemoteAccess, "Remote Access Audit"),
        "server": (ServerRole, "Server Roles Audit"),
        "system": (SystemSettings, "System Settings Audit"),
    }

    audit_class, title = audit_classes[args.command]

    try:
        audit = audit_class()

        # Replace with the actual public execution method
        # exposed by each audit class.
        results = audit.run()

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
