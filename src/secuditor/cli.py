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
    "applications",
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

_LABEL_REPLACEMENTS = {
    "os": "OS",
    "cpu": "CPU",
    "mhz": "MHz",
    "ram": "RAM",
    "gb": "GB",
    "usb": "USB",
    "asr": "ASR",
    "uac": "UAC",
    "powershell": "PowerShell",
    "bitlocker": "BitLocker",
    "uefi": "UEFI",
    "autorun": "AutoRun",
    "ip": "IP",
    "mac": "MAC",
    "dns": "DNS",
    "dhcp": "DHCP",
    "wifi": "Wi-Fi",
    "laps": "LAPS",
    "ntlm": "NTLM",
    "ntlmv1": "NTLMv1",
    "lm": "LM",
    "sso": "SSO",
    "ntp": "NTP",
    "sid": "SID",
    "san": "SAN",
    "sha256": "SHA256",
    "tls": "TLS",
    "ssl": "SSL",
    "aslr": "ASLR",
    "filevault": "FileVault",
}


def _format_label(key: str) -> str:
    """Format a report dictionary key for readable plain-text output."""
    raw = str(key)
    if ":\\" in raw or raw.startswith("/"):
        return raw

    words = raw.replace("_", " ").split()
    formatted = []
    for word in words:
        prefix = ""
        suffix = ""
        core = word
        while core and core[0] in "([":
            prefix += core[0]
            core = core[1:]
        while core and core[-1] in ")]":
            suffix = core[-1] + suffix
            core = core[:-1]

        low = core.lower()
        if low in _LABEL_REPLACEMENTS:
            formatted.append(f"{prefix}{_LABEL_REPLACEMENTS[low]}{suffix}")
        elif "-" in core:
            parts = core.split("-")
            fixed_parts = [
                _LABEL_REPLACEMENTS.get(p.lower(), p.capitalize())
                for p in parts
            ]
            formatted.append(f"{prefix}{'-'.join(fixed_parts)}{suffix}")
        else:
            formatted.append(f"{prefix}{core.capitalize()}{suffix}")
    return " ".join(formatted)


def _print_entry(
    key: str,
    item,
    indent: int,
    first_prefix: str | None = None,
) -> None:
    """Print a single dictionary key/value pair with proper indentation."""
    prefix = first_prefix if first_prefix is not None else (" " * indent)
    label = _format_label(key)

    if isinstance(item, dict):
        # Unwrap redundant single nested key matching parent (e.g. hardware -> Hardware).
        if len(item) == 1:
            only_key = next(iter(item))
            if str(only_key).lower() == str(key).lower() and isinstance(item[only_key], dict):
                item = item[only_key]
        print(f"{prefix}{label}:")
        _print_value(item, indent + 2, parent_key=str(key))
    elif isinstance(item, (list, tuple)):
        print(f"{prefix}{label}:")
        _print_value(item, indent + 2, parent_key=str(key))
    elif isinstance(item, str) and "\n" in item:
        print(f"{prefix}{label}:")
        line_prefix = " " * (indent + 2)
        for line in item.splitlines():
            print(f"{line_prefix}{line}")
    else:
        print(f"{prefix}{label}: {item}")


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
            _print_entry(key, item, indent)
    elif isinstance(value, (list, tuple)):
        if not value:
            print(f"{prefix}(none)")
            return
        for idx, item in enumerate(value):
            if idx > 0 and parent_key == "adapters":
                print("–" * 50)
            if isinstance(item, dict):
                if not item:
                    print(f"{prefix}- (none)")
                    continue
                items = list(item.items())
                first_key, first_val = items[0]
                _print_entry(
                    first_key,
                    first_val,
                    indent + 2,
                    first_prefix=f"{prefix}- ",
                )
                for sub_key, sub_val in items[1:]:
                    _print_entry(sub_key, sub_val, indent + 2)
            elif isinstance(item, (list, tuple)):
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
