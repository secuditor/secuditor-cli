# Secuditor CLI

A cross-platform Python library and CLI for security diagnostics, configuration auditing, and system inventory across Windows, Linux, and macOS, inspired by Secuditor Lite.

## Installation

```bash
pip install secuditor
```

## CLI Usage

Run a specific audit module using its flag (add `--json` for JSON output):

```bash
secuditor -dsa          # Domain affiliation, users, LAPS, NTLM, and NTP
secuditor -app          # Installed applications inventory
secuditor -pwd          # Local password policy settings
secuditor -sys          # System specifications and connected hardware
secuditor -net          # Network adapters, IPs, gateways, DNS, DHCP, and Wi-Fi
```

Examples:

```bash
secuditor -net --json
secuditor --version
```

Long flag aliases (`--domain`, `--apps`, `--password`, `--system`, `--network`) are also supported.

## Python Library Usage

Audit classes are lazily loaded from `secuditor` and expose an `.audit()` method returning a structured dictionary:

```python
from secuditor import (
    DomainAudit,
    InstalledApps,
    NetworkSettings,
    PasswordPolicy,
    SystemSettings,
)

report = DomainAudit().audit()
print(report["affiliation"])
```

## Notes

- All checks are read-only and do not modify system configuration.
- Certain checks (such as `secedit` policy export on Windows) may require elevated privileges and report `unknown` or `unavailable` otherwise.

## License

MIT License — see [LICENSE](https://github.com/secuditor/secuditor-cli/blob/main/LICENSE) for details.
