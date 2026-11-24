# Secuditor CLI

An open-source, cross-platform Python library and CLI for security diagnostics, configuration auditing, and system inventory across Windows, Linux, and macOS, inspired by Secuditor Lite.

## Installation

```bash
pip install secuditor
```

## CLI Usage

Run a specific audit module using its flag (add `--json` for JSON output):

```bash
secuditor -com          # System specifications, firmware, memory, GPU, and connected hardware
secuditor -end          # Endpoint security settings (Defender, firewall, BitLocker, UAC, MAC, etc.)
secuditor -rem          # Remote access services, protocols, and Bluetooth exposure
secuditor -net          # Network adapters, IPs, gateways, DNS, DHCP, and Wi-Fi
secuditor -app          # Installed applications inventory
secuditor -dsa          # Domain affiliation, users, LAPS, NTLM, and NTP
secuditor -pwd          # Password policy, lockout settings, and PIN/biometrics
secuditor -ssl          # SSL/TLS interception and certificate trust inspection
secuditor -prx          # System/environment proxy settings, PAC scripts, and local proxy listeners
secuditor -all          # Run all audits in sequence
```

Examples:

```bash
secuditor -all --json
secuditor -rem --json
secuditor -prx --json
secuditor --version
```

Long flag aliases (`--system`, `--endpoint`, `--remote`, `--network`, `--apps`, `--domain`, `--password`, `--ssl`, `--proxy`, `--all`) are also supported.

## Python Library Usage

Audit classes are lazily loaded from `secuditor` and expose an `.audit()` method returning a structured dictionary:

```python
from secuditor import (
    SystemSettings,
    SecurityAudit,
    RemoteAccessSettings,
    NetworkSettings,
    InstalledApps,
    DomainAudit,
    PasswordPolicy,
    SSLInterception,
    SuspiciousProxy,
    FullAudit,
)

report = DomainAudit().audit()
print(report["affiliation"])
```

## Notes

- All checks are read-only and do not modify system configuration.
- Certain checks (such as `secedit` policy export on Windows) may require elevated privileges and report `unknown` or `unavailable` otherwise.

## License

MIT License — see [LICENSE](https://github.com/secuditor/secuditor-cli/blob/main/LICENSE) for details.

## Info

Website: [secuditor.com](https://secuditor.com/)
