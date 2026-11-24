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
secuditor -smb          # Shared folders, network exports, and access permissions
secuditor -net          # Network adapters, IPs, gateways, DNS, DHCP, and Wi-Fi
secuditor -gds          # Default gateway discovery, management ports, NAT, and VPN
secuditor -app          # Installed applications inventory
secuditor -dsa          # Domain affiliation, users, LAPS, NTLM, and NTP
secuditor -pwd          # Password policy, lockout settings, and PIN/biometrics
secuditor -prx          # System/environment proxy settings, PAC scripts, and local proxy listeners
secuditor -ssl          # SSL/TLS interception and certificate trust inspection
secuditor -all          # Run all audits in sequence
```

Examples:

```bash
secuditor -all --json
secuditor -end --json
secuditor -pwd --json
secuditor --version
```

Long flag aliases (`--system`, `--endpoint`, `--remote`, `--shares`, `--network`, `--gateway`, `--apps`, `--domain`, `--password`, `--proxy`, `--ssl`, `--all`) are also supported.

## Python Library Usage

Audit classes are lazily loaded from `secuditor` and expose an `.audit()` method returning a structured dictionary:

```python
from secuditor import (
    SystemSettings,
    SecurityAudit,
    RemoteAccessSettings,
    SharedFolders,
    NetworkSettings,
    GatewayDiscovery,
    InstalledApps,
    DomainAudit,
    PasswordPolicy,
    SuspiciousProxy,
    SSLInterception,
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
