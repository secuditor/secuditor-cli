# Secuditor CLI

An open-source, cross-platform Python library and CLI for security diagnostics, configuration auditing, and system inventory across Windows, Linux, and macOS, inspired by Secuditor Lite.

## Installation

Requires Python 3.10 or later:

```bash
pip install secuditor
```

## CLI Usage

Run a single audit module or `-all` / `--audit` to run the full suite:

| Short | Long | Description |
| --- | --- | --- |
| `-com` | `--system` | System specifications, firmware, memory, GPU, and connected hardware |
| `-end` | `--endpoint` | Endpoint security settings (Defender, firewall, BitLocker/LUKS/FileVault, UAC, MAC, etc.) |
| `-rem` | `--remote` | Remote access services, protocols (RDP, SSH, SMB, WinRM, DCOM), and Bluetooth exposure |
| `-smb` | `--shares` | Shared folders, network exports (SMB/Samba/NFS), and access permissions |
| `-pth` | `--paths` | Sensitive files, credential/key artifacts, and permission exposure scan |
| `-prc` | `--processes` | Running processes behavioral security scan with risk scoring |
| `-net` | `--network` | Network adapters, IPs, gateways, DNS, DHCP, and Wi-Fi |
| `-dgm` | `--gateway` | Default gateway discovery, management ports, NAT, and VPN |
| `-app` | `--apps` | Installed applications inventory |
| `-dsa` | `--domain` | Domain affiliation, users, LAPS, NTLM, and NTP |
| `-pwd` | `--password` | Password policy, lockout settings, and PIN/biometrics |
| `-prx` | `--proxy` | System/environment proxy settings, PAC scripts, and local proxy listeners |
| `-ssl` | `--intercep` | SSL/TLS interception and certificate trust inspection |
| `-all` | `--audit` | Run all 13 audits in sequence |

### Options

| Flag | Description |
| --- | --- |
| `--json` | Output results as structured JSON to stdout (or to the file given by `-o`) |
| `-o PATH`, `--output PATH` | Write plain-text or JSON output to a UTF-8 file instead of stdout (creates missing parent directories) |
| `--version` | Show the installed `secuditor` version and exit |

- Plain-text `secuditor -all` prints each audit section followed by a **Summary Report** table with Pass / Fail / N/A counts and MITRE ATT&CK references.
- JSON `secuditor -all --json` outputs a single JSON object containing all 13 audit module results keyed by module name.

### Examples

```bash
secuditor -all
secuditor -all -o report.txt
secuditor -all --json
secuditor -all --json -o report.json
secuditor -end --json
secuditor -prc
secuditor --version
```

## Python Library Usage

Audit classes are lazily loaded from `secuditor` and expose an `.audit()` method returning a structured dictionary:

```python
from secuditor import (
    SystemSettings,
    SecurityAudit,
    RemoteAccessSettings,
    SharedFolders,
    SensitivePaths,
    SuspiciousProcesses,
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

full_report = FullAudit().audit()
print(list(full_report.keys()))
```

## Notes

- All checks are strictly read-only and do not modify system, registry, or policy configuration.
- Certain checks (such as `secedit` policy export, BitLocker, LAPS, ACLs, or protected process inspection on Windows, and root-owned configs, firewall rules, or PAM policies on Linux/macOS) may require elevated privileges and report `unknown` or `unavailable` otherwise.
- Supported on Windows, Linux, and macOS with Python 3.10+.

## License

MIT License — see [LICENSE](https://github.com/secuditor/secuditor-cli/blob/main/LICENSE) for details.

## Info

Website: [secuditor.com](https://secuditor.com/)
