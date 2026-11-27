# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Secuditor: Cross-platform security diagnostics and auditing library."""

from importlib import import_module

__version__ = "1.0.0"
__author__ = "Menahem Levinski"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "DomainAudit",
    "SecurityAudit",
    "RemoteAccessSettings",
    "SharedFolders",
    "SensitivePaths",
    "SuspiciousProcesses",
    "NetworkSettings",
    "GatewayDiscovery",
    "InstalledApps",
    "PasswordPolicy",
    "SuspiciousProxy",
    "SSLInterception",
    "SystemSettings",
    "FullAudit",
]

_MODULES = {
    "DomainAudit": ".domain_settings",
    "DomainSettingsAudit": ".domain_settings",
    "SecurityAudit": ".endpoint_security",
    "SecuritySettingsAudit": ".endpoint_security",
    "EndpointSecurity": ".endpoint_security",
    "RemoteAccessSettings": ".remote_access",
    "RemoteAccessAudit": ".remote_access",
    "SharedFolders": ".shared_folders",
    "SharedFoldersAudit": ".shared_folders",
    "SensitivePaths": ".sensitive_paths",
    "SensitivePathsAudit": ".sensitive_paths",
    "SuspiciousProcesses": ".suspicious_processes",
    "SuspiciousProcessesAudit": ".suspicious_processes",
    "NetworkSettings": ".network_settings",
    "NetworkSettingsAudit": ".network_settings",
    "GatewayDiscovery": ".gateway_discovery",
    "GatewayDiscoveryAudit": ".gateway_discovery",
    "GatewayAudit": ".gateway_discovery",
    "InstalledApps": ".installed_apps",
    "InstalledAppsAudit": ".installed_apps",
    "PasswordPolicy": ".password_policy",
    "PasswordPolicyAudit": ".password_policy",
    "SSLInterception": ".ssl_interception",
    "SSLInterceptionAudit": ".ssl_interception",
    "SSLInspection": ".ssl_interception",
    "SuspiciousProxy": ".suspicious_proxy",
    "SuspiciousProxyAudit": ".suspicious_proxy",
    "ProxyAudit": ".suspicious_proxy",
    "SystemSettings": ".system_settings",
    "SystemSettingsAudit": ".system_settings",
    "FullAudit": ".cli",
}


def __getattr__(name: str):
    """Load audit classes on demand."""
    if name not in _MODULES:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        )

    module = import_module(_MODULES[name], __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return public package attributes."""
    return sorted(set(__all__))
