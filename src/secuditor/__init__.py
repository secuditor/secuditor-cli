# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Secuditor: Cross-platform security diagnostics and auditing library."""

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "DomainAudit",
    "SecurityAudit",
    "InstalledApps",
    "LanDiscovery",
    "NetworkSettings",
    "PasswordPolicy",
    "RemoteAccess",
    "ServerRole",
    "SystemSettings",
]

_MODULES = {
    "DomainAudit": ".domain_settings",
    "SecurityAudit": ".endpoint_security",
    "InstalledApps": ".installed_apps",
    "LanDiscovery": ".lan_discovery",
    "NetworkSettings": ".network_settings",
    "PasswordPolicy": ".password_policy",
    "RemoteAccess": ".remote_access",
    "ServerRole": ".server_role",
    "SystemSettings": ".system_settings",
}


def __getattr__(name: str):
    """Load audit classes on demand."""
    if name not in _MODULES:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        )

    from importlib import import_module

    module = import_module(_MODULES[name], __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value
