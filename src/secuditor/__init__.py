# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Secuditor: Cross-platform security diagnostics and auditing library."""

from importlib import import_module

__version__ = "0.4.0"
__author__ = "Menahem Levinski"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "DomainAudit",
    "InstalledApps",
    "NetworkSettings",
    "PasswordPolicy",
    "SystemSettings",
]

_MODULES = {
    "DomainAudit": ".domain_settings",
    "DomainSettingsAudit": ".domain_settings",
    "InstalledApps": ".installed_apps",
    "InstalledAppsAudit": ".installed_apps",
    "NetworkSettings": ".network_settings",
    "NetworkSettingsAudit": ".network_settings",
    "PasswordPolicy": ".password_policy",
    "PasswordPolicyAudit": ".password_policy",
    "SystemSettings": ".system_settings",
    "SystemSettingsAudit": ".system_settings",
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
