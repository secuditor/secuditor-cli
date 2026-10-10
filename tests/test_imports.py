from secuditor_cli import (
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


def test_package_version():
    assert __version__ == "0.1.0"


def test_public_classes_are_importable():
    classes = [
        DomainAudit,
        SecurityAudit,
        InstalledApps,
        LanDiscovery,
        NetworkSettings,
        PasswordPolicy,
        RemoteAccess,
        ServerRole,
        SystemSettings,
    ]

    assert all(isinstance(cls, type) for cls in classes)
