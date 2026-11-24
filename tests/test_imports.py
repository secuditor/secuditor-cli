import unittest

import secuditor
from secuditor import (
    DomainAudit,
    FullAudit,
    GatewayDiscovery,
    InstalledApps,
    NetworkSettings,
    PasswordPolicy,
    RemoteAccessSettings,
    SSLInterception,
    SecurityAudit,
    SharedFolders,
    SuspiciousProxy,
    SystemSettings,
    __version__,
)


class TestPackageImports(unittest.TestCase):
    def test_package_version(self):
        self.assertEqual(__version__, "0.8.0")

    def test_public_classes_are_importable(self):
        classes = [
            DomainAudit,
            SecurityAudit,
            RemoteAccessSettings,
            SharedFolders,
            NetworkSettings,
            GatewayDiscovery,
            InstalledApps,
            PasswordPolicy,
            SSLInterception,
            SuspiciousProxy,
            SystemSettings,
            FullAudit,
        ]
        self.assertTrue(all(isinstance(cls, type) for cls in classes))
        for cls in classes:
            self.assertTrue(callable(getattr(cls, "audit", None)))

    def test_removed_attributes_raise(self):
        for name in ("LanDiscovery", "RemoteAccess", "ServerRole"):
            with self.subTest(name=name):
                with self.assertRaises(AttributeError):
                    getattr(secuditor, name)


if __name__ == "__main__":
    unittest.main()
