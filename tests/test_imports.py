import unittest

import secuditor
from secuditor import (
    DomainAudit,
    InstalledApps,
    NetworkSettings,
    PasswordPolicy,
    SystemSettings,
    __version__,
)


class TestPackageImports(unittest.TestCase):
    def test_package_version(self):
        self.assertEqual(__version__, "0.5.0")

    def test_public_classes_are_importable(self):
        classes = [
            DomainAudit,
            InstalledApps,
            NetworkSettings,
            PasswordPolicy,
            SystemSettings,
        ]
        self.assertTrue(all(isinstance(cls, type) for cls in classes))
        for cls in classes:
            self.assertTrue(callable(getattr(cls, "audit", None)))

    def test_removed_attributes_raise(self):
        for name in ("SecurityAudit", "LanDiscovery", "RemoteAccess", "ServerRole"):
            with self.subTest(name=name):
                with self.assertRaises(AttributeError):
                    getattr(secuditor, name)


if __name__ == "__main__":
    unittest.main()
