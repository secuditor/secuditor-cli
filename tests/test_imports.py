from pathlib import Path
import re
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
    SensitivePaths,
    SharedFolders,
    SuspiciousProcesses,
    SuspiciousProxy,
    SystemSettings,
    __version__,
)


class TestPackageImports(unittest.TestCase):
    def test_package_version(self):
        pyproject_text = (
            Path(__file__).resolve().parent.parent / "pyproject.toml"
        ).read_text(encoding="utf-8")
        match = re.search(
            r'^version\s*=\s*"([^"]+)"', pyproject_text, re.MULTILINE
        )
        self.assertIsNotNone(match)
        self.assertEqual(__version__, match.group(1))

    def test_public_classes_are_importable(self):
        classes = [
            DomainAudit,
            SecurityAudit,
            RemoteAccessSettings,
            SharedFolders,
            SensitivePaths,
            SuspiciousProcesses,
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
