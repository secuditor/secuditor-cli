# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform installed application discovery."""

import os
import platform
import plistlib

from ._utils import run_command

__all__ = ["InstalledApps", "InstalledAppsAudit"]

class InstalledAppsAudit:
    """Discover installed applications on Windows, Linux, and macOS."""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        return run_command(args, timeout=self.timeout, strip=False)

    def _windows_apps(self):
        import winreg

        apps = {}

        uninstall_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]

        roots = [
            ("HKLM", winreg.HKEY_LOCAL_MACHINE),
            ("HKCU", winreg.HKEY_CURRENT_USER),
        ]

        for root_name, root in roots:
            for key_path in uninstall_keys:
                try:
                    with winreg.OpenKey(root, key_path) as parent:
                        count = winreg.QueryInfoKey(parent)[0]

                        for index in range(count):
                            try:
                                subkey_name = winreg.EnumKey(parent, index)

                                with winreg.OpenKey(
                                    parent, subkey_name
                                ) as subkey:
                                    try:
                                        name, _ = winreg.QueryValueEx(
                                            subkey, "DisplayName"
                                        )
                                    except OSError:
                                        continue

                                    if not isinstance(name, str) or not name.strip():
                                        continue

                                    try:
                                        version, _ = winreg.QueryValueEx(
                                            subkey, "DisplayVersion"
                                        )
                                    except OSError:
                                        version = None

                                    try:
                                        publisher, _ = winreg.QueryValueEx(
                                            subkey, "Publisher"
                                        )
                                    except OSError:
                                        publisher = None

                                    item = {
                                        "name": name.strip(),
                                        "version": (
                                            version.strip()
                                            if isinstance(version, str)
                                            else version
                                        ),
                                        "publisher": (
                                            publisher.strip()
                                            if isinstance(publisher, str)
                                            else publisher
                                        ),
                                    }

                                    # Keep entries with different versions or
                                    # publishers; avoid duplicate registry views.
                                    identity = (
                                        item["name"].casefold(),
                                        str(version or "").casefold(),
                                        str(publisher or "").casefold(),
                                    )
                                    apps.setdefault(identity, item)

                            except OSError:
                                continue

                except OSError:
                    continue

        return list(apps.values())

    def _linux_apps(self):
        apps = []

        # Debian / Ubuntu and derivatives.
        output = self._run([
            "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"
        ])
        if output is not None:
            for line in output.splitlines():
                parts = line.split("\t", 1)
                if parts and parts[0].strip():
                    apps.append({
                        "name": parts[0].strip(),
                        "version": parts[1].strip() if len(parts) > 1 else None,
                        "publisher": None,
                    })
        else:
            # Fedora / RHEL / openSUSE and other RPM-based distributions.
            output = self._run([
                "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"
            ])
            if output is not None:
                for line in output.splitlines():
                    parts = line.split("\t", 1)
                    if parts and parts[0].strip():
                        apps.append({
                            "name": parts[0].strip(),
                            "version": parts[1].strip() if len(parts) > 1 else None,
                            "publisher": None,
                        })

        # Flatpak applications, if installed (may coexist with dpkg/rpm).
        output = self._run([
            "flatpak", "list", "--app", "--columns=application,version"
        ])
        if output is not None:
            for line in output.splitlines():
                parts = line.split("\t", 1)
                if parts and parts[0].strip():
                    apps.append({
                        "name": parts[0].strip(),
                        "version": parts[1].strip() if len(parts) > 1 else None,
                        "publisher": None,
                    })

        return apps

    def _macos_apps(self):
        apps = []
        seen = set()

        roots = [
            "/Applications",
            "/Applications/Utilities",
            "/System/Applications",
            "/System/Applications/Utilities",
            os.path.expanduser("~/Applications"),
        ]

        for root in roots:
            if not os.path.isdir(root):
                continue

            try:
                entries = os.scandir(root)
            except OSError:
                continue

            with entries:
                for entry in entries:
                    if not entry.name.endswith(".app"):
                        continue

                    if not entry.is_dir(follow_symlinks=False):
                        continue

                    bundle_path = entry.path
                    if bundle_path in seen:
                        continue
                    seen.add(bundle_path)

                    info_path = os.path.join(
                        bundle_path, "Contents", "Info.plist"
                    )

                    name = entry.name[:-4]
                    version = None
                    publisher = None

                    try:
                        with open(info_path, "rb") as file:
                            info = plistlib.load(file)

                        name = (
                            info.get("CFBundleDisplayName")
                            or info.get("CFBundleName")
                            or name
                        )
                        version = (
                            info.get("CFBundleShortVersionString")
                            or info.get("CFBundleVersion")
                        )
                        publisher = info.get("NSHumanReadableCopyright")

                    except (OSError, plistlib.InvalidFileException, ValueError):
                        pass

                    apps.append({
                        "name": str(name).strip(),
                        "version": version,
                        "publisher": publisher,
                        "path": bundle_path,
                    })

        return apps

    def audit(self):
        if self.system == "Windows":
            apps = self._windows_apps()
        elif self.system == "Linux":
            apps = self._linux_apps()
        elif self.system == "Darwin":
            apps = self._macos_apps()
        else:
            apps = []

        apps.sort(key=lambda item: item["name"].casefold())

        return {
            "platform": self.system,
            "count": len(apps),
            "applications": apps,
            "notes": [
                "Results depend on the operating system's application "
                "registration and package-management mechanisms.",
                "Portable applications and applications installed outside "
                "scanned locations may not be detected.",
            ],
        }


InstalledApps = InstalledAppsAudit

if __name__ == "__main__":
    import json

    report = InstalledAppsAudit().audit()
    print(json.dumps(report, indent=2, ensure_ascii=False))
