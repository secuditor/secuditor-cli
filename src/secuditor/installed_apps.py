# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform installed application discovery."""

import os
import platform
import plistlib
import shutil

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

        wow64_64 = getattr(winreg, "KEY_WOW64_64KEY", 0)
        wow64_32 = getattr(winreg, "KEY_WOW64_32KEY", 0)
        uninstall_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        wow_uninstall_path = (
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        targets = [
            (winreg.HKEY_LOCAL_MACHINE, uninstall_path, winreg.KEY_READ | wow64_64),
            (winreg.HKEY_LOCAL_MACHINE, uninstall_path, winreg.KEY_READ | wow64_32),
            (winreg.HKEY_CURRENT_USER, uninstall_path, winreg.KEY_READ),
            (winreg.HKEY_CURRENT_USER, wow_uninstall_path, winreg.KEY_READ),
        ]

        for root, key_path, access in targets:
            try:
                with winreg.OpenKey(root, key_path, 0, access) as parent:
                    count = winreg.QueryInfoKey(parent)[0]

                    for index in range(count):
                        try:
                            subkey_name = winreg.EnumKey(parent, index)

                            with winreg.OpenKey(
                                parent, subkey_name, 0, access
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
                                    str(item["version"] or "").casefold(),
                                    str(item["publisher"] or "").casefold(),
                                )
                                apps.setdefault(identity, item)

                        except OSError:
                            continue

            except OSError:
                continue

        return list(apps.values())

    def _linux_apps(self):
        apps = []
        seen = set()

        def _add(name, version):
            cleaned_name = (name or "").strip()
            if not cleaned_name:
                return
            cleaned_version = version.strip() if isinstance(version, str) else version
            identity = (cleaned_name.casefold(), str(cleaned_version or "").casefold())
            if identity in seen:
                return
            seen.add(identity)
            apps.append({
                "name": cleaned_name,
                "version": cleaned_version or None,
                "publisher": None,
            })

        # Primary distro package managers.
        if shutil.which("dpkg-query"):
            output = self._run([
                "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"
            ])
            if output is not None:
                for line in output.splitlines():
                    parts = line.split("\t", 1)
                    _add(parts[0], parts[1] if len(parts) > 1 else None)
        elif shutil.which("rpm"):
            output = self._run([
                "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"
            ])
            if output is not None:
                for line in output.splitlines():
                    parts = line.split("\t", 1)
                    _add(parts[0], parts[1] if len(parts) > 1 else None)
        elif shutil.which("pacman"):
            output = self._run(["pacman", "-Q"])
            if output is not None:
                for line in output.splitlines():
                    parts = line.split(None, 1)
                    if parts:
                        _add(parts[0], parts[1] if len(parts) > 1 else None)
        elif shutil.which("apk"):
            output = self._run(["apk", "info", "-v"])
            if output is not None:
                for line in output.splitlines():
                    entry = line.strip()
                    if not entry:
                        continue
                    # apk info -v outputs <name>-<ver>-r<rel>; split at the last two hyphens when numeric.
                    parts = entry.rsplit("-", 2)
                    if len(parts) == 3 and parts[1][:1].isdigit():
                        _add(parts[0], f"{parts[1]}-{parts[2]}")
                    else:
                        _add(entry, None)

        # Flatpak applications, if installed.
        if shutil.which("flatpak"):
            output = self._run([
                "flatpak", "list", "--app", "--columns=application,version"
            ])
            if output is not None:
                for line in output.splitlines():
                    parts = line.split("\t", 1)
                    _add(parts[0], parts[1] if len(parts) > 1 else None)

        # Snap packages, if installed.
        if shutil.which("snap"):
            output = self._run(["snap", "list"])
            if output is not None:
                for idx, line in enumerate(output.splitlines()):
                    parts = line.split()
                    if idx == 0 and parts and parts[0].lower() == "name":
                        continue
                    if parts:
                        _add(parts[0], parts[1] if len(parts) > 1 else None)

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

            scan_dirs = [root]
            try:
                with os.scandir(root) as top_entries:
                    for top in top_entries:
                        if not top.name.endswith(".app") and top.is_dir(follow_symlinks=False):
                            scan_dirs.append(top.path)
            except OSError:
                pass

            for scan_dir in scan_dirs:
                try:
                    entries = os.scandir(scan_dir)
                except OSError:
                    continue

                with entries:
                    for entry in entries:
                        if not entry.name.endswith(".app"):
                            continue

                        if not entry.is_dir(follow_symlinks=False):
                            continue

                        bundle_path = entry.path
                        canonical_path = os.path.realpath(bundle_path)
                        if canonical_path in seen:
                            continue
                        seen.add(canonical_path)

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
