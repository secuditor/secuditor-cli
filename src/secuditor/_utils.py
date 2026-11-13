# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Shared internal utilities for subprocess, PowerShell, and registry access."""

import json
import shutil
import subprocess
from typing import Any


def run_command(
    args: list[str],
    timeout: float = 8.0,
    strip: bool = True,
) -> str | None:
    """Run a command without a shell and return stdout on success, else None."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
        if result.returncode == 0:
            return result.stdout.strip() if strip else result.stdout
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def find_powershell() -> str | None:
    """Return the path to a PowerShell executable if available."""
    return shutil.which("powershell") or shutil.which("pwsh")


def run_powershell(
    command: str,
    timeout: float = 8.0,
    parse_json: bool = True,
    stop_on_error: bool = False,
) -> Any:
    """Run a PowerShell command non-interactively and optionally parse JSON."""
    executable = find_powershell()
    if not executable:
        return None

    script = (
        f"$ErrorActionPreference = 'Stop'; {command}"
        if stop_on_error
        else command
    )

    output = run_command(
        [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        timeout=timeout,
    )

    if not output:
        return None

    if not parse_json:
        return output

    try:
        return json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return None


def read_registry_value(root_name: str, path: str, name: str) -> Any:
    """Read a Windows registry value from HKLM or HKCU, returning None on error."""
    try:
        import winreg

        roots = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }
        root = roots[root_name]

        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except (OSError, ImportError, KeyError):
        return None
