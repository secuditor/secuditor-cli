# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Shared internal utilities for subprocess, PowerShell, and registry access."""

import json
import os
import shutil
import subprocess
import sys
from typing import Any

_IS_WINDOWS = sys.platform == "win32"

_WINDOWS_BUILTIN_COMMANDS = {
    "dsregcmd",
    "dsregcmd.exe",
    "net",
    "net.exe",
    "netsh",
    "netsh.exe",
    "powershell",
    "powershell.exe",
    "sc",
    "sc.exe",
    "secedit",
    "secedit.exe",
    "w32tm",
    "w32tm.exe",
}

if _IS_WINDOWS:
    _CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        _STARTUPINFO = subprocess.STARTUPINFO()
        _STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        _STARTUPINFO.wShowWindow = subprocess.SW_HIDE
    except Exception:
        _STARTUPINFO = None
else:
    _CREATE_NO_WINDOW = 0
    _STARTUPINFO = None


def _system_exe(name: str) -> str:
    """Resolve Windows built-in tools from System32 to prevent PATH/CWD hijacking."""
    if not _IS_WINDOWS or not name or os.path.isabs(name):
        return name

    lower_name = name.lower()
    if lower_name not in _WINDOWS_BUILTIN_COMMANDS:
        return name

    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(sysroot, "System32")

    if lower_name in ("powershell", "powershell.exe"):
        ps_path = os.path.join(
            sys32, "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(ps_path):
            return ps_path

    base = os.path.basename(name)
    candidates = [name] if "." in base else [f"{name}.exe", f"{name}.cmd"]
    for directory in (sys32, os.path.join(sys32, "wbem")):
        for candidate_name in candidates:
            candidate = os.path.join(directory, candidate_name)
            if os.path.isfile(candidate):
                return candidate

    return shutil.which(name) or name


def _safe_subproc_env() -> dict[str, str]:
    """Return a subprocess environment hardened against CWD exe lookup on Windows."""
    env = dict(os.environ)
    if _IS_WINDOWS:
        env.setdefault("NoDefaultCurrentDirectoryInExePath", "1")
    return env


def _windows_subproc_kwargs() -> dict[str, Any]:
    """Return Windows-only kwargs to hide child console windows."""
    if not _IS_WINDOWS:
        return {}
    kwargs: dict[str, Any] = {"creationflags": _CREATE_NO_WINDOW}
    if _STARTUPINFO is not None:
        kwargs["startupinfo"] = _STARTUPINFO
    return kwargs


def run_command_result(
    args: list[str],
    timeout: float = 8.0,
) -> tuple[int, str, str] | None:
    """Run a command safely without a shell and return (returncode, stdout, stderr)."""
    if not args:
        return None

    resolved_args = [_system_exe(str(args[0])), *args[1:]]
    try:
        result = subprocess.run(
            resolved_args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
            env=_safe_subproc_env(),
            **_windows_subproc_kwargs(),
        )
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.SubprocessError):
        return None


def run_command(
    args: list[str],
    timeout: float = 8.0,
    strip: bool = True,
) -> str | None:
    """Run a command without a shell and return stdout on success, else None."""
    result = run_command_result(args, timeout=timeout)
    if result is None:
        return None
    returncode, stdout, _ = result
    if returncode == 0:
        return stdout.strip() if strip else stdout
    return None


def find_powershell() -> str | None:
    """Return the path to a PowerShell executable if available."""
    if _IS_WINDOWS:
        resolved = _system_exe("powershell.exe")
        if os.path.isabs(resolved) and os.path.isfile(resolved):
            return resolved
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
    """Read a Windows registry value from HKLM or HKCU using the 64-bit view."""
    try:
        import winreg

        roots = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }
        root = roots[root_name]
        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)

        with winreg.OpenKey(root, path, 0, access) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except (OSError, ImportError, KeyError):
        return None
