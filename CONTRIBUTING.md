# Contributing to Secuditor CLI

Thank you for your interest in contributing to **Secuditor CLI**. Contributions of all kinds are welcome: code, documentation, testing, ideas, and feedback.

This project is an **open-source Python library and CLI** designed for ethical security diagnostics.

---

## When Using AI Copilot

Using GitHub Copilot in pull requests may cause Copilot to appear in repository activity or suggestion history.

For clear attribution and meaningful contribution tracking:

- Use Copilot as an assistant, not the primary author of changes
- Ensure meaningful changes are reviewed and committed by humans
- Prefer manual commits for core logic and important updates

---

## Code of Conduct & Ethics

By contributing, you agree to uphold the following principles:

* All contributions must support **legal, ethical, and authorized diagnostics** only.
* Do **not** add features intended to bypass security controls, evade detection, or facilitate unlawful activity.
* Respect user privacy and organizational policies.

The maintainer reserves the right to reject contributions that conflict with these principles.

---

## Ways to Contribute

You can help in many ways:

### Code Contributions

* Bug fixes
* Performance improvements
* Cross-platform compatibility enhancements (Windows, Linux, and macOS)
* Refactoring for readability and maintainability
* Adding safe, passive diagnostic checks

### Documentation

* Improve README or technical documentation clarity
* Add usage examples
* Fix typos or grammar
* Improve comments and docstrings

### Testing

* Add unit tests with mocked OS, subprocess, registry, `ctypes`, or `psutil` boundaries
* Test on different Windows, Linux, and macOS Python versions (`>=3.10`)
* Report bugs or platform-specific edge cases
* Validate audit accuracy and JSON/CLI output compatibility

### Ideas & Feedback

* Feature requests (passive, defensive, and legal only)
* UX improvements for CLI and JSON output
* Suggestions for better reporting or diagnostics

---

## Development Guidelines

To keep the project clean and consistent, please follow these rules:

* Python version: **Python 3.10 or later** (`requires-python = ">=3.10"`)
* Keep dependencies minimal (`psutil`, `cryptography`, `certifi`, plus the Python standard library)
* Keep all audits **strictly read-only** — do not mutate system, registry, or policy configuration
* Preserve safe subprocess execution (`shell=False`, explicit timeouts, System32 path resolution on Windows via `_utils.py`) and proper Win32 `ctypes` buffer cleanup (`NetApiBufferFree`, `LocalFree`)
* Guard platform-specific imports and behavior cleanly (e.g., `winreg`, `pwd`/`grp`, `ctypes.windll`) so imports work on Windows, Linux, and macOS
* Write clear, readable, and well-commented code following PEP 8 where reasonable
* Keep unit tests offline and deterministic using mocks (no live system mutations or external network calls in `tests/`)

---

## Security-Focused Contributions

This tool is designed for **passive, defensive diagnostics**, not exploitation.

✅ Acceptable:

* Bug fixes
* Performance improvements
* Refactoring for readability and maintainability
* Adding safe, ethical, read-only diagnostic features

❌ Not acceptable:

* Exploit payloads, privilege escalation, or active vulnerability exploitation
* Credential harvesting, brute-forcing, or password cracking
* Bypassing OS access controls, UAC, permissions, or security protections
* Evasion techniques or offensive attack methods

---

## How to Submit a Contribution

1. Fork the repository
2. Make your changes
3. Run the unit test suite:
   * **Linux / macOS**:
     ```bash
     PYTHONPATH=src python -m unittest discover -s tests -v
     ```
   * **Windows (PowerShell)**:
     ```powershell
     $env:PYTHONPATH="src"; python -m unittest discover -s tests -v
     ```
   * Or with `pytest` (if installed via `pip install -e ".[test]"`):
     ```bash
     pytest
     ```
4. Test on at least one supported OS (`Python >=3.10`)
5. Commit with a clear message
6. Open a **Pull Request** with:
   * What you changed
   * Why it's useful
   * Any relevant notes, assumptions, or output-format impacts

---

## Reporting Bugs

When reporting a bug, please include:

* OS and version
* Python version
* Command or Python API snippet used
* Expected vs actual behavior
* Error output or JSON/CLI output (sanitized if needed)

Clear reports help fix issues faster 👍

---

## Licensing

By contributing, you agree that your contributions will be licensed under the same MIT License as this project.

---

## Thank You

Every contribution, small or large, helps improve **Secuditor CLI**.
