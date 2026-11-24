# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform proxy configuration and suspicious local proxy audit."""

import ipaddress
import json
import os
import platform
import re
import shutil
from urllib.parse import urlparse

import psutil

from ._utils import (
    read_registry_value,
    run_command,
    run_command_result,
    run_powershell,
)
from .ssl_interception import LEGIT_ISSUERS

__all__ = ["SuspiciousProxy", "SuspiciousProxyAudit", "ProxyAudit"]


class SuspiciousProxyAudit:
    """Inspect system/environment proxies, PAC scripts, and local proxy listeners."""

    _KNOWN_TUNNEL_TOOLS = {
        "chisel",
        "ngrok",
        "frpc",
        "frps",
        "gost",
        "mitmdump",
        "mitmweb",
        "mitmproxy",
        "fiddler",
        "burpsuite",
        "socat",
        "plink",
        "proxifier",
        "tor",
        "stunnel",
    }
    _LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
    _TOR_PORTS = {9050, 9150}

    _WINDOWS_SUSPICIOUS_LOCATIONS = (
        "\\appdata\\roaming\\",
        "\\appdata\\local\\temp\\",
        "\\temp\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\documents\\",
        "\\public\\",
        "\\programdata\\",
        "\\recycler\\",
        "\\$recycle.bin\\",
        "\\perflogs\\",
        "\\appdata\\local\\microsoft\\windows\\inetcache\\",
        "\\appdata\\local\\microsoft\\windows\\iedownloads\\",
        "\\appdata\\local\\packages\\",
        "\\windows\\temp\\",
        "\\windows\\tracing\\",
        "\\windows\\debug\\",
        "\\windows\\fonts\\",
        "\\windows\\help\\",
        "\\windows\\tasks\\",
    )

    _POSIX_SUSPICIOUS_LOCATIONS = (
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/downloads/",
        "/desktop/",
    )

    def __init__(self, timeout=8.0):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        return run_command(args, timeout=self.timeout)

    @classmethod
    def _is_loopback_host(cls, host: str | None) -> bool:
        if not host:
            return False
        cleaned = host.strip().lower()
        if cleaned in cls._LOCALHOST_HOSTS:
            return True
        try:
            return ipaddress.ip_address(cleaned.strip("[]")).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _parse_proxy_endpoints(raw_value: str | None) -> list[tuple[str, str, int | None]]:
        """Parse proxy strings (WinINET/WinHTTP/URLs) into (scheme, host, port) tuples."""
        endpoints = []
        if not isinstance(raw_value, str) or not raw_value.strip():
            return endpoints

        default_ports = {
            "http": 80,
            "https": 443,
            "socks": 1080,
            "socks4": 1080,
            "socks5": 1080,
        }

        for part in re.split(r"[;\s]+", raw_value.strip()):
            item = part.strip()
            if not item:
                continue

            scheme = "http"
            kv_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)=(.+)$", item)
            if kv_match:
                scheme = kv_match.group(1).strip().lower() or "http"
                item = kv_match.group(2).strip()
                if not item:
                    continue

            candidate = item if "://" in item else f"{scheme}://{item}"
            try:
                parsed = urlparse(candidate)
                host = (parsed.hostname or "").strip().lower()
                parsed_scheme = (parsed.scheme or scheme).lower()
                port = parsed.port
                if port is None:
                    port = default_ports.get(parsed_scheme)
                if host:
                    endpoints.append((parsed_scheme, host, port))
            except Exception:
                continue

        return endpoints

    @staticmethod
    def _is_public_ip(host: str | None) -> bool:
        if not host:
            return False
        try:
            ip_obj = ipaddress.ip_address(host.strip("[]"))
            return not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )
        except ValueError:
            return False

    @staticmethod
    def _is_ip_literal(host: str | None) -> bool:
        if not host:
            return False
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            return False

    def _get_binary_signature(self, path: str) -> tuple[str, str]:
        """Return (status, signer) for a listener binary where supported."""
        if not path:
            return "Unknown", ""

        if self.system == "Windows":
            data = run_powershell(
                "$s = Get-AuthenticodeSignature -LiteralPath $env:SECUDITOR_SIG_PATH; "
                "[PSCustomObject]@{ Status = [string]$s.Status; "
                "Signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' } } "
                "| ConvertTo-Json -Compress",
                timeout=min(self.timeout, 5.0),
                parse_json=True,
                extra_env={"SECUDITOR_SIG_PATH": path},
            )
            if isinstance(data, dict):
                return (data.get("Status") or "Unknown"), (data.get("Signer") or "")
            return "Unknown", ""

        if self.system == "Darwin" and shutil.which("codesign"):
            verify_res = run_command_result(
                ["codesign", "--verify", "--strict", path],
                timeout=min(self.timeout, 5.0),
            )
            if verify_res is None:
                return "Unknown", ""
            rc, _out, _err = verify_res
            if rc != 0:
                return "Unsigned", ""
            detail_res = run_command_result(
                ["codesign", "-dv", path],
                timeout=min(self.timeout, 5.0),
            )
            signer = ""
            if detail_res is not None:
                text = (detail_res[1] or "") + "\n" + (detail_res[2] or "")
                m = re.search(r"^Authority=(.+)$", text, re.MULTILINE)
                if m:
                    signer = m.group(1).strip()
            return "Valid", signer

        return "Not Applicable", ""

    def _find_listener_for_port(self, port: int | None, target_host: str | None = None):
        """Find listening socket owner process on `port`."""
        if not port:
            return None
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return None

        target_clean = (target_host or "").strip("[]").lower()
        for conn in conns:
            if (
                conn.status != psutil.CONN_LISTEN
                or not conn.laddr
                or conn.laddr.port != port
            ):
                continue
            lip = (conn.laddr.ip or "").lower()
            if target_clean in ("127.0.0.1", "localhost"):
                if lip not in ("127.0.0.1", "0.0.0.0", "::", "::1"):
                    continue
            elif target_clean == "::1":
                if lip not in ("::1", "::", "0.0.0.0"):
                    continue

            pid = conn.pid
            name, exe = "Unknown", ""
            if pid:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name() or "Unknown"
                    exe = proc.exe() or ""
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass

            sig_status, signer = self._get_binary_signature(exe)
            return {
                "pid": pid,
                "name": name,
                "path": exe,
                "signature": sig_status,
                "signer": signer,
            }
        return None

    # --- Platform collectors ---

    @staticmethod
    def _collect_wininet():
        user_sub = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        policy_sub = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"

        def _clean(val):
            s = str(val).strip() if val is not None else ""
            return s or None

        hkcu_enable = read_registry_value("HKCU", user_sub, "ProxyEnable") or 0
        hkcu_server = _clean(read_registry_value("HKCU", user_sub, "ProxyServer"))
        hkcu_pac = _clean(read_registry_value("HKCU", user_sub, "AutoConfigURL"))
        hkcu_auto = bool(read_registry_value("HKCU", user_sub, "AutoDetect") or 0)

        hklm_enable = read_registry_value("HKLM", user_sub, "ProxyEnable") or 0
        hklm_server = _clean(read_registry_value("HKLM", user_sub, "ProxyServer"))
        hklm_pac = _clean(read_registry_value("HKLM", user_sub, "AutoConfigURL"))

        pol_per_user = read_registry_value("HKLM", policy_sub, "ProxySettingsPerUser")
        pol_enable = read_registry_value("HKLM", policy_sub, "ProxyEnable") or 0
        pol_server = _clean(read_registry_value("HKLM", policy_sub, "ProxyServer"))
        pol_pac = _clean(read_registry_value("HKLM", policy_sub, "AutoConfigURL"))

        manual = None
        raw_manual = ""
        if pol_per_user == 0:
            sources = [
                (hklm_enable, hklm_server, "[HKLM] "),
                (pol_enable, pol_server, "[Policy] "),
                (hkcu_enable, hkcu_server, ""),
            ]
            pac = hklm_pac or pol_pac or hkcu_pac
        else:
            sources = [
                (hkcu_enable, hkcu_server, ""),
                (hklm_enable, hklm_server, "[HKLM] "),
                (pol_enable, pol_server, "[Policy] "),
            ]
            pac = hkcu_pac or hklm_pac or pol_pac

        for enabled, server, prefix in sources:
            if enabled and server:
                manual = f"{prefix}{server}"
                raw_manual = server
                break

        return {
            "manual": manual,
            "raw_manual": raw_manual,
            "pac": pac,
            "autodetect": hkcu_auto,
            "policy_enforced": bool(pol_enable and (pol_server or pol_pac))
            or (pol_per_user == 0),
        }

    def _collect_winhttp(self):
        out = self._run(["netsh.exe", "winhttp", "show", "proxy"])
        if not out:
            return "Unable to determine", ""
        if "direct access" in out.lower():
            return "Direct Access", ""
        m = re.search(r"Proxy Server\(s\)\s*:\s*(.+)", out, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            return val, val
        return "Configured / Unknown", ""

    def _collect_portproxy_rules(self):
        rules = []
        out = self._run(["netsh.exe", "interface", "portproxy", "show", "all"])
        if not out:
            return rules
        for line in out.splitlines():
            m = re.match(r"^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$", line)
            if m:
                listen_ip, listen_port, conn_ip, conn_port = m.groups()
                rules.append(f"{listen_ip}:{listen_port} -> {conn_ip}:{conn_port}")
        return rules

    def _collect_linux_system_proxy(self):
        manual_parts = []
        pac = None
        autodetect = False

        if shutil.which("gsettings"):
            mode = (
                self._run(["gsettings", "get", "org.gnome.system.proxy", "mode"]) or ""
            ).strip().strip("'\"")
            if mode == "manual":
                for schema_suffix, scheme in (
                    ("http", "http"),
                    ("https", "https"),
                    ("socks", "socks5"),
                ):
                    host = (
                        self._run([
                            "gsettings",
                            "get",
                            f"org.gnome.system.proxy.{schema_suffix}",
                            "host",
                        ])
                        or ""
                    ).strip().strip("'\"")
                    port_raw = (
                        self._run([
                            "gsettings",
                            "get",
                            f"org.gnome.system.proxy.{schema_suffix}",
                            "port",
                        ])
                        or ""
                    ).strip()
                    if host:
                        port_part = (
                            f":{port_raw}"
                            if port_raw.isdigit() and int(port_raw) > 0
                            else ""
                        )
                        manual_parts.append(f"{scheme}={host}{port_part}")
            elif mode == "auto":
                pac_raw = (
                    self._run([
                        "gsettings",
                        "get",
                        "org.gnome.system.proxy",
                        "autoconfig-url",
                    ])
                    or ""
                ).strip().strip("'\"")
                if pac_raw:
                    pac = pac_raw
                else:
                    autodetect = True

        raw_manual = ";".join(manual_parts)
        return {
            "manual": raw_manual or None,
            "raw_manual": raw_manual,
            "pac": pac,
            "autodetect": autodetect,
            "policy_enforced": False,
        }

    def _collect_macos_system_proxy(self):
        manual_parts = []
        pac = None
        autodetect = False

        out = self._run(["scutil", "--proxy"])
        if out:
            kv = {}
            for line in out.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                kv[k.strip()] = v.strip()

            for prefix, scheme in (
                ("HTTP", "http"),
                ("HTTPS", "https"),
                ("SOCKS", "socks5"),
            ):
                if kv.get(f"{prefix}Enable") == "1" and kv.get(f"{prefix}Proxy"):
                    host = kv[f"{prefix}Proxy"]
                    port = kv.get(f"{prefix}Port")
                    port_part = (
                        f":{port}" if port and port.isdigit() and int(port) > 0 else ""
                    )
                    manual_parts.append(f"{scheme}={host}{port_part}")

            if kv.get("ProxyAutoConfigEnable") == "1":
                pac = kv.get("ProxyAutoConfigURLString") or None
            if kv.get("ProxyAutoDiscoveryEnable") == "1":
                autodetect = True

        raw_manual = ";".join(manual_parts)
        return {
            "manual": raw_manual or None,
            "raw_manual": raw_manual,
            "pac": pac,
            "autodetect": autodetect,
            "policy_enforced": False,
        }

    def _collect_env_proxies(self):
        vars_to_check = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
        found = {}

        for key in vars_to_check:
            val = os.environ.get(key) or os.environ.get(key.lower())
            if val and str(val).strip():
                found[key] = str(val).strip()

        if self.system == "Windows":
            for hive, subkey in (
                ("HKCU", r"Environment"),
                (
                    "HKLM",
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                ),
            ):
                for key in vars_to_check:
                    if key in found:
                        continue
                    val = read_registry_value(hive, subkey, key)
                    if val and str(val).strip():
                        found[key] = str(val).strip()
        elif self.system == "Linux":
            try:
                with open(
                    "/etc/environment", encoding="utf-8", errors="replace"
                ) as f:
                    for line in f:
                        line = line.split("#", 1)[0].strip()
                        if "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k_up = k.strip().upper()
                        v_clean = v.strip().strip("'\"")
                        if k_up in vars_to_check and v_clean and k_up not in found:
                            found[k_up] = v_clean
            except OSError:
                pass

        return found

    def check_suspicious_proxy(self):
        """Inspect proxy settings and listeners and return a structured report."""
        try:
            if self.system == "Windows":
                sys_proxy = self._collect_wininet()
                winhttp_display, winhttp_raw = self._collect_winhttp()
                portproxy_rules = self._collect_portproxy_rules()
                suspicious_locs = self._WINDOWS_SUSPICIOUS_LOCATIONS
            elif self.system == "Linux":
                sys_proxy = self._collect_linux_system_proxy()
                winhttp_display, winhttp_raw = None, ""
                portproxy_rules = []
                suspicious_locs = self._POSIX_SUSPICIOUS_LOCATIONS
            elif self.system == "Darwin":
                sys_proxy = self._collect_macos_system_proxy()
                winhttp_display, winhttp_raw = None, ""
                portproxy_rules = []
                suspicious_locs = self._POSIX_SUSPICIOUS_LOCATIONS
            else:
                sys_proxy = {
                    "manual": None,
                    "raw_manual": "",
                    "pac": None,
                    "autodetect": False,
                    "policy_enforced": False,
                }
                winhttp_display, winhttp_raw = None, ""
                portproxy_rules = []
                suspicious_locs = self._POSIX_SUSPICIOUS_LOCATIONS

            env_proxies = self._collect_env_proxies()

            endpoints = []
            if sys_proxy["raw_manual"]:
                endpoints.extend(
                    self._parse_proxy_endpoints(sys_proxy["raw_manual"])
                )
            if winhttp_raw:
                endpoints.extend(self._parse_proxy_endpoints(winhttp_raw))
            for val in env_proxies.values():
                endpoints.extend(self._parse_proxy_endpoints(val))

            proxy_detected = bool(
                sys_proxy["manual"]
                or sys_proxy["pac"]
                or winhttp_raw
                or env_proxies
                or portproxy_rules
            )

            triggers = []
            high_risk_triggers = set()

            target_host = None
            target_port = None
            listener_info = None

            for scheme, host, port in endpoints:
                if target_host is None:
                    target_host, target_port = host, port

                if scheme.startswith("socks") or port in self._TOR_PORTS:
                    msg = f"SOCKS/Tor proxy configured ({host}:{port or '?'})"
                    if msg not in triggers:
                        triggers.append(msg)
                        high_risk_triggers.add(msg)

                if self._is_public_ip(host):
                    msg = f"Public IP proxy target ({host})"
                    if msg not in triggers:
                        triggers.append(msg)
                        high_risk_triggers.add(msg)

                if self._is_loopback_host(host) and port:
                    info = self._find_listener_for_port(port, host)
                    if listener_info is None:
                        listener_info = info
                    if not info:
                        msg = f"Unowned/inactive local proxy on port {port}"
                        if msg not in triggers:
                            triggers.append(msg)
                    else:
                        proc_stem = os.path.splitext(
                            (info.get("name") or "").lower()
                        )[0]
                        proc_path_l = os.path.normcase(
                            info.get("path") or ""
                        ).lower()
                        sig = info.get("signature", "Unknown")

                        if proc_stem in self._KNOWN_TUNNEL_TOOLS:
                            msg = (
                                f"Tunnel/MITM tool listening on port {port} "
                                f"({info.get('name')})"
                            )
                            if msg not in triggers:
                                triggers.append(msg)
                                high_risk_triggers.add(msg)

                        if proc_path_l and any(
                            loc in proc_path_l for loc in suspicious_locs
                        ):
                            msg = (
                                f"Local proxy running from suspicious path "
                                f"({info.get('name')})"
                            )
                            if msg not in triggers:
                                triggers.append(msg)
                                high_risk_triggers.add(msg)

                        if sig not in ("Valid", "Not Applicable"):
                            msg = (
                                f"Untrusted/unsigned local proxy listener "
                                f"({info.get('name')}: {sig})"
                            )
                            if msg not in triggers:
                                triggers.append(msg)
                                high_risk_triggers.add(msg)

            # Evaluate PAC URL
            pac_url = sys_proxy["pac"]
            if pac_url:
                pac_lower = pac_url.lower()
                if pac_lower.startswith("file:") or pac_url.startswith("\\\\"):
                    msg = f"Local/UNC PAC script ({pac_url})"
                    triggers.append(msg)
                    high_risk_triggers.add(msg)
                else:
                    parsed_pac = urlparse(pac_url)
                    if parsed_pac.scheme.lower() == "http":
                        msg = (
                            f"Unencrypted HTTP PAC URL "
                            f"({parsed_pac.hostname or pac_url})"
                        )
                        triggers.append(msg)
                        high_risk_triggers.add(msg)
                    if parsed_pac.hostname and self._is_ip_literal(
                        parsed_pac.hostname
                    ):
                        msg = f"IP-literal PAC host ({parsed_pac.hostname})"
                        triggers.append(msg)
                        high_risk_triggers.add(msg)

            # Evaluate Windows netsh portproxy rules
            if portproxy_rules:
                msg = f"Active netsh portproxy rule ({len(portproxy_rules)})"
                triggers.append(msg)
                high_risk_triggers.add(msg)

            # Determine legitimacy
            legit = False
            legit_reason = None
            if listener_info and listener_info.get("signature") == "Valid":
                signer_l = (listener_info.get("signer") or "").lower()
                for vendor in LEGIT_ISSUERS:
                    if vendor.lower() in signer_l:
                        legit = True
                        legit_reason = f"Signed by {vendor}"
                        break
                if not legit and "microsoft" in signer_l:
                    legit = True
                    legit_reason = "Signed by Microsoft"
                if not legit and "apple" in signer_l:
                    legit = True
                    legit_reason = "Signed by Apple"

            if (
                not legit
                and sys_proxy["policy_enforced"]
                and not high_risk_triggers
            ):
                legit = True
                legit_reason = "Enforced by system policy"

            if not proxy_detected and not triggers:
                verdict = "Not Detected"
                reason = None
            elif not triggers:
                verdict = "Likely Legitimate"
                reason = (
                    legit_reason
                    or "Proxy configured with no suspicious indicators"
                )
            elif legit and not high_risk_triggers:
                verdict = "Likely Legitimate"
                reason = legit_reason
            else:
                verdict = "Suspicious"
                reason = ", ".join(triggers)

            env_summary = (
                ", ".join(f"{k}={v}" for k, v in env_proxies.items())
                if env_proxies
                else "None"
            )

            configuration = {
                "system_manual": sys_proxy["manual"] or "Disabled",
                "system_pac": pac_url or "None",
                "autodetect_wpad": sys_proxy["autodetect"],
                "env_proxy": env_summary,
            }
            if self.system == "Windows":
                configuration["winhttp_proxy"] = winhttp_display
                configuration["portproxy_rules"] = portproxy_rules

            return {
                "platform": self.system,
                "hostname": platform.node(),
                "analysis": {
                    "verdict": verdict,
                    "proxy_detected": proxy_detected,
                    "proxy_legit": legit,
                    "proxy_reason": reason,
                    "triggers": triggers,
                },
                "configuration": configuration,
                "listener": {
                    "target_host": target_host or "N/A",
                    "target_port": (
                        target_port if target_port is not None else "N/A"
                    ),
                    "owner_process": (
                        f"{listener_info.get('name')} (PID: {listener_info.get('pid')})"
                        if listener_info
                        else "N/A"
                    ),
                    "owner_path": (
                        (listener_info.get("path") or "N/A")
                        if listener_info
                        else "N/A"
                    ),
                    "owner_signature": (
                        listener_info.get("signature", "N/A")
                        if listener_info
                        else "N/A"
                    ),
                    "owner_signer": (
                        (listener_info.get("signer") or "N/A")
                        if listener_info
                        else "N/A"
                    ),
                },
            }

        except Exception as exc:
            return {
                "platform": self.system,
                "hostname": platform.node(),
                "error": str(exc),
                "analysis": {
                    "verdict": "Unknown",
                    "proxy_detected": False,
                    "proxy_legit": False,
                    "proxy_reason": str(exc),
                    "triggers": [],
                },
                "configuration": {},
                "listener": {},
            }

    def audit(self):
        """Run the suspicious proxy audit and return a structured report."""
        return self.check_suspicious_proxy()


SuspiciousProxy = SuspiciousProxyAudit
ProxyAudit = SuspiciousProxyAudit

if __name__ == "__main__":
    print(json.dumps(
        SuspiciousProxyAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
