# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform default gateway discovery and exposure audit."""

from concurrent.futures import ThreadPoolExecutor
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import urllib.error
import urllib.request

import psutil

try:
    import certifi
except ImportError:
    certifi = None

from ._utils import find_powershell, run_command, run_command_result, run_powershell
from .suspicious_proxy import SuspiciousProxyAudit

__all__ = ["GatewayDiscovery", "GatewayDiscoveryAudit", "GatewayAudit"]


class GatewayDiscoveryAudit:
    """Discover default gateway metadata, management exposure, NAT, and VPN state."""

    _MANAGEMENT_PORTS = {
        22: "SSH",
        23: "Telnet Exposed",
        80: "HTTP Exposed",
        443: "HTTPS",
        2222: "SSH (Alternative)",
        4443: "HTTPS (Alternative)",
        7547: "TR-069",
        8080: "HTTP Exposed",
        8291: "MikroTik Winbox",
        8443: "HTTPS (Alternative)",
        8728: "MikroTik API Exposed",
        8729: "MikroTik API-SSL",
        9443: "HTTPS Management",
        10000: "Webmin",
        10443: "HTTPS Management",
    }

    # Common gateway / router / firewall OUI prefixes (colon-delimited uppercase).
    _BUILTIN_OUI_PREFIXES = {
        # Fortinet
        "00:09:0F": "Fortinet",
        "08:5B:0E": "Fortinet",
        "70:4C:A5": "Fortinet",
        "90:6C:AC": "Fortinet",
        "E8:1C:BA": "Fortinet",
        # Cisco
        "00:00:0C": "Cisco Systems",
        "00:1A:A1": "Cisco Systems",
        "00:1B:D5": "Cisco Systems",
        "00:26:0B": "Cisco Systems",
        "3C:CE:73": "Cisco Systems",
        "68:BD:AB": "Cisco Systems",
        "D4:6D:50": "Cisco Systems",
        # Palo Alto Networks
        "00:1B:17": "Palo Alto Networks",
        "00:86:9C": "Palo Alto Networks",
        "08:30:6B": "Palo Alto Networks",
        "58:49:3B": "Palo Alto Networks",
        "D4:F4:BE": "Palo Alto Networks",
        # Check Point
        "00:1C:7F": "Check Point",
        # SonicWall
        "00:06:B1": "SonicWall",
        "00:17:C5": "SonicWall",
        "18:B1:69": "SonicWall",
        "2C:B8:ED": "SonicWall",
        "C0:EA:E4": "SonicWall",
        # WatchGuard
        "00:90:7F": "WatchGuard",
        "D4:7F:35": "WatchGuard",
        # Sophos
        "00:1A:8C": "Sophos",
        "7C:5A:1C": "Sophos",
        # MikroTik
        "08:55:31": "MikroTik",
        "18:FD:74": "MikroTik",
        "2C:C8:1B": "MikroTik",
        "48:8F:5A": "MikroTik",
        "4C:5E:0C": "MikroTik",
        "64:D1:54": "MikroTik",
        "6C:3B:6B": "MikroTik",
        "74:4D:28": "MikroTik",
        "B8:69:F4": "MikroTik",
        "C4:AD:34": "MikroTik",
        "CC:2D:E0": "MikroTik",
        "D4:01:C3": "MikroTik",
        "D4:CA:6D": "MikroTik",
        "DC:2C:6E": "MikroTik",
        "E4:8D:8C": "MikroTik",
        # Ubiquiti
        "00:15:6D": "Ubiquiti",
        "04:18:D6": "Ubiquiti",
        "18:E8:29": "Ubiquiti",
        "24:5A:4C": "Ubiquiti",
        "24:A4:3C": "Ubiquiti",
        "44:D9:E7": "Ubiquiti",
        "68:72:51": "Ubiquiti",
        "74:83:C2": "Ubiquiti",
        "78:8A:20": "Ubiquiti",
        "80:2A:A8": "Ubiquiti",
        "B4:FB:E4": "Ubiquiti",
        "DC:9F:DB": "Ubiquiti",
        "E0:63:DA": "Ubiquiti",
        "F0:9F:C2": "Ubiquiti",
        "FC:EC:DA": "Ubiquiti",
        # DrayTek
        "00:1D:AA": "DrayTek",
        "00:50:7F": "DrayTek",
        "14:49:BC": "DrayTek",
        # ASUS
        "04:D4:C4": "ASUS",
        "0C:9D:92": "ASUS",
        "10:7B:44": "ASUS",
        "1C:87:2C": "ASUS",
        "2C:FD:A1": "ASUS",
        "38:D5:47": "ASUS",
        "50:46:5D": "ASUS",
        "AC:9E:17": "ASUS",
        "B0:6E:BF": "ASUS",
        "F0:2F:74": "ASUS",
        # TP-Link
        "14:CC:20": "TP-Link",
        "1C:3B:F3": "TP-Link",
        "30:B5:C2": "TP-Link",
        "50:C7:BF": "TP-Link",
        "54:AF:97": "TP-Link",
        "60:E3:27": "TP-Link",
        "98:DA:C4": "TP-Link",
        "AC:84:C6": "TP-Link",
        "B0:BE:76": "TP-Link",
        "C0:25:E9": "TP-Link",
        "D8:07:B6": "TP-Link",
        "E8:DE:27": "TP-Link",
        "F4:F2:6D": "TP-Link",
        # Netgear
        "00:14:6C": "Netgear",
        "20:4E:7F": "Netgear",
        "28:C6:8E": "Netgear",
        "44:94:FC": "Netgear",
        "84:1B:5E": "Netgear",
        "A0:04:60": "Netgear",
        "C0:3F:0E": "Netgear",
        "E0:91:F5": "Netgear",
        # AVM (FRITZ!Box)
        "00:04:0E": "AVM",
        "00:1C:4A": "AVM",
        "08:96:D7": "AVM",
        "24:65:11": "AVM",
        "34:31:C4": "AVM",
        "38:10:D5": "AVM",
        "9C:C7:A6": "AVM",
        "C8:0E:14": "AVM",
        "DC:39:6F": "AVM",
        # Juniper
        "00:05:85": "Juniper Networks",
        "00:19:E2": "Juniper Networks",
        "2C:6B:F5": "Juniper Networks",
        # Huawei / ZTE / Technicolor / Arris / Sagemcom
        "00:E0:FC": "Huawei",
        "48:46:FB": "Huawei",
        "00:19:C6": "ZTE",
        "00:1E:73": "ZTE",
        "10:13:31": "Technicolor",
        "00:1D:CE": "Arris",
        "34:8A:AE": "Sagemcom",
        "7C:B7:33": "Sagemcom",
        # Hypervisors
        "00:05:69": "VMware",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:15:5D": "Microsoft Hyper-V",
        "08:00:27": "Oracle VirtualBox",
        "52:54:00": "QEMU/KVM",
    }

    _VPN_KEYWORDS = (
        "vpn",
        "ppp",
        "tap",
        "tun",
        "wg",
        "wireguard",
        "tailscale",
        "nordlynx",
        "zerotier",
    )

    def __init__(self, timeout=8.0, external_ip_timeout=3.0):
        self.timeout = timeout
        self.external_ip_timeout = external_ip_timeout
        self.system = platform.system()

    def _run(self, args):
        return run_command(args, timeout=self.timeout)

    @staticmethod
    def _is_valid_ip(value: str | None) -> bool:
        if not value:
            return False
        try:
            ip_obj = ipaddress.ip_address(value.split("%", 1)[0].strip())
            return not ip_obj.is_unspecified
        except ValueError:
            return False

    @staticmethod
    def _normalize_mac(raw_mac: str | None) -> str | None:
        if not raw_mac:
            return None
        cleaned = raw_mac.strip().replace("-", ":").lower()
        parts = cleaned.split(":")
        if len(parts) != 6:
            return None
        try:
            normalized = ":".join(f"{int(p, 16):02x}" for p in parts)
        except ValueError:
            return None
        if normalized in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return None
        return normalized

    # --- Default gateway discovery ---

    def get_default_gateway(self):
        """Return {'IPv4': str | None, 'IPv6': str | None} or None if not found."""
        gateways: dict[str, str | None] = {"IPv4": None, "IPv6": None}

        if self.system == "Windows":
            if find_powershell():
                routes = run_powershell(
                    "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' "
                    "-ErrorAction SilentlyContinue "
                    "| Sort-Object RouteMetric,InterfaceMetric "
                    "| Select-Object NextHop | ConvertTo-Json -Compress",
                    timeout=self.timeout,
                    parse_json=True,
                )
                if isinstance(routes, dict):
                    routes = [routes]
                if isinstance(routes, list):
                    for route in routes:
                        if not isinstance(route, dict):
                            continue
                        hop = str(route.get("NextHop") or "").strip()
                        if not self._is_valid_ip(hop):
                            continue
                        clean_hop = hop.split("%", 1)[0]
                        if ":" in clean_hop:
                            gateways["IPv6"] = gateways["IPv6"] or clean_hop
                        else:
                            gateways["IPv4"] = gateways["IPv4"] or clean_hop

            if not gateways["IPv4"] and not gateways["IPv6"]:
                out = self._run(["ipconfig.exe", "/all"]) or ""
                collecting = False
                for raw_line in out.splitlines():
                    line = raw_line.strip()
                    if "Default Gateway" in line:
                        gw = line.split(":", 1)[-1].strip()
                        if self._is_valid_ip(gw):
                            clean_gw = gw.split("%", 1)[0]
                            if ":" in clean_gw:
                                gateways["IPv6"] = gateways["IPv6"] or clean_gw
                            else:
                                gateways["IPv4"] = gateways["IPv4"] or clean_gw
                        collecting = True
                        continue
                    if collecting:
                        if self._is_valid_ip(line):
                            clean_gw = line.split("%", 1)[0]
                            if ":" in clean_gw:
                                gateways["IPv6"] = gateways["IPv6"] or clean_gw
                            else:
                                gateways["IPv4"] = gateways["IPv4"] or clean_gw
                        else:
                            collecting = False

        elif self.system == "Linux":
            out4 = self._run(["ip", "route", "show", "default"]) or ""
            for line in out4.splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts) and self._is_valid_ip(parts[idx + 1]):
                        gateways["IPv4"] = parts[idx + 1]
                        break

            if not gateways["IPv4"]:
                try:
                    with open("/proc/net/route", encoding="utf-8") as f:
                        for line in f.readlines()[1:]:
                            fields = line.split()
                            if len(fields) >= 3 and fields[1] == "00000000":
                                gw_hex = int(fields[2], 16)
                                gw_ip = socket.inet_ntoa(gw_hex.to_bytes(4, "little"))
                                if self._is_valid_ip(gw_ip):
                                    gateways["IPv4"] = gw_ip
                                    break
                except OSError:
                    pass

            out6 = self._run(["ip", "-6", "route", "show", "default"]) or ""
            for line in out6.splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts) and self._is_valid_ip(parts[idx + 1]):
                        gateways["IPv6"] = parts[idx + 1].split("%", 1)[0]
                        break

        elif self.system == "Darwin":
            for family_key, flag in (("IPv4", "-inet"), ("IPv6", "-inet6")):
                out = self._run(["route", "-n", "get", flag, "default"]) or ""
                for line in out.splitlines():
                    if ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    if k.strip().lower() == "gateway":
                        cand = v.strip().split("%", 1)[0]
                        if self._is_valid_ip(cand):
                            gateways[family_key] = cand
                            break

        if not gateways["IPv4"] and not gateways["IPv6"]:
            return None
        return gateways

    # --- Ping & ARP ---

    def ping_device(self, ip: str) -> str:
        """Send a single ICMP echo probe to `ip` and return the summary line."""
        if not self._is_valid_ip(ip):
            return "No response"
        clean_ip = ip.split("%", 1)[0].strip()
        is_v6 = ":" in clean_ip

        if self.system == "Windows":
            cmd = (
                ["ping.exe", "-6", "-n", "1", "-w", "1000", clean_ip]
                if is_v6
                else ["ping.exe", "-n", "1", "-w", "1000", clean_ip]
            )
        elif self.system == "Darwin":
            cmd = (
                ["ping6", "-c", "1", clean_ip]
                if is_v6
                else ["ping", "-c", "1", "-t", "1", clean_ip]
            )
        else:
            cmd = (
                ["ping", "-6", "-c", "1", "-W", "1", clean_ip]
                if is_v6
                else ["ping", "-c", "1", "-W", "1", clean_ip]
            )

        res = run_command_result(cmd, timeout=min(self.timeout, 4.0))
        if res is None:
            return "No response"
        _rc, stdout, _stderr = res
        for raw_line in (stdout or "").splitlines():
            line = raw_line.strip()
            if (
                line.startswith("Reply from")
                or "TTL=" in line.upper()
                or "time=" in line.lower()
            ):
                return line
            if "request timed out" in line.lower():
                return "Request timed out"
        return "No response"

    def get_mac_from_arp(self, ip: str | None) -> str | None:
        """Look up the gateway MAC address from the OS ARP/neighbor table."""
        if not ip or ":" in str(ip):
            return None
        ip_key = str(ip).strip()
        mac_re = re.compile(r"\b(?:[0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2}\b")

        if self.system == "Windows":
            out = self._run(["arp.exe", "-a"]) or ""
            for line in out.splitlines():
                tokens = line.split()
                if tokens and tokens[0] == ip_key:
                    m = mac_re.search(line)
                    if m:
                        return self._normalize_mac(m.group(0))
        elif self.system == "Linux":
            if shutil.which("ip"):
                out = self._run(["ip", "neigh", "show", ip_key]) or ""
                for line in out.splitlines():
                    m = mac_re.search(line)
                    if m:
                        return self._normalize_mac(m.group(0))
            try:
                with open("/proc/net/arp", encoding="utf-8") as f:
                    for line in f.readlines()[1:]:
                        fields = line.split()
                        if len(fields) >= 4 and fields[0] == ip_key:
                            return self._normalize_mac(fields[3])
            except OSError:
                pass
        elif self.system == "Darwin":
            out = self._run(["arp", "-n", ip_key]) or ""
            for line in out.splitlines():
                m = mac_re.search(line)
                if m:
                    return self._normalize_mac(m.group(0))

        return None

    # --- Vendor lookup & classification ---

    @staticmethod
    def _lookup_system_oui(oui_colon: str) -> str | None:
        """Search common local IEEE OUI files on POSIX hosts without network access."""
        oui_hex = oui_colon.replace(":", "").upper()
        oui_dash = oui_colon.replace(":", "-").upper()
        for path in (
            "/usr/share/ieee-data/oui.txt",
            "/usr/share/misc/oui.txt",
            "/usr/share/hwdata/oui.txt",
        ):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith(oui_dash) or line.startswith(oui_hex):
                            parts = re.split(r"\(hex\)|\(base 16\)", line, maxsplit=1)
                            if len(parts) == 2 and parts[1].strip():
                                return parts[1].strip()
            except OSError:
                continue
        return None

    @staticmethod
    def classify_gateway_device(vendor: str | None, fingerprint_text: str = "") -> str:
        """Classify gateway device type from HTTP/TLS fingerprints and vendor name."""
        if not vendor or vendor == "Unknown":
            return "Unknown"

        vendor_l = vendor.lower()
        fp = (fingerprint_text or "").lower()

        if any(x in fp for x in ("fortigate", "fortios")):
            return "Firewall"
        if any(
            x in fp
            for x in ("cisco adaptive security appliance", "cisco asa", "firepower")
        ):
            return "Firewall"
        if any(x in fp for x in ("cisco ios", "integrated services router")):
            return "Router"
        if any(x in fp for x in ("pan-os", "palo alto networks")):
            return "Firewall"
        if any(x in fp for x in ("gaia portal", "check point")):
            return "Firewall"
        if "sonicwall" in fp:
            return "Firewall"
        if any(x in fp for x in ("fireware", "watchguard")):
            return "Firewall"
        if any(x in fp for x in ("mikrotik", "routeros")):
            return "Router"
        if any(
            x in fp
            for x in ("unifi security gateway", "unifi dream machine", "edgeos")
        ):
            return "Security Gateway"

        firewall_vendors = (
            "fortinet",
            "palo alto",
            "check point",
            "sonicwall",
            "watchguard",
            "sophos",
            "barracuda",
        )
        if any(x in vendor_l for x in firewall_vendors):
            return "Firewall"

        router_vendors = ("mikrotik", "draytek", "asus", "avm", "tp-link", "netgear")
        if any(x in vendor_l for x in router_vendors):
            return "Router"

        return "Other Type"

    def lookup_vendor(
        self,
        mac: str | None,
        device_ip: str | None = None,
        fingerprint_text: str = "",
        ping_reply: str | None = None,
    ) -> str:
        """Resolve gateway vendor from MAC OUI, local-admin bit, or TTL fallback."""
        if not mac:
            return "Unknown"

        norm_mac = self._normalize_mac(mac)
        if not norm_mac:
            return "Unknown"

        vendor = "Unknown"
        try:
            first_byte = int(norm_mac.split(":", 1)[0], 16)
            if first_byte & 0b00000010:
                vendor = "Virtual/Software MAC"
        except ValueError:
            pass

        if vendor == "Unknown":
            oui = norm_mac[:8].upper()
            vendor = (
                self._BUILTIN_OUI_PREFIXES.get(oui)
                or self._lookup_system_oui(oui)
                or "Unknown"
            )

        if vendor == "Unknown" and (ping_reply or device_ip):
            reply = ping_reply if ping_reply is not None else self.ping_device(device_ip)
            ttl_match = re.search(r"TTL=(\d+)", reply or "", re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    vendor = "Likely Linux/Unix device"
                elif ttl <= 128:
                    vendor = "Likely Windows device"
                elif ttl <= 255:
                    vendor = "Likely network appliance / router"

        if vendor in (
            "Unknown",
            "Virtual/Software MAC",
            "Likely Linux/Unix device",
            "Likely Windows device",
            "Likely network appliance / router",
        ):
            return vendor

        device_type = self.classify_gateway_device(vendor, fingerprint_text)
        return f"{vendor} ({device_type})"

    # --- Interface CIDR & MTU (pure psutil) ---

    @staticmethod
    def _active_interface_info(gateway_ip: str | None):
        """Return (local_ip, cidr_str, mtu_str) for the interface hosting `gateway_ip`."""
        if not gateway_ip:
            return None, "Unavailable", "Unavailable"
        if ":" in gateway_ip:
            return None, "IPv6 Only / Unavailable", "IPv6 Only / Unavailable"

        try:
            gw_obj = ipaddress.ip_address(gateway_ip)
        except ValueError:
            return None, "Unavailable", "Unavailable"

        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family != socket.AF_INET or not addr.address or not addr.netmask:
                    continue
                try:
                    iface_ip = ipaddress.ip_address(addr.address)
                    if iface_ip.is_loopback or iface_ip.is_link_local:
                        continue
                    net = ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                    if gw_obj in net:
                        iface_stat = stats.get(iface)
                        mtu_val = (
                            f"{iface_stat.mtu} bytes"
                            if iface_stat and getattr(iface_stat, "mtu", 0) > 0
                            else "Unavailable"
                        )
                        return addr.address, str(net), mtu_val
                except ValueError:
                    continue

        return None, "Unavailable", "Unavailable"

    # --- Management port & web UI inspection ---

    @staticmethod
    def _check_http_redirect(ip: str) -> bool:
        conn = None
        try:
            conn = http.client.HTTPConnection(ip, 80, timeout=1.5)
            conn.request("HEAD", "/", headers={"User-Agent": "Secuditor"})
            resp = conn.getresponse()
            loc = resp.getheader("Location", "") or ""
            return resp.status in (301, 302, 303, 307, 308) and loc.lower().startswith(
                "https://"
            )
        except Exception:
            return False
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def detect_management_ports(self, ip: str | None) -> str:
        """Probe common gateway TCP management ports concurrently."""
        ip_key = str(ip or "").strip()
        if not ip_key:
            return "Unable to scan"

        def _check(port: int):
            try:
                with socket.create_connection((ip_key, port), timeout=0.7):
                    return port
            except OSError:
                return None

        try:
            with ThreadPoolExecutor(max_workers=10) as pool:
                open_ports = sorted(
                    p for p in pool.map(_check, self._MANAGEMENT_PORTS.keys()) if p is not None
                )
        except Exception:
            return "Unable to scan"

        if not open_ports:
            return "No common management ports detected"

        detected = []
        for port in open_ports:
            service = self._MANAGEMENT_PORTS[port]
            if port == 80 and self._check_http_redirect(ip_key):
                service = "HTTP Redirected"
            detected.append(f"{service} ({port})")
        return ", ".join(detected)

    def check_http_access(self, ip: str | None) -> tuple[str, str]:
        """Check gateway HTTP/HTTPS web UI and collect light Server/Title fingerprint."""
        if not ip:
            return "No web interface detected", ""

        clean_ip = ip.split("%", 1)[0].strip()
        fingerprint_parts: list[str] = []

        for scheme, port in (("http", 80), ("https", 443)):
            conn = None
            try:
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(
                        clean_ip, port, timeout=2.5, context=ctx
                    )
                else:
                    conn = http.client.HTTPConnection(clean_ip, port, timeout=2.5)

                conn.request("GET", "/", headers={"User-Agent": "Secuditor"})
                resp = conn.getresponse()
                body = resp.read(4096).decode("utf-8", errors="ignore")
                server_hdr = resp.getheader("Server") or ""
                if server_hdr:
                    fingerprint_parts.append(server_hdr)
                title_m = re.search(
                    r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL
                )
                if title_m:
                    fingerprint_parts.append(title_m.group(1).strip())
                if resp.status < 500:
                    return (
                        f"{scheme.upper()} Responding ({resp.status})",
                        " ".join(fingerprint_parts),
                    )
            except ssl.SSLError:
                if scheme == "https":
                    return (
                        "HTTPS Responding (Self-Signed/Untrusted Cert)",
                        " ".join(fingerprint_parts),
                    )
            except Exception:
                continue
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

        return "No web interface detected", " ".join(fingerprint_parts)

    # --- External IP, NAT, VPN & Proxy ---

    def get_external_ip(self) -> str:
        """Discover external/public IPv4 address using HTTPS (stdlib urllib)."""
        contexts = [ssl.create_default_context()]
        if certifi is not None:
            contexts.append(ssl.create_default_context(cafile=certifi.where()))

        for ctx in contexts:
            try:
                req = urllib.request.Request(
                    "https://api.ipify.org",
                    headers={"User-Agent": "Secuditor"},
                )
                with urllib.request.urlopen(
                    req, timeout=self.external_ip_timeout, context=ctx
                ) as resp:
                    candidate = resp.read(128).decode("utf-8", errors="ignore").strip()
                    if self._is_valid_ip(candidate):
                        return candidate
            except ssl.SSLError:
                continue
            except (urllib.error.URLError, OSError, ValueError):
                break
        return "Unavailable"

    @staticmethod
    def detect_nat(local_ip: str | None, external_ip: str | None) -> str:
        """Compare active local IPv4 address against external public IP."""
        if not local_ip or not external_ip or external_ip == "Unavailable":
            return "Unable to determine"
        return "Detected" if local_ip != external_ip else "Not Detected"

    def detect_vpn(self) -> str:
        """Detect active VPN tunnel adapters via psutil."""
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            active = []
            for name, st in stats.items():
                if not getattr(st, "isup", False):
                    continue
                low = name.lower()
                if self.system == "Darwin" and low.startswith("utun"):
                    # macOS creates default utun interfaces; require a non-link-local IP.
                    has_routable = False
                    for a in addrs.get(name, []):
                        if a.family in (socket.AF_INET, socket.AF_INET6) and a.address:
                            try:
                                ip_obj = ipaddress.ip_address(a.address.split("%", 1)[0])
                                if not ip_obj.is_link_local and not ip_obj.is_loopback:
                                    has_routable = True
                                    break
                            except ValueError:
                                continue
                    if has_routable:
                        active.append(name)
                elif any(kw in low for kw in self._VPN_KEYWORDS):
                    active.append(name)
            if active:
                return f"Enabled ({', '.join(active)})"
            return "Not Detected"
        except Exception:
            return "Unknown"

    def get_proxy_configuration(self) -> str:
        """Return a concise cross-platform proxy configuration summary."""
        try:
            prx = SuspiciousProxyAudit(timeout=min(self.timeout, 5.0)).audit()
            cfg = prx.get("configuration") or {}
            items = []
            manual = cfg.get("system_manual")
            if manual and manual != "Disabled":
                items.append(f"Manual: {manual}")
            pac = cfg.get("system_pac")
            if pac and pac != "None":
                items.append(f"PAC: {pac}")
            if cfg.get("autodetect_wpad"):
                items.append("WPAD AutoDetect: Enabled")
            winhttp = cfg.get("winhttp_proxy")
            if winhttp and winhttp not in ("Direct Access", "Unable to determine"):
                items.append(f"WinHTTP: {winhttp}")
            env_p = cfg.get("env_proxy")
            if env_p and env_p != "None":
                items.append(f"Env: {env_p}")
            return "; ".join(items) if items else "No Proxy Detected"
        except Exception:
            return "Unable to determine"

    def detect_gateway_device(self):
        """Run full gateway discovery and return a structured dictionary."""
        gateways = self.get_default_gateway()
        if not gateways:
            return {
                "platform": self.system,
                "hostname": platform.node(),
                "gateway": {
                    "ip": "Not Found",
                    "ipv6": None,
                    "mac": "Unknown",
                    "vendor": "Unknown",
                    "ping": "Unknown",
                    "network_cidr": "Unavailable",
                    "mtu": "Unavailable",
                },
                "exposure": {
                    "management_ports": "Unable to scan",
                    "web_interface": "No web interface detected",
                    "proxy_configuration": self.get_proxy_configuration(),
                },
                "connectivity": {
                    "nat": "Unable to determine",
                    "vpn": self.detect_vpn(),
                    "public_ip": "Unavailable",
                },
            }

        gw_v4 = gateways.get("IPv4")
        gw_v6 = gateways.get("IPv6")
        gw_ip = gw_v4 or gw_v6

        ping_reply = self.ping_device(gw_ip)
        mac = self.get_mac_from_arp(gw_ip)
        web_ui, fingerprint = self.check_http_access(gw_ip)
        vendor = self.lookup_vendor(
            mac,
            device_ip=gw_ip,
            fingerprint_text=fingerprint,
            ping_reply=ping_reply,
        )
        local_ip, cidr, mtu = self._active_interface_info(gw_v4 or gw_ip)
        mgmt_ports = self.detect_management_ports(gw_ip)
        public_ip = self.get_external_ip()
        nat = self.detect_nat(local_ip, public_ip)

        return {
            "platform": self.system,
            "hostname": platform.node(),
            "gateway": {
                "ip": gw_ip,
                "ipv6": gw_v6,
                "mac": mac or "Unknown",
                "vendor": vendor,
                "ping": ping_reply,
                "network_cidr": cidr,
                "mtu": mtu,
            },
            "exposure": {
                "management_ports": mgmt_ports,
                "web_interface": web_ui,
                "proxy_configuration": self.get_proxy_configuration(),
            },
            "connectivity": {
                "nat": nat,
                "vpn": self.detect_vpn(),
                "public_ip": public_ip,
            },
        }

    def audit(self):
        """Run the gateway discovery audit and return a structured report."""
        return self.detect_gateway_device()


GatewayDiscovery = GatewayDiscoveryAudit
GatewayAudit = GatewayDiscoveryAudit

if __name__ == "__main__":
    print(json.dumps(
        GatewayDiscoveryAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
