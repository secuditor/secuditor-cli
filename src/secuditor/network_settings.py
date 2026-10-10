# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform network adapter and configuration discovery."""

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess

import psutil

__all__ = ["NetworkSettings"]

class NetworkSettingsAudit:
    """Collect local network configuration on Windows, Linux, and macOS."""

    def __init__(self, timeout=3.0):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        """Run a command safely without a shell."""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def _prefix_from_mask(mask):
        if not mask:
            return None
        try:
            return ipaddress.ip_network(
                f"0.0.0.0/{mask}"
            ).prefixlen
        except ValueError:
            try:
                return ipaddress.ip_network(
                    f"::/{mask}"
                ).prefixlen
            except ValueError:
                return None

    @staticmethod
    def _normalize_mac(mac):
        if not mac:
            return None
        mac = mac.strip().replace("-", ":").lower()
        if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            return mac
        return None

    def _interface_addresses(self):
        result = {}

        for name, addresses in psutil.net_if_addrs().items():
            entries = []

            for address in addresses:
                if address.family == socket.AF_INET:
                    ip = address.address
                    if ip:
                        entries.append({
                            "ip": ip,
                            "version": 4,
                            "prefix_length": self._prefix_from_mask(
                                address.netmask
                            ),
                            "subnet_mask": address.netmask,
                        })

                elif address.family == socket.AF_INET6:
                    ip = address.address.split("%", 1)[0]
                    if ip:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                        except ValueError:
                            continue

                        # psutil does not consistently expose IPv6
                        # prefix lengths across operating systems.
                        entries.append({
                            "ip": ip,
                            "version": 6,
                            "prefix_length": None,
                        })

                elif getattr(psutil, "AF_LINK", None) == address.family:
                    pass

            result[name] = entries

        return result

    def _mac_addresses(self):
        result = {}

        for name, addresses in psutil.net_if_addrs().items():
            for address in addresses:
                if getattr(psutil, "AF_LINK", None) == address.family:
                    mac = self._normalize_mac(address.address)
                    if mac:
                        result[name] = mac
                        break

        return result

    def _default_gateways(self):
        gateways = {}

        if self.system == "Windows":
            output = self._run([
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' "
                "| Select-Object InterfaceAlias,NextHop "
                "| ConvertTo-Json -Compress",
            ])

            if output:
                try:
                    routes = json.loads(output)
                    if isinstance(routes, dict):
                        routes = [routes]

                    for route in routes:
                        interface = route.get("InterfaceAlias")
                        gateway = route.get("NextHop")
                        if interface and gateway:
                            try:
                                ipaddress.ip_address(gateway)
                                if not ipaddress.ip_address(gateway).is_unspecified:
                                    gateways.setdefault(interface, []).append(
                                        gateway
                                    )
                            except ValueError:
                                continue
                    return gateways
                except (json.JSONDecodeError, AttributeError):
                    pass

        elif self.system == "Linux":
            output = self._run(["ip", "route", "show", "default"])
            if output:
                for line in output.splitlines():
                    parts = line.split()
                    if "via" in parts and "dev" in parts:
                        gateway = parts[parts.index("via") + 1]
                        interface = parts[parts.index("dev") + 1]
                        gateways.setdefault(interface, []).append(gateway)

            output6 = self._run(["ip", "-6", "route", "show", "default"])
            if output6:
                for line in output6.splitlines():
                    parts = line.split()
                    if "via" in parts and "dev" in parts:
                        gateway = parts[parts.index("via") + 1]
                        interface = parts[parts.index("dev") + 1]
                        gateways.setdefault(interface, []).append(gateway)

        elif self.system == "Darwin":
            for family, flag in (
                (4, "-inet"),
                (6, "-inet6"),
            ):
                output = self._run(["route", "-n", "get", flag, "default"])
                if not output:
                    continue

                gateway = None
                interface = None
                for line in output.splitlines():
                    parts = line.strip().split(":", 1)
                    if len(parts) != 2:
                        continue
                    key, value = parts[0].strip(), parts[1].strip()
                    if key == "gateway":
                        gateway = value
                    elif key == "interface":
                        interface = value

                if gateway and interface:
                    gateways.setdefault(interface, []).append(gateway)

        for name in gateways:
            gateways[name] = list(dict.fromkeys(gateways[name]))

        return gateways

    def _dns_servers(self):
        servers = []

        if self.system == "Windows":
            output = self._run([
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-DnsClientServerAddress "
                "| ForEach-Object { $_.ServerAddresses }",
            ])
            if output:
                for line in output.splitlines():
                    value = line.strip()
                    try:
                        ipaddress.ip_address(value)
                        servers.append(value)
                    except ValueError:
                        continue

        elif self.system == "Linux":
            # systemd-resolved provides per-link DNS where available.
            output = self._run(["resolvectl", "dns"])
            if output:
                for line in output.splitlines():
                    for value in line.split(":", 1)[-1].split():
                        try:
                            ipaddress.ip_address(value)
                            servers.append(value)
                        except ValueError:
                            continue

            if not output:
                servers.extend(self._parse_resolv_conf())

        elif self.system == "Darwin":
            output = self._run(["scutil", "--dns"])
            if output:
                for line in output.splitlines():
                    match = re.search(
                        r"nameserver\[\d+\]\s*:\s*(\S+)", line
                    )
                    if match:
                        value = match.group(1)
                        try:
                            ipaddress.ip_address(value)
                            servers.append(value)
                        except ValueError:
                            continue

        return list(dict.fromkeys(servers))

    @staticmethod
    def _parse_resolv_conf():
        servers = []
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as file:
                for line in file:
                    parts = line.split("#", 1)[0].split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        try:
                            ipaddress.ip_address(parts[1])
                            servers.append(parts[1])
                        except ValueError:
                            pass
        except OSError:
            pass
        return servers

    def _dhcp_servers(self):
        servers = {}

        if self.system == "Windows":
            output = self._run([
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_NetworkAdapterConfiguration "
                "-Filter 'IPEnabled=True' "
                "| Select-Object Description, DHCPServer "
                "| ConvertTo-Json -Compress",
            ])
            if output:
                try:
                    adapters = json.loads(output)
                    if isinstance(adapters, dict):
                        adapters = [adapters]
                    for adapter in adapters:
                        name = adapter.get("Description")
                        server = adapter.get("DHCPServer")
                        if name and server:
                            servers[name] = [server]
                except (json.JSONDecodeError, AttributeError):
                    pass

        elif self.system == "Linux":
            # DHCP lease storage varies by network manager and distribution.
            # Do not infer a DHCP server from a local lease without parsing
            # the format belonging to the active network manager.

            pass

        elif self.system == "Darwin":
            # DHCP lease files are managed by macOS and can require elevated
            # permissions. Avoid assuming a lease file exists or is readable.
            pass

        return servers

    def _wifi_info(self):
        if self.system == "Windows":
            output = self._run(["netsh", "wlan", "show", "interfaces"])
            if output:
                interfaces = []
                current = {}

                for line in output.splitlines():
                    if ":" not in line:
                        continue
                    key, value = line.strip().split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if key == "name":
                        if current:
                            interfaces.append(current)
                        current = {"name": value}
                    elif key == "state":
                        current["status"] = value
                    elif key == "ssid":
                        current["ssid"] = value

                if current:
                    interfaces.append(current)

                return interfaces

        elif self.system == "Linux":
            output = self._run(["iw", "dev"])
            if output:
                interfaces = []
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "Interface":
                        interfaces.append({
                            "name": parts[1],
                            "status": "unknown",
                            "ssid": None,
                        })
                return interfaces

        elif self.system == "Darwin":
            # macOS has no stable built-in CLI for Wi-Fi SSID across
            # all supported releases and permission configurations.
            pass

        return None

    def audit(self):
        stats = psutil.net_if_stats()
        addresses = self._interface_addresses()
        macs = self._mac_addresses()
        gateways = self._default_gateways()
        dns_servers = self._dns_servers()
        dhcp_servers = self._dhcp_servers()
        wifi = self._wifi_info()

        adapters = []

        for name, entries in addresses.items():
            stat = stats.get(name)
            is_up = stat.isup if stat else None

            adapters.append({
                "name": name,
                "status": (
                    "up" if is_up is True
                    else "down" if is_up is False
                    else "unknown"
                ),
                "mac_address": macs.get(name),
                "addresses": entries,
                "gateways": gateways.get(name, []),
                "dns_servers": dns_servers,
                "dhcp_servers": dhcp_servers,
                "wifi": next(
                    (item for item in (wifi or [])
                     if item.get("name") == name),
                    None,
                ),
            })

        return {
            "platform": self.system,
            "adapters": adapters,
            "errors": [],
            "notes": [
                "Missing DHCP details mean they could not be retrieved.",
                "DNS servers may be system-wide when per-adapter mapping "
                "is unavailable.",
                "A detected gateway or local address does not prove "
                "remote reachability.",
            ],
        }


if __name__ == "__main__":
    print(json.dumps(
        NetworkSettingsAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
