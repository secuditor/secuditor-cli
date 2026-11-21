# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform network adapter and configuration discovery."""

import ipaddress
import json
import platform
import re
import shutil
import socket

import psutil

from ._utils import run_command, run_command_result, run_powershell

__all__ = ["NetworkSettings", "NetworkSettingsAudit"]

class NetworkSettingsAudit:
    """Collect local network configuration on Windows, Linux, and macOS."""

    def __init__(self, timeout=3.0):
        self.timeout = timeout
        self.system = platform.system()

    def _run(self, args):
        """Run a command safely without a shell."""
        return run_command(args, timeout=self.timeout, strip=False)

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
        if (
            re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
            and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
        ):
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
                            ipaddress.ip_address(ip)
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

    def _windows_network_ps_data(self):
        """Collect Windows routes, DNS, DHCP, and Wi-Fi adapters in one PowerShell call."""
        if self.system != "Windows":
            return None

        script = (
            "$adapters = @{}; "
            "Get-CimInstance Win32_NetworkAdapter "
            "| Where-Object { $_.NetConnectionID } "
            "| ForEach-Object { $adapters[$_.InterfaceIndex] = $_.NetConnectionID }; "
            "$dhcp = @(Get-CimInstance Win32_NetworkAdapterConfiguration "
            "-Filter 'IPEnabled=True' | ForEach-Object { "
            "[PSCustomObject]@{ "
            "Alias = $adapters[$_.InterfaceIndex]; "
            "Description = $_.Description; "
            "DHCPServer = $_.DHCPServer "
            "} }); "
            "$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' "
            "-ErrorAction SilentlyContinue "
            "| Select-Object InterfaceAlias,NextHop); "
            "$dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue "
            "| Select-Object InterfaceAlias,ServerAddresses); "
            "$wifi = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue "
            "| Where-Object { $_.InterfaceDescription -match 'Wireless|Wi-Fi' } "
            "| Select-Object Name,Status); "
            "[PSCustomObject]@{ "
            "routes = $routes; dns = $dns; dhcp = $dhcp; wifi = $wifi "
            "} | ConvertTo-Json -Depth 4 -Compress"
        )
        data = run_powershell(script, timeout=self.timeout, parse_json=True)
        return data if isinstance(data, dict) else None

    @staticmethod
    def _parse_windows_gateways(routes):
        gateways = {}
        if isinstance(routes, dict):
            routes = [routes]
        if not isinstance(routes, list):
            return gateways

        for route in routes:
            if not isinstance(route, dict):
                continue
            interface = route.get("InterfaceAlias")
            gateway = route.get("NextHop")
            if interface and gateway:
                try:
                    ip_obj = ipaddress.ip_address(gateway)
                    if not ip_obj.is_unspecified:
                        gateways.setdefault(interface, []).append(gateway)
                except ValueError:
                    continue

        for name in gateways:
            gateways[name] = list(dict.fromkeys(gateways[name]))
        return gateways

    def _default_gateways(self, ps_routes=None):
        gateways = {}

        if self.system == "Windows":
            if ps_routes is not None:
                return self._parse_windows_gateways(ps_routes)

            routes = run_powershell(
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' "
                "| Select-Object InterfaceAlias,NextHop "
                "| ConvertTo-Json -Compress",
                timeout=self.timeout,
                parse_json=True,
            )
            if routes is not None:
                return self._parse_windows_gateways(routes)

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

    _EXCLUDED_DNS_NETWORK = ipaddress.ip_network("fec0:0:0::/48")

    @classmethod
    def _is_valid_dns_server(cls, value):
        cleaned = str(value).strip().lower()
        if cleaned.startswith("fec0:0:0:"):
            return False
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return addr not in cls._EXCLUDED_DNS_NETWORK

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
                    if self._is_valid_dns_server(value):
                        servers.append(value)

        elif self.system == "Linux":
            # systemd-resolved provides per-link DNS where available.
            output = self._run(["resolvectl", "dns"])
            if output:
                for line in output.splitlines():
                    for value in line.split(":", 1)[-1].split():
                        if self._is_valid_dns_server(value):
                            servers.append(value)

            if not output:
                servers.extend(
                    s for s in self._parse_resolv_conf()
                    if self._is_valid_dns_server(s)
                )

        elif self.system == "Darwin":
            output = self._run(["scutil", "--dns"])
            if output:
                for line in output.splitlines():
                    match = re.search(
                        r"nameserver\[\d+\]\s*:\s*(\S+)", line
                    )
                    if match:
                        value = match.group(1)
                        if self._is_valid_dns_server(value):
                            servers.append(value)

        return list(dict.fromkeys(servers))

    def _dns_servers_by_adapter(self, ps_dns=None):
        if self.system != "Windows":
            return None

        data = (
            ps_dns
            if ps_dns is not None
            else run_powershell(
                "Get-DnsClientServerAddress "
                "| Select-Object InterfaceAlias,ServerAddresses "
                "| ConvertTo-Json -Compress",
                timeout=self.timeout,
                parse_json=True,
            )
        )
        if data is None:
            return None
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return None

        by_adapter = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            alias = item.get("InterfaceAlias")
            addrs = item.get("ServerAddresses") or []
            if isinstance(addrs, str):
                addrs = [addrs]
            if not alias or not isinstance(addrs, list):
                continue
            valid = []
            for addr in addrs:
                if not isinstance(addr, str):
                    continue
                cleaned = addr.strip()
                if self._is_valid_dns_server(cleaned):
                    valid.append(cleaned)
            if valid:
                existing = by_adapter.setdefault(alias, [])
                for ip in valid:
                    if ip not in existing:
                        existing.append(ip)
        return by_adapter

    def _dhcp_servers_by_adapter(self, ps_dhcp=None):
        if self.system != "Windows":
            return None

        data = (
            ps_dhcp
            if ps_dhcp is not None
            else run_powershell(
                "$adapters = @{}; "
                "Get-CimInstance Win32_NetworkAdapter "
                "| Where-Object { $_.NetConnectionID } "
                "| ForEach-Object { $adapters[$_.InterfaceIndex] = $_.NetConnectionID }; "
                "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' "
                "| ForEach-Object { "
                "[PSCustomObject]@{ "
                "Alias = $adapters[$_.InterfaceIndex]; "
                "Description = $_.Description; "
                "DHCPServer = $_.DHCPServer "
                "} } | ConvertTo-Json -Compress",
                timeout=self.timeout,
                parse_json=True,
            )
        )
        if data is None:
            return None
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return None

        by_adapter = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            alias = item.get("Alias")
            desc = item.get("Description")
            server = item.get("DHCPServer")
            if alias and desc and server:
                by_adapter.setdefault(alias, {})[desc] = [server]
        return by_adapter

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
            if shutil.which("nmcli"):
                output = self._run([
                    "nmcli", "-t", "-f", "GENERAL.DEVICE,DHCP4.OPTION", "dev", "show"
                ])
                if output:
                    current_dev = None
                    for line in output.splitlines():
                        if line.startswith("GENERAL.DEVICE:"):
                            current_dev = line.split(":", 1)[1].strip()
                        elif (
                            current_dev
                            and "dhcp_server_identifier" in line
                            and "=" in line
                        ):
                            server = line.split("=", 1)[1].strip()
                            try:
                                ipaddress.ip_address(server)
                                servers[current_dev] = [server]
                            except ValueError:
                                pass

        elif self.system == "Darwin":
            # `ipconfig getpacket <iface>` exposes DHCP options without root.
            for iface in psutil.net_if_addrs():
                output = self._run(["ipconfig", "getpacket", iface])
                if not output:
                    continue
                match = re.search(
                    r"server_identifier\s*\(ip\)\s*:\s*(\S+)", output
                )
                if match:
                    server = match.group(1).strip()
                    try:
                        ipaddress.ip_address(server)
                        servers[iface] = [server]
                    except ValueError:
                        pass

        return servers

    def _wifi_info(self, ps_wifi=None):
        if self.system == "Windows":
            result = run_command_result(
                ["netsh", "wlan", "show", "interfaces"],
                timeout=self.timeout,
            )
            interfaces = []
            unavailable_reason = None

            if result is not None:
                rc, stdout, stderr = result
                combined = f"{stdout}\n{stderr}".lower()
                if (
                    "location permission" in combined
                    or "access is denied" in combined
                    or "error 5" in combined
                ):
                    unavailable_reason = "Location permission required"
                elif rc == 0 and stdout:
                    current = {}
                    for line in stdout.splitlines():
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

            if interfaces:
                if unavailable_reason:
                    for item in interfaces:
                        item.setdefault("ssid", None)
                        item["note"] = unavailable_reason
                return interfaces

            if ps_wifi is not None:
                wifi_list = [ps_wifi] if isinstance(ps_wifi, dict) else ps_wifi
                if isinstance(wifi_list, list) and wifi_list:
                    fallback = []
                    for adapter in wifi_list:
                        if not isinstance(adapter, dict):
                            continue
                        name = adapter.get("Name")
                        if not name:
                            continue
                        entry = {
                            "name": name,
                            "status": str(adapter.get("Status") or "unknown").lower(),
                            "ssid": None,
                        }
                        if unavailable_reason:
                            entry["note"] = unavailable_reason
                        fallback.append(entry)
                    return fallback or None

            return None

        elif self.system == "Linux":
            output = self._run(["iw", "dev"]) if shutil.which("iw") else None
            if output:
                interfaces = []
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "Interface":
                        iface = parts[1]
                        status = "unknown"
                        ssid = None
                        link_out = self._run(["iw", "dev", iface, "link"])
                        if link_out:
                            if "Not connected." in link_out:
                                status = "disconnected"
                            elif "Connected to" in link_out:
                                status = "connected"
                                m = re.search(r"^\s*SSID:\s*(.+)$", link_out, re.MULTILINE)
                                if m:
                                    ssid = m.group(1).strip()
                        interfaces.append({
                            "name": iface,
                            "status": status,
                            "ssid": ssid,
                        })
                return interfaces

            if shutil.which("nmcli"):
                nm_out = self._run([
                    "nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev"
                ])
                if nm_out:
                    interfaces = []
                    for line in nm_out.splitlines():
                        parts = line.split(":", 3)
                        if len(parts) == 4 and parts[1] == "wifi":
                            interfaces.append({
                                "name": parts[0],
                                "status": parts[2],
                                "ssid": parts[3] if parts[3] not in ("", "--") else None,
                            })
                    return interfaces or None

        elif self.system == "Darwin":
            # macOS has no stable built-in CLI for Wi-Fi SSID across
            # all supported releases and permission configurations.
            pass

        return None

    def audit(self):
        stats = psutil.net_if_stats()
        addresses = self._interface_addresses()
        macs = self._mac_addresses()

        ps_data = (
            self._windows_network_ps_data()
            if self.system == "Windows"
            else None
        )

        gateways = self._default_gateways(
            ps_routes=ps_data.get("routes") if ps_data else None
        )
        dns_by_adapter = self._dns_servers_by_adapter(
            ps_dns=ps_data.get("dns") if ps_data else None
        )
        dns_servers = (
            [] if dns_by_adapter is not None else self._dns_servers()
        )
        dhcp_by_adapter = self._dhcp_servers_by_adapter(
            ps_dhcp=ps_data.get("dhcp") if ps_data else None
        )
        dhcp_servers = (
            {} if dhcp_by_adapter is not None else self._dhcp_servers()
        )
        wifi = self._wifi_info(
            ps_wifi=ps_data.get("wifi") if ps_data else None
        )

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
                "dns_servers": (
                    dns_by_adapter.get(name, [])
                    if dns_by_adapter is not None
                    else dns_servers
                ),
                "dhcp_servers": (
                    dhcp_by_adapter.get(name, {})
                    if dhcp_by_adapter is not None
                    else dhcp_servers
                ),
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


NetworkSettings = NetworkSettingsAudit

if __name__ == "__main__":
    print(json.dumps(
        NetworkSettingsAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
