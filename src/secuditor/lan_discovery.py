
# Secuditor – Copyright (c) 2026 Menahem Levinski

"""Cross-platform LAN discovery and TCP port auditing."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
from typing import Iterable

import psutil


__all__ = ["LanDiscovery"]


COMMON_PORTS_TCP = [
    20, 21, 22, 23, 53, 79, 80, 443, 445, 389, 636,
    989, 990, 1080, 1433, 1434, 1521, 2049, 2222,
    2375, 2376, 3306, 3389, 5432, 5601, 5900,
    5985, 5986, 6379, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9001, 9042, 10000, 10443,
    27017, 30015,
]

# Used to identify responsive hosts during discovery.
DISCOVERY_PORTS = (22, 53, 80, 139, 443, 445, 3389, 5985)


class LanDiscovery:
    """Discover IPv4 LAN hosts and optionally audit their TCP ports.

    The scanner uses standard sockets, OS ping/ARP utilities, and psutil.
    Administrative privileges may improve the information available.

    Args:
        timeout: TCP connection timeout in seconds.
        max_workers: Maximum concurrent scanning workers.
        max_hosts: Maximum number of addresses to scan in one subnet.
    """

    def __init__(
        self,
        timeout: float = 0.4,
        max_workers: int = 64,
        max_hosts: int = 1024,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if max_hosts < 1:
            raise ValueError("max_hosts must be at least 1")

        self.timeout = timeout
        self.max_workers = max_workers
        self.max_hosts = max_hosts

    def get_default_interface(self) -> dict:
        """Return the default IPv4 interface and its network information."""

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Select the interface used by the system's routing table.
            # This does not send application data to the destination.
            sock.connect(("192.0.2.1", 80))
            local_ip = sock.getsockname()[0]
        except OSError as exc:
            raise RuntimeError(
                "Unable to determine the default IPv4 interface"
            ) from exc
        finally:
            sock.close()

        for name, addresses in psutil.net_if_addrs().items():
            for address in addresses:
                if (
                    address.family == socket.AF_INET
                    and address.address == local_ip
                    and address.netmask
                ):
                    network = ipaddress.IPv4Interface(
                        f"{local_ip}/{address.netmask}"
                    ).network

                    return {
                        "interface": name,
                        "ip": local_ip,
                        "netmask": address.netmask,
                        "subnet": str(network),
                    }

        raise RuntimeError(
            f"Could not determine the subnet for {local_ip}"
        )

    @staticmethod
    def _validate_ports(ports: Iterable[int]) -> list[int]:
        """Validate and deduplicate TCP port numbers."""

        result = []

        for port in ports:
            if isinstance(port, bool) or not isinstance(port, int):
                raise ValueError(f"Invalid TCP port: {port!r}")

            if not 1 <= port <= 65535:
                raise ValueError(f"TCP port out of range: {port}")

            if port not in result:
                result.append(port)

        return result

    def _tcp_connect(self, ip: str, port: int) -> bool:
        """Return whether a TCP connection to a port succeeds."""

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False

    def _ping(self, ip: str) -> bool:
        """Perform one best-effort ICMP ping using the system utility."""

        system = platform.system().lower()

        if system == "windows":
            command = [
                "ping", "-n", "1", "-w",
                str(max(1, int(self.timeout * 1000))), ip,
            ]
        elif system == "darwin":
            command = [
                "ping", "-c", "1", "-W",
                str(max(1, int(self.timeout * 1000))), ip,
            ]
        else:
            command = [
                "ping", "-c", "1", "-W",
                str(max(1, int(self.timeout))), ip,
            ]

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(2.0, self.timeout + 1.0),
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _parse_arp_table() -> dict[str, str]:
        """Read cached IPv4-to-MAC mappings from the OS ARP table."""

        system = platform.system().lower()

        if system == "windows":
            command = ["arp", "-a"]
        else:
            command = ["arp", "-an"]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}

        if result.returncode != 0:
            return {}

        ip_to_mac = {}

        for line in result.stdout.splitlines():
            # Windows: 192.168.1.10  aa-bb-cc-dd-ee-ff
            # Linux/macOS: host (192.168.1.10) at aa:bb:cc:dd:ee:ff
            match = re.search(
                r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
                r".*?"
                r"(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}"
                r"[0-9a-fA-F]{2})",
                line,
            )

            if not match:
                continue

            ip = match.group("ip")

            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                continue

            mac = match.group("mac").replace("-", ":").lower()

            if mac != "00:00:00:00:00:00":
                ip_to_mac[ip] = mac

        return ip_to_mac

    def _scan_host(
        self,
        ip: str,
        ports: list[int],
        scan_ports: bool,
    ) -> dict:
        """Probe one host and return its result."""

        if scan_ports:
            open_ports = [
                port for port in ports
                if self._tcp_connect(ip, port)
            ]
            responsive = bool(open_ports)
        else:
            open_ports = []
            responsive = any(
                self._tcp_connect(ip, port)
                for port in DISCOVERY_PORTS
            )

        if not responsive:
            responsive = self._ping(ip)

        return {
            "ip": ip,
            "responsive": responsive,
            "open_ports": open_ports,
        }

    def scan(
        self,
        subnet: str | ipaddress.IPv4Network | None = None,
        *,
        scan_ports: bool = False,
        ports: Iterable[int] | None = None,
        include_local: bool = False,
    ) -> list[dict]:
        """Discover IPv4 hosts on a subnet and optionally audit TCP ports.

        Args:
            subnet: IPv4 subnet in CIDR notation, such as ``192.168.1.0/24``.
                    If omitted, the default interface subnet is detected.
            scan_ports: Audit the selected TCP ports on each scanned host.
            ports: TCP ports to audit. Defaults to COMMON_PORTS_TCP when
                   scan_ports is enabled.
            include_local: Include the scanning computer in the results.

        Returns:
            A list of dictionaries containing ``ip``, ``mac``,
            ``responsive``, and ``open_ports``.

            An ARP entry may identify a host even if it did not respond
            to the TCP or ping probes. Such a host has ``responsive=False``;
            this does not establish that the host is offline.
        """

        interface_info = self.get_default_interface() if subnet is None else None
        local_ip = interface_info["ip"] if interface_info else None

        if subnet is None:
            subnet = interface_info["subnet"]

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid subnet: {subnet!r}") from exc

        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 subnets are supported currently")

        hosts = list(network.hosts())

        if len(hosts) > self.max_hosts:
            raise ValueError(
                f"Subnet contains {len(hosts)} hosts; "
                f"limit is {self.max_hosts}. Specify a smaller subnet "
                "or increase max_hosts explicitly."
            )

        if local_ip and not include_local:
            hosts = [host for host in hosts if str(host) != local_ip]

        ports_to_scan = self._validate_ports(
            ports if ports is not None else COMMON_PORTS_TCP
        )

        results = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            futures = {
                executor.submit(
                    self._scan_host,
                    str(host),
                    ports_to_scan,
                    scan_ports,
                ): str(host)
                for host in hosts
            }

            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]

                try:
                    results.append(future.result())
                except Exception:
                    results.append({
                        "ip": ip,
                        "responsive": False,
                        "open_ports": [],
                    })

        # Add cached ARP hosts that weren't discovered by probes.
        arp_table = self._parse_arp_table()
        existing_ips = {item["ip"] for item in results}

        for ip, mac in arp_table.items():
            address = ipaddress.IPv4Address(ip)

            if address not in network or ip in existing_ips:
                continue

            if local_ip and ip == local_ip and not include_local:
                continue

            results.append({
                "ip": ip,
                "responsive": False,
                "open_ports": [],
            })
            existing_ips.add(ip)

        for item in results:
            item["mac"] = arp_table.get(item["ip"])
            item["hostname"] = None

        # Reverse DNS is best-effort; avoid delaying the scan for every host.
        results.sort(key=lambda item: ipaddress.IPv4Address(item["ip"]))

        return results

    def audit_ports(
        self,
        host: str,
        ports: Iterable[int] | None = None,
    ) -> dict:
        """Audit TCP ports on one explicitly specified host.

        This method does not perform UDP scanning or service fingerprinting.
        """

        try:
            address = ipaddress.ip_address(host)

            if not isinstance(address, ipaddress.IPv4Address):
                raise ValueError("Only IPv4 hosts are supported currently")
        except ValueError:
            # Permit DNS hostnames as well as IPv4 addresses.
            try:
                host = socket.gethostbyname(host)
            except OSError as exc:
                raise ValueError(f"Unable to resolve host: {host}") from exc

        selected_ports = self._validate_ports(
            ports if ports is not None else COMMON_PORTS_TCP
        )

        open_ports = [
            port for port in selected_ports
            if self._tcp_connect(host, port)
        ]

        return {
            "host": host,
            "open_ports": sorted(open_ports),
            "scanned_ports": len(selected_ports),
        }
