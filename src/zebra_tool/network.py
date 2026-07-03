"""Network utilities: subnet detection, CIDR parsing, broadcast computation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import ifaddr


@dataclass
class SubnetInfo:
    """A detected or user-specified subnet ready for scanning."""

    network: ipaddress.IPv4Network
    broadcast: str
    interface_ip: str | None = None

    @property
    def cidr(self) -> str:
        return str(self.network)

    @classmethod
    def from_cidr(cls, cidr: str) -> SubnetInfo:
        net = parse_cidr(cidr)
        return cls(network=net, broadcast=compute_broadcast(net))


def parse_cidr(cidr: str) -> ipaddress.IPv4Network:
    """Parse and validate a CIDR string like '192.168.1.0/24'.

    The prefix length (e.g. /24) is required.
    Raises ValueError if the string is not a valid IPv4 CIDR.
    """
    if "/" not in cidr:
        raise ValueError(
            f"Invalid CIDR notation: {cidr!r} — missing prefix length"
        )
    try:
        return ipaddress.IPv4Network(cidr, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid CIDR notation: {cidr!r} — {exc}") from exc


def compute_broadcast(net: ipaddress.IPv4Network) -> str:
    """Return the broadcast address of an IPv4 network as a string."""
    return str(net.broadcast_address)


def iter_subnet_ips(net: ipaddress.IPv4Network):
    """Yield usable host IPs in the subnet (excludes network + broadcast).

    For /32, yields the single address.
    For /31, yields both addresses (point-to-point link).
    """
    if net.prefixlen == 32:
        yield str(net.network_address)
    elif net.prefixlen == 31:
        yield from (str(h) for h in net.hosts())
    else:
        yield from (str(h) for h in net.hosts())


def detect_local_subnets() -> list[SubnetInfo]:
    """Detect all non-loopback IPv4 subnets on local interfaces.

    Returns a list of SubnetInfo, one per IPv4 address found.
    """
    subnets: list[SubnetInfo] = []

    for adapter in ifaddr.get_adapters():
        for ip_info in adapter.ips:
            ip = ip_info.ip

            # Skip IPv6 (ifaddr returns a tuple for IPv6 addresses)
            if isinstance(ip, tuple):
                continue

            # Skip loopback
            if ip.startswith("127."):
                continue

            prefix = ip_info.network_prefix
            try:
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            except ValueError:
                continue

            subnets.append(
                SubnetInfo(
                    network=net,
                    broadcast=compute_broadcast(net),
                    interface_ip=ip,
                )
            )

    return subnets


def default_subnet() -> SubnetInfo | None:
    """Return the first detected non-loopback subnet, or None."""
    subnets = detect_local_subnets()
    return subnets[0] if subnets else None
