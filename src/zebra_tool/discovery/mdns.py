"""mDNS / Bonjour discovery for Zebra printers.

Browses for _ipp._tcp, _printer._tcp, and _http._tcp services on the
local network. Catches printers that don't respond to UDP 4201.
"""

from __future__ import annotations

import ipaddress
import time
from datetime import datetime

from zeroconf import Zeroconf, ServiceBrowser

from zebra_tool.models import DiscoveryMethod, Printer

SERVICE_TYPES = [
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_http._tcp.local.",
]


class PrinterCollector:
    """ServiceListener that collects discovered mDNS services."""

    def __init__(self) -> None:
        self.services: dict[str, object] = {}

    def add_service(self, zeroconf, service_type: str, name: str) -> None:
        info = zeroconf.get_service_info(service_type, name)
        if info:
            self.services[name] = info

    def remove_service(self, zeroconf, service_type: str, name: str) -> None:
        self.services.pop(name, None)

    def update_service(self, zeroconf, service_type: str, name: str) -> None:
        info = zeroconf.get_service_info(service_type, name)
        if info:
            self.services[name] = info


def _extract_ipv4(addresses: list) -> str | None:
    """Find the first IPv4 address in a list of ipaddress objects."""
    for addr in addresses:
        if isinstance(addr, ipaddress.IPv4Address):
            return str(addr)
    return None


def _extract_hostname(name: str) -> str | None:
    """Extract the hostname from an mDNS service name.

    e.g. 'ZBR4262077._ipp._tcp.local.' -> 'ZBR4262077'
    """
    return name.split(".")[0] if name else None


def service_info_to_printer(info: object) -> Printer | None:
    """Convert a zeroconf ServiceInfo object into a Printer.

    Returns None if no IPv4 address is available.
    """
    addresses = getattr(info, "addresses", [])
    ip = _extract_ipv4(addresses)
    if not ip:
        return None

    name = getattr(info, "name", "")
    hostname = _extract_hostname(name)

    return Printer(
        ip_address=ip,
        hostname=hostname,
        discovered_via={DiscoveryMethod.MDNS},
        last_seen=datetime.now(),
    )


def mdns_browse(timeout: float = 5.0) -> list[Printer]:
    """Browse for Zebra printers via mDNS/Bonjour.

    Listens for the configured service types for the given duration,
    then returns discovered printers deduplicated by IP.
    """
    zc = Zeroconf()
    collector = PrinterCollector()

    browsers = [
        ServiceBrowser(zc, st, collector) for st in SERVICE_TYPES
    ]

    time.sleep(timeout)

    for browser in browsers:
        browser.cancel()

    zc.close()

    printers: dict[str, Printer] = {}
    for info in collector.services.values():
        printer = service_info_to_printer(info)
        if printer and printer.ip_address not in printers:
            printers[printer.ip_address] = printer

    return list(printers.values())
