"""Data models for discovered printers, enums, and merge logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class DiscoveryMethod(Enum):
    """Which protocol found this printer."""

    UDP = "udp_4201"
    SNMP = "snmp"
    MDNS = "mdns"


class PrinterStatus(Enum):
    """Operational status reported by the printer."""

    UNKNOWN = "unknown"
    READY = "ready"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class Printer:
    """A single discovered Zebra printer.

    Fields are populated progressively: discovery protocols fill the
    basics, TCP 9100 enrichment adds live status.
    """

    ip_address: str
    hostname: str | None = None
    model: str | None = None
    serial_number: str | None = None
    firmware_version: str | None = None
    mac_address: str | None = None
    subnet_mask: str | None = None
    default_gateway: str | None = None
    status: PrinterStatus = PrinterStatus.UNKNOWN

    # TCP 9100 enrichment fields
    print_speed: str | None = None
    darkness: str | None = None
    head_temperature: str | None = None
    total_labels: str | None = None

    # metadata
    discovered_via: set[DiscoveryMethod] = field(default_factory=set)
    last_seen: datetime | None = None
    stale: bool = False

    def to_dict(self) -> dict:
        """Serialize to a plain dict for CSV/JSON export."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "model": self.model,
            "serial_number": self.serial_number,
            "firmware_version": self.firmware_version,
            "mac_address": self.mac_address,
            "subnet_mask": self.subnet_mask,
            "default_gateway": self.default_gateway,
            "status": self.status.value,
            "print_speed": self.print_speed,
            "darkness": self.darkness,
            "head_temperature": self.head_temperature,
            "total_labels": self.total_labels,
            "discovered_via": sorted(m.value for m in self.discovered_via),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "stale": self.stale,
        }


def merge_printers(existing: Printer, new: Printer) -> Printer:
    """Merge two Printer objects with the same IP address.

    Rules:
    - Existing non-null fields are preserved (first writer wins).
    - Null fields in existing are filled from new.
    - discovered_via accumulates from both.
    - last_seen takes the most recent timestamp.
    - stale is cleared if new data arrived.
    """
    if existing.ip_address != new.ip_address:
        raise ValueError(
            f"Cannot merge printers with different IPs: "
            f"{existing.ip_address} vs {new.ip_address}"
        )

    merged = Printer(ip_address=existing.ip_address)

    for f in (
        "hostname",
        "model",
        "serial_number",
        "firmware_version",
        "mac_address",
        "subnet_mask",
        "default_gateway",
        "print_speed",
        "darkness",
        "head_temperature",
        "total_labels",
    ):
        existing_val = getattr(existing, f)
        new_val = getattr(new, f)
        setattr(merged, f, existing_val if existing_val is not None else new_val)

    # status: UNKNOWN acts as "unset" so a concrete value always wins
    if existing.status is not PrinterStatus.UNKNOWN:
        merged.status = existing.status
    else:
        merged.status = new.status

    merged.discovered_via = existing.discovered_via | new.discovered_via

    times = [t for t in (existing.last_seen, new.last_seen) if t is not None]
    merged.last_seen = max(times) if times else None

    merged.stale = False

    return merged
