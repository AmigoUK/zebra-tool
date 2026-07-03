"""Printer registry: manages discovered printers with dedup and stale tracking."""

from __future__ import annotations

import ipaddress

from zebra_tool.models import Printer, merge_printers


class PrinterRegistry:
    """Thread-safe-ish registry of discovered printers keyed by IP.

    Handles merge/dedup when the same printer is found by multiple
    discovery methods, and tracks stale printers during refresh cycles.
    """

    def __init__(self) -> None:
        self._printers: dict[str, Printer] = {}
        self._refresh_seen: set[str] | None = None

    def add(self, printer: Printer) -> Printer:
        """Add or merge a printer into the registry."""
        ip = printer.ip_address

        if ip in self._printers:
            self._printers[ip] = merge_printers(self._printers[ip], printer)
        else:
            self._printers[ip] = printer

        if self._refresh_seen is not None:
            self._refresh_seen.add(ip)
            self._printers[ip].stale = False

        return self._printers[ip]

    def get(self, ip: str) -> Printer | None:
        return self._printers.get(ip)

    def all(self) -> list[Printer]:
        return list(self._printers.values())

    def to_list(self) -> list[Printer]:
        """Return printers sorted by IP address."""
        return sorted(
            self._printers.values(),
            key=lambda p: ipaddress.IPv4Address(p.ip_address),
        )

    def clear(self) -> None:
        self._printers.clear()
        self._refresh_seen = None

    def begin_refresh(self) -> None:
        """Start a refresh cycle. Call end_refresh() when done."""
        self._refresh_seen = set()

    def end_refresh(self) -> None:
        """Mark printers not seen during this refresh cycle as stale."""
        if self._refresh_seen is None:
            return
        for ip, printer in self._printers.items():
            if ip not in self._refresh_seen:
                printer.stale = True
        self._refresh_seen = None

    def clear_stale(self) -> None:
        """Remove all printers marked as stale."""
        self._printers = {
            ip: p for ip, p in self._printers.items() if not p.stale
        }

    def __len__(self) -> int:
        return len(self._printers)
