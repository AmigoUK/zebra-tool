"""Tests for the TUI app and printer registry orchestration."""

import pytest
from datetime import datetime

from zebra_tool.models import DiscoveryMethod, Printer, PrinterStatus, merge_printers
from zebra_tool.tui.registry import PrinterRegistry


class TestPrinterRegistry:
    def test_add_new_printer(self):
        reg = PrinterRegistry()
        p = Printer(ip_address="192.168.1.50", model="ZD421")
        reg.add(p)
        assert len(reg) == 1
        assert reg.get("192.168.1.50").model == "ZD421"

    def test_add_merges_duplicate_ip(self):
        reg = PrinterRegistry()
        a = Printer(
            ip_address="192.168.1.50",
            model="ZD421",
            discovered_via={DiscoveryMethod.UDP},
        )
        b = Printer(
            ip_address="192.168.1.50",
            serial_number="D6J211701128",
            discovered_via={DiscoveryMethod.SNMP},
        )
        reg.add(a)
        reg.add(b)
        assert len(reg) == 1
        printer = reg.get("192.168.1.50")
        assert printer.model == "ZD421"
        assert printer.serial_number == "D6J211701128"
        assert printer.discovered_via == {DiscoveryMethod.UDP, DiscoveryMethod.SNMP}

    def test_all(self):
        reg = PrinterRegistry()
        reg.add(Printer(ip_address="10.0.0.1"))
        reg.add(Printer(ip_address="10.0.0.2"))
        all_printers = reg.all()
        assert len(all_printers) == 2

    def test_clear(self):
        reg = PrinterRegistry()
        reg.add(Printer(ip_address="10.0.0.1"))
        reg.clear()
        assert len(reg) == 0

    def test_mark_stale_removes_seen(self):
        """After a refresh, printers not re-confirmed are marked stale."""
        reg = PrinterRegistry()
        reg.add(Printer(ip_address="10.0.0.1", model="ZD421"))
        reg.add(Printer(ip_address="10.0.0.2", model="ZD621"))

        reg.begin_refresh()
        reg.add(Printer(ip_address="10.0.0.1", model="ZD421"))
        reg.end_refresh()

        p1 = reg.get("10.0.0.1")
        p2 = reg.get("10.0.0.2")
        assert p1.stale is False
        assert p2.stale is True

    def test_clear_stale(self):
        reg = PrinterRegistry()
        reg.add(Printer(ip_address="10.0.0.1"))
        reg.add(Printer(ip_address="10.0.0.2"))

        reg.begin_refresh()
        reg.add(Printer(ip_address="10.0.0.1"))
        reg.end_refresh()
        reg.clear_stale()

        assert len(reg) == 1
        assert reg.get("10.0.0.2") is None

    def test_get_nonexistent(self):
        reg = PrinterRegistry()
        assert reg.get("10.0.0.99") is None

    def test_to_list_sorted_by_ip(self):
        reg = PrinterRegistry()
        reg.add(Printer(ip_address="10.0.0.5"))
        reg.add(Printer(ip_address="10.0.0.1"))
        reg.add(Printer(ip_address="10.0.0.3"))
        ips = [p.ip_address for p in reg.to_list()]
        assert ips == ["10.0.0.1", "10.0.0.3", "10.0.0.5"]
