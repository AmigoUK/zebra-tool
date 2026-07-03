"""Tests for the Printer data model, enums, and merge logic."""

from datetime import datetime

from zebra_tool.models import (
    DiscoveryMethod,
    Printer,
    PrinterStatus,
    merge_printers,
)


class TestDiscoveryMethod:
    def test_values(self):
        assert DiscoveryMethod.UDP.value == "udp_4201"
        assert DiscoveryMethod.SNMP.value == "snmp"
        assert DiscoveryMethod.MDNS.value == "mdns"


class TestPrinterStatus:
    def test_values(self):
        assert PrinterStatus.UNKNOWN.value == "unknown"
        assert PrinterStatus.READY.value == "ready"
        assert PrinterStatus.PAUSED.value == "paused"
        assert PrinterStatus.ERROR.value == "error"


class TestPrinterCreation:
    def test_minimal(self):
        p = Printer(ip_address="192.168.1.50")
        assert p.ip_address == "192.168.1.50"
        assert p.hostname is None
        assert p.model is None
        assert p.status is PrinterStatus.UNKNOWN
        assert p.discovered_via == set()

    def test_full(self):
        p = Printer(
            ip_address="192.168.1.50",
            hostname="ZBR4262077",
            model="ZTC ZD421-203dpi ZPL",
            serial_number="D6J211701128",
            firmware_version="V93.21.07Z",
            mac_address="00:1B:A5:XX:XX:XX",
            status=PrinterStatus.READY,
            print_speed="6",
            darkness="15",
        )
        assert p.model == "ZTC ZD421-203dpi ZPL"
        assert p.status is PrinterStatus.READY
        assert p.print_speed == "6"


class TestPrinterToDict:
    def test_to_dict_contains_all_fields(self):
        p = Printer(
            ip_address="192.168.1.50",
            model="ZTC ZD421-203dpi ZPL",
            serial_number="D6J211701128",
            firmware_version="V93.21.07Z",
        )
        d = p.to_dict()
        assert d["ip_address"] == "192.168.1.50"
        assert d["model"] == "ZTC ZD421-203dpi ZPL"
        assert d["serial_number"] == "D6J211701128"
        assert d["firmware_version"] == "V93.21.07Z"
        assert d["status"] == "unknown"
        assert d["hostname"] is None

    def test_to_dict_serializes_discovered_via(self):
        p = Printer(ip_address="10.0.0.1")
        p.discovered_via = {DiscoveryMethod.UDP, DiscoveryMethod.SNMP}
        d = p.to_dict()
        assert set(d["discovered_via"]) == {"udp_4201", "snmp"}

    def test_to_dict_serializes_last_seen(self):
        ts = datetime(2025, 7, 3, 14, 23, 5)
        p = Printer(ip_address="10.0.0.1", last_seen=ts)
        d = p.to_dict()
        assert d["last_seen"] == "2025-07-03T14:23:05"


class TestMergePrinters:
    def test_merge_combines_fields(self):
        """First non-null wins per field, discovered_via accumulates."""
        a = Printer(
            ip_address="192.168.1.50",
            model="ZD421",
            discovered_via={DiscoveryMethod.UDP},
        )
        b = Printer(
            ip_address="192.168.1.50",
            serial_number="D6J211701128",
            firmware_version="V93.21.07Z",
            discovered_via={DiscoveryMethod.SNMP},
        )
        merged = merge_printers(a, b)
        assert merged.ip_address == "192.168.1.50"
        assert merged.model == "ZD421"
        assert merged.serial_number == "D6J211701128"
        assert merged.firmware_version == "V93.21.07Z"
        assert merged.discovered_via == {DiscoveryMethod.UDP, DiscoveryMethod.SNMP}

    def test_merge_existing_field_not_overwritten(self):
        """If both have the same field, the first (existing) value wins."""
        a = Printer(ip_address="10.0.0.1", model="FromUDP")
        b = Printer(ip_address="10.0.0.1", model="FromSNMP")
        merged = merge_printers(a, b)
        assert merged.model == "FromUDP"

    def test_merge_different_ips_raises(self):
        a = Printer(ip_address="10.0.0.1")
        b = Printer(ip_address="10.0.0.2")
        import pytest
        with pytest.raises(ValueError, match="Cannot merge"):
            merge_printers(a, b)

    def test_merge_updates_last_seen(self):
        ts1 = datetime(2025, 1, 1)
        ts2 = datetime(2025, 7, 3)
        a = Printer(ip_address="10.0.0.1", last_seen=ts1)
        b = Printer(ip_address="10.0.0.1", last_seen=ts2)
        merged = merge_printers(a, b)
        assert merged.last_seen == ts2

    def test_merge_accumulates_tcp_enrichment(self):
        a = Printer(
            ip_address="10.0.0.1",
            model="ZD421",
            discovered_via={DiscoveryMethod.UDP},
        )
        b = Printer(
            ip_address="10.0.0.1",
            print_speed="6",
            darkness="15",
            head_temperature="32",
            status=PrinterStatus.READY,
            discovered_via={DiscoveryMethod.SNMP},
        )
        merged = merge_printers(a, b)
        assert merged.print_speed == "6"
        assert merged.darkness == "15"
        assert merged.head_temperature == "32"
        assert merged.status is PrinterStatus.READY


class TestPrinterStale:
    def test_default_not_stale(self):
        p = Printer(ip_address="10.0.0.1")
        assert p.stale is False

    def test_mark_stale(self):
        p = Printer(ip_address="10.0.0.1")
        p.stale = True
        assert p.stale is True
