"""Tests for mDNS/Bonjour printer discovery."""

import ipaddress
from unittest.mock import patch, MagicMock

import pytest

from zebra_tool.discovery.mdns import (
    mdns_browse,
    service_info_to_printer,
    SERVICE_TYPES,
    PrinterCollector,
)
from zebra_tool.models import DiscoveryMethod


class FakeServiceInfo:
    """Mimic zeroconf.ServiceInfo for tests."""

    def __init__(self, name, addresses, port=631, properties=None):
        self.name = name
        self.addresses = addresses
        self.port = port
        self.properties = properties or {}
        self.type = name.split(".")[-3] + "." + name.split(".")[-2] + "." + "local."


class TestServiceTypes:
    def test_includes_ipp(self):
        assert "_ipp._tcp.local." in SERVICE_TYPES

    def test_includes_printer(self):
        assert "_printer._tcp.local." in SERVICE_TYPES

    def test_includes_http(self):
        assert "_http._tcp.local." in SERVICE_TYPES


class TestServiceInfoToPrinter:
    def test_ipv4_address(self):
        info = FakeServiceInfo(
            name="ZBR-D6J2117011._ipp._tcp.local.",
            addresses=[ipaddress.IPv4Address("192.168.1.50")],
            port=631,
        )
        printer = service_info_to_printer(info)
        assert printer is not None
        assert printer.ip_address == "192.168.1.50"
        assert DiscoveryMethod.MDNS in printer.discovered_via

    def test_hostname_from_service_name(self):
        info = FakeServiceInfo(
            name="ZBR4262077._printer._tcp.local.",
            addresses=[ipaddress.IPv4Address("10.0.0.1")],
        )
        printer = service_info_to_printer(info)
        assert printer.hostname == "ZBR4262077"

    def test_strips_ipp_suffix(self):
        info = FakeServiceInfo(
            name="ZD421-Serial._ipp._tcp.local.",
            addresses=[ipaddress.IPv4Address("10.0.0.2")],
        )
        printer = service_info_to_printer(info)
        assert printer.hostname == "ZD421-Serial"

    def test_returns_none_if_no_addresses(self):
        info = FakeServiceInfo(
            name="Test._ipp._tcp.local.",
            addresses=[],
        )
        printer = service_info_to_printer(info)
        assert printer is None

    def test_skips_ipv6_only(self):
        info = FakeServiceInfo(
            name="Test._ipp._tcp.local.",
            addresses=[ipaddress.IPv6Address("fe80::1")],
        )
        printer = service_info_to_printer(info)
        assert printer is None

    def test_prefers_ipv4_when_both_exist(self):
        info = FakeServiceInfo(
            name="Test._ipp._tcp.local.",
            addresses=[
                ipaddress.IPv6Address("fe80::1"),
                ipaddress.IPv4Address("192.168.1.50"),
            ],
        )
        printer = service_info_to_printer(info)
        assert printer is not None
        assert printer.ip_address == "192.168.1.50"


class TestPrinterCollector:
    def test_add_service(self):
        collector = PrinterCollector()
        mock_zc = MagicMock()
        info = FakeServiceInfo(
            name="ZBR._ipp._tcp.local.",
            addresses=[ipaddress.IPv4Address("192.168.1.50")],
        )
        mock_zc.get_service_info.return_value = info

        collector.add_service(mock_zc, "_ipp._tcp.local.", "ZBR._ipp._tcp.local.")

        assert "ZBR._ipp._tcp.local." in collector.services

    def test_add_service_no_info(self):
        collector = PrinterCollector()
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = None

        collector.add_service(mock_zc, "_ipp._tcp.local.", "Unknown._ipp._tcp.local.")

        assert len(collector.services) == 0

    def test_remove_service(self):
        collector = PrinterCollector()
        collector.services["test"] = MagicMock()
        collector.remove_service(MagicMock(), "_ipp._tcp.local.", "test")
        assert "test" not in collector.services


class TestMdnsBrowse:
    @patch("zebra_tool.discovery.mdns.Zeroconf")
    @patch("zebra_tool.discovery.mdns.ServiceBrowser")
    @patch("zebra_tool.discovery.mdns.time.sleep")
    def test_returns_printers(self, mock_sleep, mock_browser_cls, mock_zc_cls):
        collector = PrinterCollector()
        info = FakeServiceInfo(
            name="ZBR._ipp._tcp.local.",
            addresses=[ipaddress.IPv4Address("192.168.1.50")],
        )
        collector.services["ZBR._ipp._tcp.local."] = info

        mock_zc = MagicMock()
        mock_zc_cls.return_value = mock_zc

        with patch("zebra_tool.discovery.mdns.PrinterCollector") as mock_collector_cls:
            mock_collector_cls.return_value = collector
            printers = mdns_browse(timeout=0.1)

        assert len(printers) == 1
        assert printers[0].ip_address == "192.168.1.50"
        assert DiscoveryMethod.MDNS in printers[0].discovered_via

    @patch("zebra_tool.discovery.mdns.Zeroconf")
    @patch("zebra_tool.discovery.mdns.ServiceBrowser")
    @patch("zebra_tool.discovery.mdns.time.sleep")
    def test_empty_result(self, mock_sleep, mock_browser_cls, mock_zc_cls):
        mock_zc = MagicMock()
        mock_zc_cls.return_value = mock_zc

        with patch("zebra_tool.discovery.mdns.PrinterCollector") as mock_collector_cls:
            mock_collector_cls.return_value = PrinterCollector()
            printers = mdns_browse(timeout=0.1)

        assert printers == []

    @patch("zebra_tool.discovery.mdns.Zeroconf")
    @patch("zebra_tool.discovery.mdns.ServiceBrowser")
    @patch("zebra_tool.discovery.mdns.time.sleep")
    def test_dedupes_by_ip(self, mock_sleep, mock_browser_cls, mock_zc_cls):
        collector = PrinterCollector()
        info1 = FakeServiceInfo(
            name="ZBR._ipp._tcp.local.",
            addresses=[ipaddress.IPv4Address("192.168.1.50")],
        )
        info2 = FakeServiceInfo(
            name="ZBR._http._tcp.local.",
            addresses=[ipaddress.IPv4Address("192.168.1.50")],
        )
        collector.services["ZBR._ipp._tcp.local."] = info1
        collector.services["ZBR._http._tcp.local."] = info2

        mock_zc = MagicMock()
        mock_zc_cls.return_value = mock_zc

        with patch("zebra_tool.discovery.mdns.PrinterCollector") as mock_collector_cls:
            mock_collector_cls.return_value = collector
            printers = mdns_browse(timeout=0.1)

        assert len(printers) == 1  # same IP, deduped

    @patch("zebra_tool.discovery.mdns.Zeroconf")
    @patch("zebra_tool.discovery.mdns.ServiceBrowser")
    @patch("zebra_tool.discovery.mdns.time.sleep")
    def test_closes_zeroconf(self, mock_sleep, mock_browser_cls, mock_zc_cls):
        mock_zc = MagicMock()
        mock_zc_cls.return_value = mock_zc

        with patch("zebra_tool.discovery.mdns.PrinterCollector") as mock_collector_cls:
            mock_collector_cls.return_value = PrinterCollector()
            mdns_browse(timeout=0.1)

        mock_zc.close.assert_called_once()
