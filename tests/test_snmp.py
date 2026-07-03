"""Tests for SNMP v1/v2c discovery and enrichment."""

from unittest.mock import patch, MagicMock
import ipaddress

import pytest

from zebra_tool.models import DiscoveryMethod, Printer, PrinterStatus
from zebra_tool.network import SubnetInfo
from zebra_tool.discovery.snmp import (
    ZEBRA_OIDS,
    snmp_query,
    snmp_enrich,
    sweep_subnet,
    format_mac,
)


class TestZebraOids:
    def test_model_oid(self):
        assert ZEBRA_OIDS["model"] == "1.3.6.1.4.1.10642.1.1.0"

    def test_firmware_oid(self):
        assert ZEBRA_OIDS["firmware"] == "1.3.6.1.4.1.10642.1.2.0"

    def test_serial_oid(self):
        assert ZEBRA_OIDS["serial"] == "1.3.6.1.4.1.10642.1.9.0"

    def test_hostname_oid(self):
        assert ZEBRA_OIDS["hostname"] == "1.3.6.1.4.1.10642.1.4.0"


class TestFormatMac:
    def test_hex_string(self):
        assert format_mac("001BA5FFEE01") == "00:1B:A5:FF:EE:01"

    def test_with_spaces(self):
        assert format_mac("00 1B A5 FF EE 01") == "00:1B:A5:FF:EE:01"

    def test_already_colon(self):
        assert format_mac("00:1B:A5:FF:EE:01") == "00:1B:A5:FF:EE:01"

    def test_short_returns_none(self):
        assert format_mac("001BA5") is None

    def test_empty_returns_none(self):
        assert format_mac("") is None

    def test_none_returns_none(self):
        assert format_mac(None) is None


class TestSnmpQuery:
    @patch("zebra_tool.discovery.snmp.snmp_get")
    def test_returns_printer_with_fields(self, mock_get):
        mock_get.return_value = {
            "1.3.6.1.4.1.10642.1.1.0": "ZTC ZD421-203dpi ZPL",
            "1.3.6.1.4.1.10642.1.2.0": "V93.21.07Z",
            "1.3.6.1.4.1.10642.1.4.0": "Z203037",
            "1.3.6.1.4.1.10642.1.9.0": "D6J211701128",
        }

        printer = snmp_query("192.168.1.50", community="public")

        assert printer is not None
        assert printer.ip_address == "192.168.1.50"
        assert printer.model == "ZTC ZD421-203dpi ZPL"
        assert printer.firmware_version == "V93.21.07Z"
        assert printer.hostname == "Z203037"
        assert printer.serial_number == "D6J211701128"
        assert DiscoveryMethod.SNMP in printer.discovered_via

    @patch("zebra_tool.discovery.snmp.snmp_get")
    def test_returns_none_on_timeout(self, mock_get):
        mock_get.return_value = {}
        printer = snmp_query("192.168.1.50")
        assert printer is None

    @patch("zebra_tool.discovery.snmp.snmp_get")
    def test_partial_response(self, mock_get):
        """If only some OIDs respond, still return a printer with partial data."""
        mock_get.return_value = {
            "1.3.6.1.4.1.10642.1.1.0": "ZTC ZD421-203dpi ZPL",
        }
        printer = snmp_query("192.168.1.50")
        assert printer is not None
        assert printer.model == "ZTC ZD421-203dpi ZPL"
        assert printer.serial_number is None

    @patch("zebra_tool.discovery.snmp.snmp_get")
    def test_passes_community_and_version(self, mock_get):
        mock_get.return_value = {}
        snmp_query("10.0.0.1", community="private", version="v2c", timeout=5.0)
        call_kwargs = mock_get.call_args
        assert call_kwargs.kwargs["community"] == "private"
        assert call_kwargs.kwargs["version"] == "v2c"
        assert call_kwargs.kwargs["timeout"] == 5.0


class TestSnmpEnrich:
    @patch("zebra_tool.discovery.snmp.snmp_get")
    def test_enriches_existing_printer(self, mock_get):
        mock_get.return_value = {
            "1.3.6.1.4.1.10642.1.9.0": "D6J211701128",
            "1.3.6.1.4.1.10642.1.2.0": "V93.21.07Z",
        }

        existing = Printer(ip_address="192.168.1.50", model="ZD421")
        result = snmp_enrich(existing, community="public")

        assert result.serial_number == "D6J211701128"
        assert result.firmware_version == "V93.21.07Z"
        assert result.model == "ZD421"  # preserved from existing
        assert DiscoveryMethod.SNMP in result.discovered_via

    @patch("zebra_tool.discovery.snmp.snmp_get")
    def test_returns_unchanged_on_failure(self, mock_get):
        mock_get.return_value = {}
        existing = Printer(ip_address="192.168.1.50", model="ZD421")
        result = snmp_enrich(existing)
        assert result.model == "ZD421"
        assert DiscoveryMethod.SNMP not in result.discovered_via


class TestSweepSubnet:
    @patch("zebra_tool.discovery.snmp.snmp_query")
    def test_finds_printers(self, mock_query):
        def fake_query(ip, **kwargs):
            if ip == "192.168.1.1":
                return Printer(ip_address=ip, model="ZD421")
            elif ip == "192.168.1.5":
                return Printer(ip_address=ip, model="ZT411")
            return None

        mock_query.side_effect = fake_query
        subnet = SubnetInfo.from_cidr("192.168.1.0/29")  # 6 usable IPs

        printers = sweep_subnet(subnet)

        assert len(printers) == 2
        ips = [p.ip_address for p in printers]
        assert "192.168.1.1" in ips
        assert "192.168.1.5" in ips

    @patch("zebra_tool.discovery.snmp.snmp_query")
    def test_empty_subnet(self, mock_query):
        mock_query.return_value = None
        subnet = SubnetInfo.from_cidr("192.168.1.0/30")
        printers = sweep_subnet(subnet)
        assert printers == []

    @patch("zebra_tool.discovery.snmp.snmp_query")
    def test_sweep_calls_query_for_each_ip(self, mock_query):
        mock_query.return_value = None
        subnet = SubnetInfo.from_cidr("192.168.1.0/30")  # 2 usable IPs
        sweep_subnet(subnet)
        assert mock_query.call_count == 2
