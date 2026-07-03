"""Tests for Zebra UDP 4201 discovery protocol — packet parsing and broadcast."""

import socket
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

from zebra_tool.discovery.udp import (
    DISCOVERY_PACKET,
    RESPONSE_MAGIC,
    parse_response,
    broadcast_discover,
    build_test_packet,
)
from zebra_tool.models import DiscoveryMethod


class TestConstants:
    def test_discovery_packet(self):
        assert DISCOVERY_PACKET == b"\x2e\x2c\x3a\x01\x00\x00"

    def test_response_magic(self):
        assert RESPONSE_MAGIC == b"\x3a\x2c\x2e"


class TestParseResponse:
    def test_valid_packet(self):
        pkt = build_test_packet(
            product="79071",
            friendly_name="ZD421",
            firmware="V93.21.07Z",
            serial="4262077",
            ip="192.168.1.50",
            subnet="255.255.255.0",
            gateway="192.168.1.1",
            hostname="ZBR4262077",
        )
        printer = parse_response(pkt, source_ip="192.168.1.50")

        assert printer.ip_address == "192.168.1.50"
        assert printer.serial_number == "4262077"
        assert printer.firmware_version == "V93.21.07Z"
        assert printer.hostname == "ZBR4262077"
        assert printer.subnet_mask == "255.255.255.0"
        assert printer.default_gateway == "192.168.1.1"
        assert DiscoveryMethod.UDP in printer.discovered_via
        assert printer.last_seen is not None

    def test_model_from_friendly_name(self):
        pkt = build_test_packet(friendly_name="ZD421-203")
        printer = parse_response(pkt, source_ip="10.0.0.1")
        assert printer.model == "ZD421-203"

    def test_uses_source_ip_if_packet_ip_is_zero(self):
        """If the IP field is 0.0.0.0, fall back to the source IP."""
        pkt = build_test_packet(ip="0.0.0.0")
        printer = parse_response(pkt, source_ip="10.0.0.99")
        assert printer.ip_address == "10.0.0.99"

    def test_invalid_magic_raises(self):
        with pytest.raises(ValueError, match="Invalid response"):
            parse_response(b"\x00\x00\x00" + b"\x00" * 200, source_ip="10.0.0.1")

    def test_short_packet_does_not_crash(self):
        """A truncated packet should not raise — missing fields become None."""
        pkt = RESPONSE_MAGIC + b"\x03" + b"\x00" * 10
        printer = parse_response(pkt, source_ip="10.0.0.1")
        assert printer.ip_address == "10.0.0.1"
        assert printer.serial_number is None
        assert printer.firmware_version is None

    def test_null_terminated_strings(self):
        """Strings with embedded nulls are correctly truncated."""
        pkt = build_test_packet(
            serial="AB123\x00\x00garbage",
        )
        printer = parse_response(pkt, source_ip="10.0.0.1")
        assert printer.serial_number == "AB123"

    def test_empty_strings_become_none(self):
        pkt = build_test_packet(
            friendly_name="",
            serial="",
            firmware="",
            hostname="",
        )
        printer = parse_response(pkt, source_ip="10.0.0.1")
        assert printer.model is None
        assert printer.serial_number is None
        assert printer.firmware_version is None
        assert printer.hostname is None


class TestBroadcastDiscover:
    @patch("zebra_tool.discovery.udp.socket.socket")
    def test_sends_discovery_packet(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout()

        broadcast_discover("192.168.1.255", timeout=0.1)

        # Verify at least one sendto to the broadcast address on port 4201
        sends = mock_sock.sendto.call_args_list
        assert any(
            call.args[0] == DISCOVERY_PACKET
            and call.args[1] == ("192.168.1.255", 4201)
            for call in sends
        )

    @patch("zebra_tool.discovery.udp.socket.socket")
    def test_collects_responses(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Build a valid response packet
        pkt = build_test_packet(
            serial="4262077",
            ip="192.168.1.50",
            friendly_name="ZD421-203",
            firmware="V93.21.07Z",
            hostname="ZBR4262077",
        )

        # First recvfrom returns the packet, second raises socket.timeout
        mock_sock.recvfrom.side_effect = [
            (pkt, ("192.168.1.50", 4201)),
            socket.timeout(),
        ]

        printers = broadcast_discover("192.168.1.255", timeout=0.1)

        assert len(printers) == 1
        assert printers[0].ip_address == "192.168.1.50"
        assert printers[0].serial_number == "4262077"

    @patch("zebra_tool.discovery.udp.socket.socket")
    def test_dedupes_by_ip(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        pkt = build_test_packet(serial="SN001", ip="192.168.1.50")

        # Same IP responds twice (Zebra sends 9 replies per discovery)
        mock_sock.recvfrom.side_effect = [
            (pkt, ("192.168.1.50", 4201)),
            (pkt, ("192.168.1.50", 4201)),
            socket.timeout(),
        ]

        printers = broadcast_discover("192.168.1.255", timeout=0.1)
        assert len(printers) == 1  # deduped

    @patch("zebra_tool.discovery.udp.socket.socket")
    def test_no_responses_returns_empty(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout()

        printers = broadcast_discover("192.168.1.255", timeout=0.1)
        assert printers == []

    @patch("zebra_tool.discovery.udp.socket.socket")
    def test_ignores_non_zebra_packets(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        mock_sock.recvfrom.side_effect = [
            (b"\x00\x00\x00random garbage", ("192.168.1.99", 4201)),
            socket.timeout(),
        ]

        printers = broadcast_discover("192.168.1.255", timeout=0.1)
        assert printers == []

    @patch("zebra_tool.discovery.udp.socket.socket")
    def test_sets_broadcast_socket_option(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout()

        broadcast_discover("192.168.1.255", timeout=0.1)

        mock_sock.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
