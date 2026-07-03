"""Tests for TCP 9100 SGD enrichment."""

import socket
from unittest.mock import patch, MagicMock

import pytest

from zebra_tool.models import Printer, PrinterStatus
from zebra_tool.discovery.tcp import (
    SGD_COMMANDS,
    parse_sgd_response,
    parse_host_status,
    enrich_via_tcp_9100,
)


class TestSgdCommands:
    def test_includes_host_status(self):
        assert "host_status" in SGD_COMMANDS

    def test_includes_print_speed(self):
        assert "print.speed" in SGD_COMMANDS

    def test_includes_darkness(self):
        assert "print.darkness" in SGD_COMMANDS

    def test_includes_head_temperature(self):
        assert "head_temperature" in SGD_COMMANDS

    def test_includes_odometer(self):
        assert "odometer.total_label" in SGD_COMMANDS


class TestParseSgdResponse:
    def test_quoted_value(self):
        assert parse_sgd_response('"6"') == "6"

    def test_quoted_with_whitespace(self):
        assert parse_sgd_response('  "6"  ') == "6"

    def test_no_quotes(self):
        assert parse_sgd_response("15") == "15"

    def test_empty_quoted(self):
        assert parse_sgd_response('""') is None

    def test_empty_string(self):
        assert parse_sgd_response("") is None

    def test_with_newline(self):
        assert parse_sgd_response('"6"\r\n') == "6"

    def test_comma_separated(self):
        result = parse_sgd_response('"ready,no errors"')
        assert result == "ready,no errors"

    def test_strips_outer_quotes_preserves_inner(self):
        result = parse_sgd_response('"V93.21.07Z"')
        assert result == "V93.21.07Z"


class TestParseHostStatus:
    def test_ready(self):
        status = parse_host_status('"ready"')
        assert status is PrinterStatus.READY

    def test_ready_in_list(self):
        status = parse_host_status('"ready,head cold,no label"')
        assert status is PrinterStatus.READY

    def test_paused(self):
        status = parse_host_status('"paused"')
        assert status is PrinterStatus.PAUSED

    def test_paused_in_list(self):
        status = parse_host_status('"ready,paused"')
        assert status is PrinterStatus.PAUSED

    def test_error(self):
        status = parse_host_status('"error"')
        assert status is PrinterStatus.ERROR

    def test_error_in_list(self):
        status = parse_host_status('"head open,error"')
        assert status is PrinterStatus.ERROR

    def test_unknown_status(self):
        status = parse_host_status('"something weird"')
        assert status is PrinterStatus.UNKNOWN

    def test_empty(self):
        status = parse_host_status("")
        assert status is PrinterStatus.UNKNOWN

    def test_none(self):
        status = parse_host_status(None)
        assert status is PrinterStatus.UNKNOWN


class TestEnrichViaTcp9100:
    @patch("zebra_tool.discovery.tcp.socket.socket")
    def test_enriches_all_fields(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        responses = [
            b'"ready"\r\n',                           # host_status
            b'"6"\r\n',                               # print.speed
            b'"15"\r\n',                              # print.darkness
            b'"32"\r\n',                              # head_temperature
            b'"127843"\r\n',                          # odometer.total_label
        ]
        mock_sock.recv.side_effect = responses

        printer = Printer(ip_address="192.168.1.50")
        result = enrich_via_tcp_9100(printer, timeout=2.0)

        assert result.status is PrinterStatus.READY
        assert result.print_speed == "6"
        assert result.darkness == "15"
        assert result.head_temperature == "32"
        assert result.total_labels == "127843"

    @patch("zebra_tool.discovery.tcp.socket.socket")
    def test_connection_reflected(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError()

        printer = Printer(ip_address="192.168.1.50", model="ZD421")
        result = enrich_via_tcp_9100(printer)

        # Should return unchanged printer
        assert result.model == "ZD421"
        assert result.status is PrinterStatus.UNKNOWN
        assert result.print_speed is None

    @patch("zebra_tool.discovery.tcp.socket.socket")
    def test_timeout(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        printer = Printer(ip_address="192.168.1.50")
        result = enrich_via_tcp_9100(printer)

        assert result.status is PrinterStatus.UNKNOWN

    @patch("zebra_tool.discovery.tcp.socket.socket")
    def test_partial_response(self, mock_socket_cls):
        """If some commands fail, still enrich what we can."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        responses = [
            b'"ready"\r\n',        # host_status
            b'"6"\r\n',            # print.speed
            b'',                   # darkness - empty response
            socket.timeout(),      # head_temperature - timeout
        ]
        mock_sock.recv.side_effect = responses

        printer = Printer(ip_address="192.168.1.50")
        result = enrich_via_tcp_9100(printer)

        assert result.status is PrinterStatus.READY
        assert result.print_speed == "6"
        assert result.darkness is None
        assert result.head_temperature is None

    @patch("zebra_tool.discovery.tcp.socket.socket")
    def test_sends_sgd_commands(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b'""\r\n'

        printer = Printer(ip_address="192.168.1.50")
        enrich_via_tcp_9100(printer)

        # Verify sendall was called with SGD commands
        sent_data = [call.args[0] for call in mock_sock.sendall.call_args_list]
        # At least the host_status command should have been sent
        assert any(b"host_status" in d for d in sent_data)

    @patch("zebra_tool.discovery.tcp.socket.socket")
    def test_connects_to_port_9100(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b'""\r\n'

        printer = Printer(ip_address="192.168.1.50")
        enrich_via_tcp_9100(printer)

        mock_sock.connect.assert_called_with(("192.168.1.50", 9100))

    @patch("zebra_tool.discovery.tcp.socket.socket")
    def test_closes_socket(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b'""\r\n'

        printer = Printer(ip_address="192.168.1.50")
        enrich_via_tcp_9100(printer)

        mock_sock.close.assert_called_once()
