"""TCP 9100 SGD enrichment for Zebra printers.

Connects to the printer's raw printing port (9100) and sends SGD
(Set-Get Data) commands to retrieve live operational status: print
speed, darkness, head temperature, odometer, and status.
"""

from __future__ import annotations

import socket

from zebra_tool.models import Printer, PrinterStatus

TCP_PORT = 9100

# SGD commands mapped to Printer fields
SGD_COMMANDS: dict[str, str] = {
    "host_status": 'host_status',
    "print.speed": 'print.speed',
    "print.darkness": 'print.darkness',
    "head_temperature": 'head_temperature',
    "odometer.total_label": 'odometer.total_label',
}

_RECV_BUFFER = 4096


def parse_sgd_response(raw: str | None) -> str | None:
    """Parse a raw SGD response string.

    SGD responses are typically quoted: '"value"'. This strips
    surrounding whitespace, quotes, and trailing newlines.
    Returns None for empty responses.
    """
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    # Remove trailing \r\n if present
    s = s.rstrip("\r\n").strip()
    # Strip surrounding double quotes
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s if s else None


def parse_host_status(raw: str | None) -> PrinterStatus:
    """Parse an SGD host_status response into a PrinterStatus.

    The response is a comma-separated list of status indicators.
    Priority: error > paused > ready > unknown.
    """
    value = parse_sgd_response(raw)
    if not value:
        return PrinterStatus.UNKNOWN

    parts = [p.strip().lower() for p in value.split(",")]

    if any("error" in p for p in parts):
        return PrinterStatus.ERROR
    if any("paused" in p or "pause" in p for p in parts):
        return PrinterStatus.PAUSED
    if any("ready" in p for p in parts):
        return PrinterStatus.READY
    return PrinterStatus.UNKNOWN


def _send_sgd(sock: socket.socket, var_name: str) -> str | None:
    """Send a single SGD getvar command and return the parsed response.

    Does not catch exceptions — caller handles timeouts/connection errors.
    """
    command = f'! U1 getvar "{var_name}"\r\n'
    sock.sendall(command.encode("ascii"))
    data = sock.recv(_RECV_BUFFER)
    if not data:
        return None
    return parse_sgd_response(data.decode("ascii", errors="replace"))


def enrich_via_tcp_9100(
    printer: Printer,
    timeout: float = 2.0,
) -> Printer:
    """Enrich a Printer with live status via TCP 9100 SGD commands.

    On connection failure or timeout, returns the printer unchanged.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((printer.ip_address, TCP_PORT))
    except (ConnectionRefusedError, socket.timeout, OSError):
        sock.close()
        return printer

    try:
        # Query host_status first
        raw_status = _send_sgd(sock, SGD_COMMANDS["host_status"])
        printer.status = parse_host_status(raw_status)

        # Query remaining fields
        field_map = {
            "print.speed": "print_speed",
            "print.darkness": "darkness",
            "head_temperature": "head_temperature",
            "odometer.total_label": "total_labels",
        }

        for var_name, attr in field_map.items():
            try:
                value = _send_sgd(sock, SGD_COMMANDS[var_name])
                if value is not None:
                    setattr(printer, attr, value)
            except (socket.timeout, OSError):
                break  # connection dead, stop trying
    except (socket.timeout, OSError):
        pass
    finally:
        sock.close()

    return printer
