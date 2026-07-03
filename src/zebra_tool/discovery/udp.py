"""Zebra proprietary UDP 4201 broadcast discovery protocol.

Sends a 6-byte discovery packet to the broadcast address on UDP port 4201.
Zebra printers respond with a unicast packet containing model, serial
number, firmware version, IP, subnet mask, gateway, and hostname.
"""

from __future__ import annotations

import socket
import time
from datetime import datetime

from zebra_tool.models import DiscoveryMethod, Printer

DISCOVERY_PORT = 4201

#: 6-byte packet sent to discover printers
DISCOVERY_PACKET = b"\x2e\x2c\x3a\x01\x00\x00"

#: First 3 bytes of every valid response
RESPONSE_MAGIC = b"\x3a\x2c\x2e"

# Number of discovery packets to send (Zebra protocol sends 3 rounds of 3)
_DISCOVERY_ROUNDS = 3
_PACKETS_PER_ROUND = 3

# Response packet field offsets (reverse-engineered from Zebra firmware)
_OFFSET_MAGIC = 0x00
_OFFSET_VERSION = 0x03
_OFFSET_PRODUCT = 0x04  # 8 bytes, null-terminated
_OFFSET_FRIENDLY = 0x0C  # 12 bytes, null-terminated (used as model)
_OFFSET_DATE_CODE = 0x18  # 8 bytes, null-terminated
_OFFSET_FIRMWARE = 0x21  # 14 bytes, null-terminated
_OFFSET_SERIAL = 0x37  # 8 bytes, null-terminated
_OFFSET_IP = 0x43  # 4 bytes, big-endian
_OFFSET_SUBNET = 0x47  # 4 bytes, big-endian
_OFFSET_GATEWAY = 0x4C  # 4 bytes, big-endian
_OFFSET_HOSTNAME = 0x50  # 16 bytes, null-terminated

_MIN_PACKET_SIZE = _OFFSET_HOSTNAME + 16


def _extract_str(data: bytes, start: int, end: int) -> str | None:
    """Extract a null-terminated ASCII string from a byte range."""
    if start >= len(data):
        return None
    chunk = data[start : min(end, len(data))]
    null_idx = chunk.find(b"\x00")
    if null_idx >= 0:
        chunk = chunk[:null_idx]
    s = chunk.decode("ascii", errors="replace").strip()
    return s if s else None


def _extract_ip(data: bytes, offset: int) -> str | None:
    """Extract a dotted-quad IP address from 4 bytes at the given offset."""
    if offset + 4 > len(data):
        return None
    return ".".join(str(b) for b in data[offset : offset + 4])


def parse_response(data: bytes, source_ip: str) -> Printer:
    """Parse a Zebra discovery response packet into a Printer object.

    Raises ValueError if the packet doesn't start with the response magic.
    Truncated packets are handled gracefully (missing fields become None).
    """
    if len(data) < 3 or data[:3] != RESPONSE_MAGIC:
        raise ValueError("Invalid response packet: bad magic bytes")

    ip = _extract_ip(data, _OFFSET_IP)
    if not ip or ip == "0.0.0.0":
        ip = source_ip

    return Printer(
        ip_address=ip,
        hostname=_extract_str(data, _OFFSET_HOSTNAME, _OFFSET_HOSTNAME + 16),
        model=_extract_str(data, _OFFSET_FRIENDLY, _OFFSET_FRIENDLY + 12),
        serial_number=_extract_str(data, _OFFSET_SERIAL, _OFFSET_SERIAL + 8),
        firmware_version=_extract_str(data, _OFFSET_FIRMWARE, _OFFSET_FIRMWARE + 14),
        subnet_mask=_extract_ip(data, _OFFSET_SUBNET),
        default_gateway=_extract_ip(data, _OFFSET_GATEWAY),
        discovered_via={DiscoveryMethod.UDP},
        last_seen=datetime.now(),
    )


def broadcast_discover(
    broadcast_addr: str,
    port: int = DISCOVERY_PORT,
    timeout: float = 2.0,
) -> list[Printer]:
    """Broadcast discovery packets and collect printer responses.

    Sends multiple rounds of discovery packets to the broadcast address,
    then listens for responses until the timeout expires. Responses are
    deduplicated by IP address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    target = (broadcast_addr, port)
    for _ in range(_DISCOVERY_ROUNDS):
        for _ in range(_PACKETS_PER_ROUND):
            sock.sendto(DISCOVERY_PACKET, target)

    printers: dict[str, Printer] = {}
    deadline = time.monotonic() + timeout

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            try:
                printer = parse_response(data, addr[0])
            except ValueError:
                continue
            if printer.ip_address not in printers:
                printers[printer.ip_address] = printer
    finally:
        sock.close()

    return list(printers.values())


def build_test_packet(
    product: str = "79071",
    friendly_name: str = "ZD421-T",
    date_code: str = "1166A",
    firmware: str = "V93.21.07Z",
    serial: str = "D6J2117011",
    ip: str = "192.168.1.50",
    subnet: str = "255.255.255.0",
    gateway: str = "192.168.1.1",
    hostname: str = "ZBR4262077",
) -> bytes:
    """Build a synthetic Zebra discovery response packet for testing."""
    pkt = bytearray(_MIN_PACKET_SIZE)

    pkt[_OFFSET_MAGIC : _OFFSET_MAGIC + 3] = RESPONSE_MAGIC
    pkt[_OFFSET_VERSION] = 0x03

    def _put_str(offset: int, length: int, value: str) -> None:
        b = value.encode("ascii", errors="replace")[:length]
        pkt[offset : offset + len(b)] = b

    _put_str(_OFFSET_PRODUCT, 8, product)
    _put_str(_OFFSET_FRIENDLY, 12, friendly_name)
    _put_str(_OFFSET_DATE_CODE, 8, date_code)
    _put_str(_OFFSET_FIRMWARE, 14, firmware)
    _put_str(_OFFSET_SERIAL, 8, serial)
    _put_str(_OFFSET_HOSTNAME, 16, hostname)

    pkt[_OFFSET_IP : _OFFSET_IP + 4] = bytes(int(x) for x in ip.split("."))
    pkt[_OFFSET_SUBNET : _OFFSET_SUBNET + 4] = bytes(
        int(x) for x in subnet.split(".")
    )
    pkt[_OFFSET_GATEWAY : _OFFSET_GATEWAY + 4] = bytes(
        int(x) for x in gateway.split(".")
    )

    return bytes(pkt)
