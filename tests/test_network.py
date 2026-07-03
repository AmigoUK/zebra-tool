"""Tests for subnet detection, CIDR parsing, and broadcast computation."""

import ipaddress
from unittest.mock import patch

import pytest

from zebra_tool.network import (
    SubnetInfo,
    detect_local_subnets,
    default_subnet,
    parse_cidr,
    compute_broadcast,
    iter_subnet_ips,
)


class FakeIP:
    """Mimic ifaddr.IP for tests."""

    def __init__(self, ip, prefix):
        self.ip = ip
        self.network_prefix = prefix


class FakeAdapter:
    """Mimic ifaddr.Adapter for tests."""

    def __init__(self, name, ips):
        self.nice_name = name
        self.ips = ips


class TestParseCidr:
    def test_valid_24(self):
        net = parse_cidr("192.168.1.0/24")
        assert net.network_address == ipaddress.IPv4Address("192.168.1.0")
        assert net.prefixlen == 24

    def test_valid_16(self):
        net = parse_cidr("10.0.0.0/16")
        assert net.prefixlen == 16

    def test_valid_with_host_bits(self):
        """10.0.5.30/24 should normalise to 10.0.5.0/24."""
        net = parse_cidr("10.0.5.30/24")
        assert net.network_address == ipaddress.IPv4Address("10.0.5.0")

    def test_valid_32(self):
        net = parse_cidr("192.168.1.50/32")
        assert net.prefixlen == 32

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            parse_cidr("not-an-ip")

    def test_invalid_no_prefix(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            parse_cidr("192.168.1.0")

    def test_empty_string(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            parse_cidr("")


class TestComputeBroadcast:
    def test_24(self):
        net = ipaddress.IPv4Network("192.168.1.0/24")
        assert compute_broadcast(net) == "192.168.1.255"

    def test_16(self):
        net = ipaddress.IPv4Network("10.0.0.0/16")
        assert compute_broadcast(net) == "10.0.255.255"

    def test_30(self):
        net = ipaddress.IPv4Network("192.168.1.0/30")
        assert compute_broadcast(net) == "192.168.1.3"

    def test_32(self):
        net = ipaddress.IPv4Network("192.168.1.50/32")
        assert compute_broadcast(net) == "192.168.1.50"


class TestIterSubnetIps:
    def test_30_excludes_network_and_broadcast(self):
        net = ipaddress.IPv4Network("192.168.1.0/30")
        ips = list(iter_subnet_ips(net))
        assert ips == ["192.168.1.1", "192.168.1.2"]

    def test_32_returns_single(self):
        net = ipaddress.IPv4Network("192.168.1.50/32")
        ips = list(iter_subnet_ips(net))
        assert ips == ["192.168.1.50"]

    def test_24_count(self):
        net = ipaddress.IPv4Network("10.0.0.0/24")
        ips = list(iter_subnet_ips(net))
        assert len(ips) == 254
        assert ips[0] == "10.0.0.1"
        assert ips[-1] == "10.0.0.254"


class TestSubnetInfo:
    def test_from_cidr(self):
        info = SubnetInfo.from_cidr("192.168.1.0/24")
        assert str(info.network) == "192.168.1.0/24"
        assert info.broadcast == "192.168.1.255"
        assert info.cidr == "192.168.1.0/24"


class TestDetectLocalSubnets:
    @patch("zebra_tool.network.ifaddr")
    def test_returns_non_loopback(self, mock_ifaddr):
        mock_adapter = FakeAdapter("eth0", [
            FakeIP("192.168.1.100", 24),
            FakeIP("10.0.0.50", 24),
        ])
        mock_ifaddr.get_adapters.return_value = [mock_adapter]

        subnets = detect_local_subnets()
        assert len(subnets) == 2
        assert any(s.network.network_address == ipaddress.IPv4Address("192.168.1.0") for s in subnets)
        assert any(s.network.network_address == ipaddress.IPv4Address("10.0.0.0") for s in subnets)

    @patch("zebra_tool.network.ifaddr")
    def test_filters_loopback(self, mock_ifaddr):
        mock_adapter = FakeAdapter("lo", [FakeIP("127.0.0.1", 8)])
        mock_ifaddr.get_adapters.return_value = [mock_adapter]
        subnets = detect_local_subnets()
        assert len(subnets) == 0

    @patch("zebra_tool.network.ifaddr")
    def test_filters_ipv6(self, mock_ifaddr):
        mock_adapter = FakeAdapter("eth0", [
            FakeIP("192.168.1.100", 24),
            FakeIP(("fe80::1", 0, 0), 64),
        ])
        mock_ifaddr.get_adapters.return_value = [mock_adapter]
        subnets = detect_local_subnets()
        assert len(subnets) == 1
        assert subnets[0].network.version == 4

    @patch("zebra_tool.network.ifaddr")
    def test_no_adapters(self, mock_ifaddr):
        mock_ifaddr.get_adapters.return_value = []
        subnets = detect_local_subnets()
        assert subnets == []


class TestDefaultSubnet:
    @patch("zebra_tool.network.ifaddr")
    def test_returns_first_subnet(self, mock_ifaddr):
        mock_adapter = FakeAdapter("eth0", [FakeIP("192.168.1.100", 24)])
        mock_ifaddr.get_adapters.return_value = [mock_adapter]
        subnet = default_subnet()
        assert subnet is not None
        assert subnet.cidr == "192.168.1.0/24"

    @patch("zebra_tool.network.ifaddr")
    def test_returns_none_if_no_interfaces(self, mock_ifaddr):
        mock_ifaddr.get_adapters.return_value = []
        subnet = default_subnet()
        assert subnet is None
