"""SNMP v1/v2c discovery for Zebra Link-OS printers.

Queries the Zebra enterprise OID tree (1.3.6.1.4.1.10642.*) to discover
printers and enrich data from other discovery methods.
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from zebra_tool.models import DiscoveryMethod, Printer, merge_printers
from zebra_tool.network import SubnetInfo, iter_subnet_ips

# Key Zebra enterprise OIDs for printer identification
ZEBRA_OIDS: dict[str, str] = {
    "model": "1.3.6.1.4.1.10642.1.1.0",
    "firmware": "1.3.6.1.4.1.10642.1.2.0",
    "hostname": "1.3.6.1.4.1.10642.1.4.0",
    "serial": "1.3.6.1.4.1.10642.1.9.0",
}

# Map OID field names to Printer dataclass attributes
_FIELD_MAP: dict[str, str] = {
    "model": "model",
    "firmware": "firmware_version",
    "hostname": "hostname",
    "serial": "serial_number",
}

SNMP_PORT = 161


def format_mac(raw: str | None) -> str | None:
    """Format a raw MAC address string into colon-separated notation."""
    if not raw:
        return None
    cleaned = raw.replace(" ", "").replace(":", "").replace("-", "").upper()
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _normalize_oid(oid: str) -> str:
    """Normalize an OID string for comparison (strip leading dot, MIB prefix)."""
    if "::" in oid:
        oid = oid.split("::")[-1]
    return oid.lstrip(".").strip()


def snmp_get(
    ip: str,
    oids: Sequence[str],
    community: str = "public",
    version: str = "v2c",
    timeout: float = 2.0,
    retries: int = 1,
) -> dict[str, str]:
    """Perform an SNMP get request for multiple OIDs on a single host.

    Returns a dict mapping OID string to value string. Returns empty dict
    on any error (timeout, no response, etc).
    """
    mp_model = 1 if version == "v2c" else 0

    try:
        from pysnmp.hlapi import (
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            getCmd,
        )
    except ImportError:
        return {}

    try:
        transport = UdpTransportTarget((ip, SNMP_PORT), timeout=timeout, retries=retries)
    except Exception:
        return {}

    objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]

    result: dict[str, str] = {}
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=mp_model),
            transport,
            ContextData(),
            *objects,
        )
        for error_indication, error_status, _error_index, var_binds in iterator:
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                oid_str = _normalize_oid(str(var_bind[0]))
                value = str(var_bind[1])
                result[oid_str] = value
    except Exception:
        pass

    return result


def snmp_query(
    ip: str,
    community: str = "public",
    version: str = "v2c",
    timeout: float = 2.0,
) -> Printer | None:
    """Query a single IP for Zebra printer identification via SNMP.

    Returns a Printer object if the host responds with at least one
    identifiable field, otherwise None.
    """
    oid_list = list(ZEBRA_OIDS.values())
    results = snmp_get(ip, oid_list, community=community, version=version, timeout=timeout)

    if not results:
        return None

    # Build reverse lookup: normalized OID -> field name
    oid_to_field = {
        _normalize_oid(oid): field for field, oid in ZEBRA_OIDS.items()
    }

    printer_fields: dict[str, str] = {"ip_address": ip}

    for oid_str, value in results.items():
        norm_oid = _normalize_oid(oid_str)
        field = oid_to_field.get(norm_oid)
        if field and value:
            attr = _FIELD_MAP.get(field, field)
            printer_fields[attr] = value

    # Require at least one identifying field beyond the IP
    if not any(k in printer_fields for k in ("model", "firmware_version", "serial_number")):
        return None

    printer_fields["discovered_via"] = {DiscoveryMethod.SNMP}
    printer_fields["last_seen"] = datetime.now()

    return Printer(**printer_fields)


def snmp_enrich(
    printer: Printer,
    community: str = "public",
    version: str = "v2c",
    timeout: float = 2.0,
) -> Printer:
    """Enrich an existing Printer with SNMP data. Returns merged result."""
    snmp_printer = snmp_query(
        printer.ip_address, community=community, version=version, timeout=timeout
    )
    if snmp_printer is None:
        return printer
    return merge_printers(printer, snmp_printer)


def sweep_subnet(
    subnet: SubnetInfo,
    community: str = "public",
    version: str = "v2c",
    timeout: float = 2.0,
) -> list[Printer]:
    """Sweep all usable IPs in a subnet via SNMP.

    Queries each host IP individually. Suitable for subnets where UDP
    broadcast discovery doesn't work (different VLAN, etc).
    """
    printers: list[Printer] = []

    for ip in iter_subnet_ips(subnet.network):
        printer = snmp_query(ip, community=community, version=version, timeout=timeout)
        if printer is not None:
            printers.append(printer)

    return printers
