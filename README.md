# zebra-tool

Terminal-based discovery tool for finding Zebra printers on a LAN.

Discovers Zebra Link-OS printers (ZD421, ZD621, ZT411, GK420, and more) using three methods:

- **UDP 4201** — Zebra proprietary broadcast (fastest, richest response)
- **SNMP v1/v2c** — OID queries under `1.3.6.1.4.1.10642.*`
- **mDNS / Bonjour** — zero-config `_ipp._tcp` browse

Optional TCP 9100 enrichment pulls live status (print speed, darkness, head temperature, odometer).

## Install

```bash
uv venv && uv sync
```

## Run

```bash
uv run zebra-tool
```

## Keys

| Key | Action |
|-----|--------|
| `F2` | Start scan |
| `Enter` | Printer detail |
| `F3` | Export CSV |
| `F4` | Export JSON |
| `R` | Refresh / re-scan |
| `Q` | Quit |
