"""Tests for CSV and JSON export."""

import csv
import json
from datetime import datetime
from pathlib import Path

import pytest

from zebra_tool.models import DiscoveryMethod, Printer, PrinterStatus
from zebra_tool.export import (
    export_csv,
    export_json,
    generate_filename,
    CSV_COLUMNS,
)


@pytest.fixture
def sample_printers():
    return [
        Printer(
            ip_address="192.168.1.50",
            hostname="ZBR4262077",
            model="ZTC ZD421-203dpi ZPL",
            serial_number="D6J211701128",
            firmware_version="V93.21.07Z",
            mac_address="00:1B:A5:XX:XX:XX",
            status=PrinterStatus.READY,
            print_speed="6",
            darkness="15",
            discovered_via={DiscoveryMethod.UDP, DiscoveryMethod.SNMP},
            last_seen=datetime(2025, 7, 3, 14, 23, 5),
        ),
        Printer(
            ip_address="192.168.1.51",
            model="ZTC ZD621-300dpi ZPL",
            serial_number="D7J2210022",
            firmware_version="V93.21.07Z",
            status=PrinterStatus.UNKNOWN,
            discovered_via={DiscoveryMethod.MDNS},
        ),
    ]


class TestGenerateFilename:
    def test_csv_extension(self):
        name = generate_filename("csv")
        assert name.endswith(".csv")
        assert "zebra_printers_" in name

    def test_json_extension(self):
        name = generate_filename("json")
        assert name.endswith(".json")
        assert "zebra_printers_" in name

    def test_includes_timestamp(self):
        name = generate_filename("csv")
        # Should match pattern zebra_printers_YYYYMMDD_HHMMSS.csv
        assert len(name) == len("zebra_printers_20250703_142305.csv")


class TestExportCsv:
    def test_writes_file(self, tmp_path, sample_printers):
        path = tmp_path / "printers.csv"
        export_csv(sample_printers, path)
        assert path.exists()

    def test_header_row(self, tmp_path, sample_printers):
        path = tmp_path / "printers.csv"
        export_csv(sample_printers, path)
        with open(path) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames is not None
            assert "ip_address" in reader.fieldnames
            assert "model" in reader.fieldnames
            assert "serial_number" in reader.fieldnames

    def test_data_rows(self, tmp_path, sample_printers):
        path = tmp_path / "printers.csv"
        export_csv(sample_printers, path)
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["ip_address"] == "192.168.1.50"
        assert rows[0]["model"] == "ZTC ZD421-203dpi ZPL"
        assert rows[0]["serial_number"] == "D6J211701128"
        assert rows[1]["ip_address"] == "192.168.1.51"

    def test_empty_list(self, tmp_path):
        path = tmp_path / "empty.csv"
        export_csv([], path)
        with open(path) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames == CSV_COLUMNS
            rows = list(reader)
            assert len(rows) == 0

    def test_accepts_string_path(self, tmp_path, sample_printers):
        path = str(tmp_path / "str_path.csv")
        export_csv(sample_printers, path)
        assert Path(path).exists()


class TestExportJson:
    def test_writes_file(self, tmp_path, sample_printers):
        path = tmp_path / "printers.json"
        export_json(sample_printers, path)
        assert path.exists()

    def test_valid_json(self, tmp_path, sample_printers):
        path = tmp_path / "printers.json"
        export_json(sample_printers, path)
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_content(self, tmp_path, sample_printers):
        path = tmp_path / "printers.json"
        export_json(sample_printers, path)
        with open(path) as f:
            data = json.load(f)
        assert data[0]["ip_address"] == "192.168.1.50"
        assert data[0]["model"] == "ZTC ZD421-203dpi ZPL"
        assert data[0]["serial_number"] == "D6J211701128"
        assert data[0]["status"] == "ready"
        assert "udp_4201" in data[0]["discovered_via"]

    def test_empty_list(self, tmp_path):
        path = tmp_path / "empty.json"
        export_json([], path)
        with open(path) as f:
            data = json.load(f)
        assert data == []

    def test_null_fields_preserved(self, tmp_path, sample_printers):
        path = tmp_path / "printers.json"
        export_json(sample_printers, path)
        with open(path) as f:
            data = json.load(f)
        # Second printer has no hostname
        assert data[1]["hostname"] is None
