"""CSV and JSON export for discovered printers."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Union

from zebra_tool.models import Printer

CSV_COLUMNS = [
    "ip_address",
    "hostname",
    "model",
    "serial_number",
    "firmware_version",
    "mac_address",
    "subnet_mask",
    "default_gateway",
    "status",
    "print_speed",
    "darkness",
    "head_temperature",
    "total_labels",
    "discovered_via",
    "last_seen",
    "stale",
]

PathLike = Union[str, Path]


def generate_filename(ext: str) -> str:
    """Generate a timestamped filename like zebra_printers_20250703_142305.csv."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"zebra_printers_{ts}.{ext}"


def export_csv(printers: list[Printer], path: PathLike) -> Path:
    """Write printers to a CSV file. Returns the resolved Path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for printer in printers:
            row = printer.to_dict()
            # Flatten discovered_via list to comma-separated string
            if isinstance(row.get("discovered_via"), list):
                row["discovered_via"] = ",".join(row["discovered_via"])
            writer.writerow(row)

    return path


def export_json(printers: list[Printer], path: PathLike) -> Path:
    """Write printers to a JSON file. Returns the resolved Path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = [printer.to_dict() for printer in printers]
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return path
