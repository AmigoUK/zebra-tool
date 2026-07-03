"""Textual TUI application for Zebra printer discovery."""

from __future__ import annotations

from datetime import datetime

from textual import work, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import (
    Header,
    Footer,
    DataTable,
    Input,
    RichLog,
    Static,
    Select,
)

from zebra_tool.models import Printer, PrinterStatus, DiscoveryMethod
from zebra_tool.network import SubnetInfo, default_subnet, parse_cidr
from zebra_tool.discovery.udp import broadcast_discover
from zebra_tool.discovery.snmp import sweep_subnet, snmp_enrich
from zebra_tool.discovery.mdns import mdns_browse
from zebra_tool.discovery.tcp import enrich_via_tcp_9100
from zebra_tool.export import export_csv, export_json, generate_filename
from zebra_tool.tui.registry import PrinterRegistry
from zebra_tool.tui.detail_screen import DetailScreen


class PrinterDiscovered(Message):
    """Posted when a printer is found by any discovery method."""

    def __init__(self, printer: Printer, source: str = "") -> None:
        super().__init__()
        self.printer = printer
        self.source = source


class ScanStarted(Message):
    """Posted when a scan begins."""


class ScanComplete(Message):
    """Posted when all discovery methods finish."""

    def __init__(self, total: int) -> None:
        super().__init__()
        self.total = total


class ZebraDiscoveryApp(App):
    """Terminal UI for discovering Zebra printers on a LAN."""

    TITLE = "Zebra Printer Discovery"
    SUB_TITLE = "UDP 4201 | SNMP | mDNS"

    CSS = """
    #subnet-row {
        height: 3;
        padding: 0 1;
    }

    #subnet-input {
        width: 1fr;
    }

    #community-input {
        width: 20;
    }

    #timeout-input {
        width: 10;
    }

    #autorefresh-select {
        width: 18;
    }

    #results {
        height: 1fr;
        margin: 0 1;
        border: solid $primary;
    }

    #log-panel {
        height: 8;
        margin: 0 1;
        border: solid $accent;
    }

    #status-bar {
        height: 1;
        padding: 0 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("f2", "scan", "Scan"),
        Binding("f3", "export_csv", "CSV"),
        Binding("f4", "export_json", "JSON"),
        Binding("r", "refresh", "Refresh"),
        Binding("enter", "show_detail", "Details"),
        Binding("q", "quit", "Quit"),
    ]

    AUTO_REFRESH_OPTIONS = [
        ("Off", None),
        ("30s", 30),
        ("60s", 60),
        ("120s", 120),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.registry = PrinterRegistry()
        self._scan_active = False
        self._auto_refresh_timer = None

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal(id="subnet-row"):
            yield Input(placeholder="Subnet (CIDR)", id="subnet-input")
            yield Input(value="public", placeholder="Community", id="community-input")
            yield Input(value="2.0", placeholder="Timeout", id="timeout-input")
            yield Select(
                self.AUTO_REFRESH_OPTIONS,
                value="Off",
                id="autorefresh-select",
            )

        yield DataTable(id="results")
        yield RichLog(id="log-panel", markup=True)
        yield Static("Ready — press F2 to scan", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results", DataTable)
        table.add_column("", width=1)         # status dot
        table.add_column("IP", width=16)
        table.add_column("Model", width=28)
        table.add_column("Serial", width=16)
        table.add_column("Firmware", width=16)
        table.add_column("Hostname", width=16)

        subnet = default_subnet()
        if subnet:
            self.query_one("#subnet-input", Input).value = subnet.cidr

        self.query_one("#log-panel", RichLog).write(
            "[dim]Ready. Press F2 to start scanning.[/dim]"
        )

    def _log(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        log = self.query_one("#log-panel", RichLog)
        log.write(f"[dim]{ts}[/dim] {text}")

    def _set_status(self, text: str) -> None:
        self.query_one("#status-bar", Static).update(text)

    def _refresh_table(self) -> None:
        table = self.query_one("#results", DataTable)
        table.clear()

        for printer in self.registry.to_list():
            if printer.stale:
                dot = "[dim]░[/dim]"
            elif printer.status is PrinterStatus.READY:
                dot = "[green]●[/green]"
            elif printer.status is PrinterStatus.ERROR:
                dot = "[red]●[/red]"
            elif printer.status is PrinterStatus.PAUSED:
                dot = "[yellow]●[/yellow]"
            else:
                dot = "[blue]●[/blue]"

            table.add_row(
                dot,
                printer.ip_address,
                printer.model or "-",
                printer.serial_number or "-",
                printer.firmware_version or "-",
                printer.hostname or "-",
            )

    def _parse_subnet(self) -> SubnetInfo | None:
        raw = self.query_one("#subnet-input", Input).value.strip()
        if not raw:
            self._log("[red]No subnet specified[/red]")
            return None
        try:
            return SubnetInfo.from_cidr(raw)
        except ValueError as e:
            self._log(f"[red]{e}[/red]")
            return None

    def _get_community(self) -> str:
        return self.query_one("#community-input", Input).value.strip() or "public"

    def _get_timeout(self) -> float:
        try:
            return float(self.query_one("#timeout-input", Input).value)
        except (ValueError, TypeError):
            return 2.0

    # --- Discovery workers ---

    @work(thread=True, exclusive=True, group="discovery")
    def action_scan(self) -> None:
        """Start discovery using all methods in parallel."""
        if self._scan_active:
            return

        subnet = self._parse_subnet()
        if not subnet:
            return

        self._scan_active = True
        self.registry.begin_refresh()
        self._set_status("● Scanning…")
        self._log(f"[bold]Scan started[/bold] — subnet {subnet.cidr}")

        community = self._get_community()
        timeout = self._get_timeout()

        self._run_udp(subnet, timeout)
        self._run_snmp(subnet, community, timeout)
        self._run_mdns()

    def _run_udp(self, subnet: SubnetInfo, timeout: float) -> None:
        try:
            self._log(f"[UDP] Broadcasting to {subnet.broadcast}:4201…")
            printers = broadcast_discover(subnet.broadcast, timeout=timeout)
            for p in printers:
                self.post_message(PrinterDiscovered(p, "UDP"))
            self._log(f"[UDP] Found {len(printers)} printer(s)")
        except Exception as e:
            self._log(f"[red][UDP] Error: {e}[/red]")

    def _run_snmp(self, subnet: SubnetInfo, community: str, timeout: float) -> None:
        try:
            self._log(f"[SNMP] Sweeping {subnet.cidr}…")
            printers = sweep_subnet(subnet, community=community, timeout=timeout)
            for p in printers:
                self.post_message(PrinterDiscovered(p, "SNMP"))
            self._log(f"[SNMP] Found {len(printers)} printer(s)")
        except Exception as e:
            self._log(f"[red][SNMP] Error: {e}[/red]")

    def _run_mdns(self) -> None:
        try:
            self._log("[mDNS] Browsing for services…")
            printers = mdns_browse(timeout=5.0)
            for p in printers:
                self.post_message(PrinterDiscovered(p, "mDNS"))
            self._log(f"[mDNS] Found {len(printers)} printer(s)")
        except Exception as e:
            self._log(f"[red][mDNS] Error: {e}[/red]")

    def _finalize_scan(self) -> None:
        self.registry.end_refresh()
        self._scan_active = False
        total = len(self.registry)
        self._refresh_table()
        self._set_status(f"Scan complete — {total} printer(s) found")
        self._log(f"[bold]Scan complete[/bold] — {total} printer(s)")

    @on(PrinterDiscovered)
    def _on_printer_discovered(self, msg: PrinterDiscovered) -> None:
        self.registry.add(msg.printer)
        self._refresh_table()
        self._log(
            f"[{msg.source}] Found {msg.printer.ip_address}"
            f" — {msg.printer.model or 'unknown model'}"
        )

    @on(ScanComplete)
    def _on_scan_complete(self, msg: ScanComplete) -> None:
        self._finalize_scan()

    # --- Actions ---

    def action_refresh(self) -> None:
        """Re-scan: existing printers not seen again are marked stale."""
        self.action_scan()

    def action_export_csv(self) -> None:
        printers = self.registry.to_list()
        if not printers:
            self._log("[yellow]No printers to export[/yellow]")
            return
        filename = generate_filename("csv")
        export_csv(printers, filename)
        self._log(f"[green]Exported {len(printers)} printers to {filename}[/green]")

    def action_export_json(self) -> None:
        printers = self.registry.to_list()
        if not printers:
            self._log("[yellow]No printers to export[/yellow]")
            return
        filename = generate_filename("json")
        export_json(printers, filename)
        self._log(f"[green]Exported {len(printers)} printers to {filename}[/green]")

    def action_show_detail(self) -> None:
        table = self.query_one("#results", DataTable)
        if table.cursor_row is None or table.cursor_row < 0:
            return
        printers = self.registry.to_list()
        if table.cursor_row >= len(printers):
            return
        printer = printers[table.cursor_row]
        self.push_screen(DetailScreen(printer.to_dict()))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle Enter key on the results table."""
        self.action_show_detail()

    def on_worker_state_changed(self, event) -> None:
        """When all discovery workers finish, finalize the scan."""
        if event.group == "discovery" and event.state == "running":
            return
        # Check if any discovery workers are still running
        active = [w for w in self.workers if w.group == "discovery"]
        if not active and self._scan_active:
            self._finalize_scan()
