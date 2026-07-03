"""Detail modal screen showing full printer information."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll, Center, Middle
from textual.screen import ModalScreen
from textual.widgets import Static, Button


class DetailScreen(ModalScreen):
    """Modal screen displaying detailed information about a selected printer."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Close", show=True),
        Binding("t", "reenrich", "Re-enrich (TCP 9100)", show=True),
    ]

    DEFAULT_CSS = """
    DetailScreen {
        align: center middle;
    }

    #detail-container {
        width: 70;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }

    #detail-title {
        text-align: center;
        text-style: bold;
        color: $text;
        margin-bottom: 1;
    }

    .detail-row {
        height: 1;
        margin: 0 0 0 0;
    }

    .detail-label {
        color: $text-muted;
        width: 20;
    }

    .detail-value {
        color: $text;
    }

    .detail-separator {
        margin: 1 0;
        color: $primary-darken-3;
    }

    #detail-buttons {
        dock: bottom;
        height: 3;
        align: center middle;
        padding-top: 1;
    }
    """

    def __init__(self, printer_data: dict) -> None:
        super().__init__()
        self.printer_data = printer_data

    def compose(self) -> ComposeResult:
        d = self.printer_data

        def _row(label: str, value) -> ComposeResult:
            yield Static(
                f"[dim]{label:<20}[/dim] [bold]{value or '-'}[/bold]",
                classes="detail-row",
            )

        with VerticalScroll(id="detail-container"):
            yield Static(d.get("ip_address", "?"), id="detail-title")

            yield from _row("Model", d.get("model"))
            yield from _row("Serial", d.get("serial_number"))
            yield from _row("Firmware", d.get("firmware_version"))
            yield from _row("Hostname", d.get("hostname"))
            yield from _row("MAC", d.get("mac_address"))
            yield from _row("Subnet", d.get("subnet_mask"))
            yield from _row("Gateway", d.get("default_gateway"))

            yield Static("─" * 50, classes="detail-separator")

            status = d.get("status", "unknown")
            yield from _row("Status", status)
            yield from _row("Print speed", d.get("print_speed"))
            yield from _row("Darkness", d.get("darkness"))
            yield from _row("Head temp", d.get("head_temperature"))
            yield from _row("Total labels", d.get("total_labels"))

            yield Static("─" * 50, classes="detail-separator")

            via = d.get("discovered_via", [])
            via_str = ", ".join(via) if isinstance(via, list) else str(via)
            yield from _row("Discovered via", via_str)
            yield from _row("Last seen", d.get("last_seen"))
            yield from _row("Stale", "Yes" if d.get("stale") else "No")

            with Center(id="detail-buttons"):
                yield Button("Close (Esc)", id="btn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.app.pop_screen()

    def action_reenrich(self) -> None:
        self.dismiss("reenrich")
