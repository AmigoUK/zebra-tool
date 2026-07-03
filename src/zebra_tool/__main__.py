"""Entry point for the Zebra printer discovery tool.

Run with:
    uv run zebra-tool
    uv run python -m zebra_tool
"""

from __future__ import annotations

import sys


def main() -> None:
    """Launch the Textual TUI application."""
    from zebra_tool.tui.app import ZebraDiscoveryApp

    app = ZebraDiscoveryApp()
    app.run()


if __name__ == "__main__":
    main()
