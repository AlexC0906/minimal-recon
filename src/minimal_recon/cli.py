"""Command-line interface for Minimal Recon.

The commands live in ``minimal_recon.commands``; this module builds the
``recon`` application from them and holds the global options.
"""

from typing import Optional

import typer

from minimal_recon import __version__
from minimal_recon.commands import checks, footprint, reports
from minimal_recon.commands.common import handle_error
from minimal_recon.services.http import configure

app = typer.Typer(help="Read-only OSINT reconnaissance utilities.")


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"Minimal Recon {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
    timeout: Optional[float] = typer.Option(
        None,
        "--timeout",
        min=0.1,
        help="Seconds to wait on each HTTP, DNS and TLS operation instead of the per-command defaults.",
    ),
) -> None:
    """Read-only OSINT reconnaissance utilities."""
    configure(timeout)


@app.command("ui")
def ui_command(
    port: int = typer.Option(8765, "--port", min=0, max=65535, help="Local port; 0 picks a free one."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open the browser automatically."),
) -> None:
    """Open the local web interface (served on 127.0.0.1 only)."""
    from minimal_recon.ui.server import serve

    try:
        serve(port, open_browser=not no_browser, announce=typer.echo)
    except OSError as error:
        handle_error(OSError(f"could not start the interface on port {port}: {error.strerror or error}"))


for module in (checks, footprint, reports):
    app.registered_commands.extend(module.app.registered_commands)
    app.registered_groups.extend(module.app.registered_groups)


if __name__ == "__main__":
    app()
