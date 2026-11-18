"""Output and error helpers shared by every command."""

from dataclasses import asdict, is_dataclass
import json
from typing import Any, NoReturn

import httpx
import typer

# Errors a command reports as a short message instead of a traceback.
COMMAND_ERRORS = (httpx.HTTPError, OSError, ValueError)


def emit(data: Any, as_json: bool) -> None:
    """Print a result in human-readable or automation-friendly form."""
    if as_json:
        payload = asdict(data) if is_dataclass(data) and not isinstance(data, type) else data
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    if isinstance(data, dict):
        for key, values in data.items():
            for value in values if isinstance(values, list) else [values]:
                typer.echo(f"{key}: {value}")


def handle_error(error: Exception) -> NoReturn:
    if isinstance(error, httpx.TimeoutException):
        message = "network timeout"
    elif isinstance(error, httpx.HTTPStatusError):
        message = f"remote service returned HTTP {error.response.status_code}"
    elif isinstance(error, httpx.RequestError):
        message = "network connection failed"
    else:
        message = str(error)
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=1)


def compact(value: Any) -> str:
    """Render one diff value on a single line."""
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


def short(value: Any, limit: int = 160) -> str:
    """Single-line value cut to ``limit`` characters, for terminal summaries."""
    text = compact(value)
    return text if len(text) <= limit else f"{text[: limit - 3]}..."
