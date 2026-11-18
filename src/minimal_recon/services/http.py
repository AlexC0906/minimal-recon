"""Shared HTTP client construction and timeout settings for all services."""

from typing import Callable, Optional, TypeVar

import httpx

from minimal_recon import __version__

# An honest, identifiable User-Agent: the tool is read-only and does not try to
# look like a browser.
USER_AGENT = f"minimal-recon/{__version__}"

T = TypeVar("T")

_timeout_override: Optional[float] = None


def configure(timeout: Optional[float] = None) -> None:
    """Set a global timeout (seconds) that replaces every per-service default."""
    global _timeout_override
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    _timeout_override = timeout


def resolve_timeout(default: float) -> float:
    """Return the configured global timeout, or the service default."""
    return _timeout_override if _timeout_override is not None else default


def new_client(timeout: float = 10.0) -> httpx.Client:
    """Create the standard client: redirects followed, tool User-Agent set."""
    return httpx.Client(
        follow_redirects=True,
        timeout=resolve_timeout(timeout),
        headers={"User-Agent": USER_AGENT},
    )


def with_client(
    operation: Callable[[httpx.Client], T],
    client: Optional[httpx.Client] = None,
    timeout: float = 10.0,
) -> T:
    """Run ``operation`` with the injected client, or a temporary standard one."""
    if client is not None:
        return operation(client)
    with new_client(timeout) as active_client:
        return operation(active_client)
