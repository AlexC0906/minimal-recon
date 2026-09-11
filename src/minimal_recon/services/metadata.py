"""Local file metadata extraction."""

from pathlib import Path
from typing import Any


def extract_metadata(path: Path) -> dict[str, Any]:
    """Return non-sensitive filesystem metadata for a local file."""
    stat = path.stat()
    return {
        "name": path.name,
        "suffix": path.suffix or "(none)",
        "size_bytes": stat.st_size,
        "modified_timestamp": stat.st_mtime,
    }
