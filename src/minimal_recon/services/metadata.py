"""Local file metadata extraction."""

from pathlib import Path
from typing import Any, Dict

from PIL import ExifTags, Image


def extract_metadata(path: Path) -> Dict[str, Any]:
    """Return filesystem and readable image metadata for a local file."""
    stat = path.stat()
    metadata: Dict[str, Any] = {
        "name": path.name,
        "suffix": path.suffix or "(none)",
        "size_bytes": stat.st_size,
        "modified_timestamp": stat.st_mtime,
    }
    if not _is_image(path):
        return metadata

    with Image.open(path) as image:
        metadata.update(
            {
                "image_format": image.format,
                "width": image.width,
                "height": image.height,
            }
        )
        exif = image.getexif()
        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if isinstance(value, (str, int, float, bool)):
                metadata[f"exif_{tag_name}"] = value
    return metadata


def _is_image(path: Path) -> bool:
    """Check the file signature through Pillow without trusting the suffix."""
    try:
        with Image.open(path) as image:
            image.verify()
    except (OSError, SyntaxError):
        return False
    return True
