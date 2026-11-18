"""Offline comparison of two saved Minimal Recon JSON reports."""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

# Values that differ on every run and say nothing about the target.
IGNORED_KEYS = frozenset({"generated_at", "checked_at"})

# Fields that identify one entry in a list of records, in order of preference,
# so entries are matched by identity instead of by position.
IDENTITY_KEYS = ("site", "path", "ip", "original_url", "url")


@dataclass(frozen=True)
class Change:
    path: str
    change: str  # "added", "removed" or "changed"
    old: Any = None
    new: Any = None


def load_report(path: Path) -> Dict[str, Any]:
    """Read a JSON report written by ``recon report --output``."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise ValueError(f"{path} is not valid JSON") from error
    if not isinstance(report, dict) or "target" not in report:
        raise ValueError(f"{path} is not a Minimal Recon report")
    return report


def diff_reports(old: Dict[str, Any], new: Dict[str, Any]) -> List[Change]:
    """Return every difference between two reports, ordered by section path."""
    changes: List[Change] = []
    _walk("", old, new, changes)
    return changes


def _walk(path: str, old: Any, new: Any, changes: List[Change]) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            if key in IGNORED_KEYS:
                continue
            child = f"{path}.{key}" if path else str(key)
            if key not in old:
                changes.append(Change(child, "added", new=new[key]))
            elif key not in new:
                changes.append(Change(child, "removed", old=old[key]))
            else:
                _walk(child, old[key], new[key], changes)
        return

    if isinstance(old, list) and isinstance(new, list):
        identity = _identity_key(old + new)
        if identity:
            _walk(
                path,
                {str(item[identity]): item for item in old},
                {str(item[identity]): item for item in new},
                changes,
            )
            return
        old_items = {_canonical(item): item for item in old}
        new_items = {_canonical(item): item for item in new}
        for key in sorted(set(new_items) - set(old_items)):
            changes.append(Change(path, "added", new=new_items[key]))
        for key in sorted(set(old_items) - set(new_items)):
            changes.append(Change(path, "removed", old=old_items[key]))
        return

    if old != new:
        changes.append(Change(path, "changed", old, new))


def _identity_key(items: List[Any]) -> Optional[str]:
    """Find a field present in every record that can be used to pair records."""
    if not items or not all(isinstance(item, dict) for item in items):
        return None
    for key in IDENTITY_KEYS:
        if all(key in item for item in items):
            return key
    return None


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)
