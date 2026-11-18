"""Local history of footprint runs and domain reports, stored as JSON files.

Entries live only on this computer, in the user's data folder:
``%LOCALAPPDATA%\\minimal-recon\\history`` on Windows and
``~/.local/share/minimal-recon/history`` elsewhere. ``MINIMAL_RECON_HOME``
overrides the base folder.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import secrets
import threading
from typing import Any, Dict, List, Optional

from minimal_recon.services.diff import diff_reports

KINDS = ("footprint", "report")
_ID_PATTERN = re.compile(r"\d{8}T\d{6}\d{6}Z-(footprint|report)-[0-9a-f]{6}")
TLS_WARNING_DAYS = 30


@dataclass(frozen=True)
class HistoryEntry:
    id: str
    kind: str
    target: str
    created_at: str
    summary: Dict[str, Any] = field(default_factory=dict)


def history_dir() -> Path:
    override = os.environ.get("MINIMAL_RECON_HOME")
    if override:
        base = Path(override)
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "minimal-recon"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "minimal-recon"
    return base / "history"


def save(kind: str, target: str, data: Any, summary: Optional[Dict[str, Any]] = None) -> HistoryEntry:
    """Store one run and return its entry."""
    if kind not in KINDS:
        raise ValueError(f"history kind must be one of: {', '.join(KINDS)}")
    now = _next_timestamp()
    entry = HistoryEntry(
        id=f"{now.strftime('%Y%m%dT%H%M%S%f')}Z-{kind}-{secrets.token_hex(3)}",
        kind=kind,
        target=target.strip().lower(),
        created_at=now.isoformat(),
        summary=summary or {},
    )
    folder = history_dir()
    folder.mkdir(parents=True, exist_ok=True)
    temporary = folder / f".{entry.id}.tmp"
    temporary.write_text(json.dumps({"entry": asdict(entry), "data": data}, default=str), encoding="utf-8")
    temporary.replace(folder / f"{entry.id}.json")
    return entry


def list_entries(kind: Optional[str] = None, target: Optional[str] = None) -> List[HistoryEntry]:
    """Return saved entries, newest first, optionally filtered."""
    folder = history_dir()
    if not folder.is_dir():
        return []
    wanted_target = target.strip().lower() if target else None
    entries = []
    for path in folder.glob("*.json"):
        if not _ID_PATTERN.fullmatch(path.stem):
            continue
        try:
            entry = HistoryEntry(**json.loads(path.read_text(encoding="utf-8"))["entry"])
        except (OSError, ValueError, KeyError, TypeError):
            continue  # skip files that were edited or damaged by hand
        if kind and entry.kind != kind:
            continue
        if wanted_target and wanted_target not in entry.target:
            continue
        entries.append(entry)
    return sorted(entries, key=lambda item: item.id, reverse=True)


def load(entry_id: str) -> Dict[str, Any]:
    """Return ``{"entry": HistoryEntry, "data": ...}`` for one saved run."""
    path = _path(entry_id)
    if not path.is_file():
        raise ValueError(f"history entry {entry_id} does not exist")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
        return {"entry": HistoryEntry(**stored["entry"]), "data": stored["data"]}
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"history entry {entry_id} is damaged") from error


def previous(entry: HistoryEntry) -> Optional[HistoryEntry]:
    """The most recent earlier entry of the same kind and target."""
    for candidate in list_entries(entry.kind):
        if candidate.target == entry.target and candidate.id < entry.id:
            return candidate
    return None


def compare(old_id: str, new_id: str) -> Dict[str, Any]:
    """Differences between two saved runs of the same kind."""
    old, new = load(old_id), load(new_id)
    if old["entry"].kind != new["entry"].kind:
        raise ValueError("only runs of the same kind can be compared")
    changes = diff_reports(_comparable(old["data"]), _comparable(new["data"]))
    return {
        "old": asdict(old["entry"]),
        "new": asdict(new["entry"]),
        "changes": [asdict(change) for change in changes],
        "alerts": alerts(changes, new["data"]) if new["entry"].kind == "report" else [],
    }


def delete(entry_id: str) -> bool:
    path = _path(entry_id)
    if not path.is_file():
        return False
    path.unlink()
    return True


def clear() -> int:
    """Delete every saved entry and return how many were removed."""
    removed = 0
    for entry in list_entries():
        removed += delete(entry.id)
    return removed


def summarize_footprint(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    found = [result["site"] for result in results if result.get("found")]
    return {"found": len(found), "checked": len(results), "found_sites": found}


def summarize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    errors = sorted(
        name for name, value in report.items() if isinstance(value, dict) and value.get("status") == "error"
    )
    summary: Dict[str, Any] = {"errors": errors}
    subdomains = report.get("subdomains")
    if isinstance(subdomains, dict) and isinstance(subdomains.get("subdomains"), list):
        summary["subdomains"] = len(subdomains["subdomains"])
    tls = report.get("tls")
    if isinstance(tls, dict) and "days_until_expiry" in tls:
        summary["tls_days"] = tls.get("days_until_expiry")
    return summary


def alerts(changes: List[Any], report: Dict[str, Any]) -> List[str]:
    """Short warnings worth acting on, from a report and its changes since the last run."""
    messages: List[str] = []
    tls = report.get("tls")
    if isinstance(tls, dict) and "status" not in tls:
        days = tls.get("days_until_expiry")
        if isinstance(days, int) and days < 0:
            messages.append(f"TLS certificate expired {-days} day(s) ago")
        elif isinstance(days, int) and days < TLS_WARNING_DAYS:
            messages.append(f"TLS certificate expires in {days} day(s)")
        if tls.get("verified") is False:
            messages.append(f"TLS certificate is not valid: {tls.get('verification_error')}")
    for change in changes:
        path, kind = _field(change, "path"), _field(change, "change")
        if path == "subdomains.subdomains" and kind == "added":
            messages.append(f"New subdomain: {_field(change, 'new')}")
        elif path.startswith("dns.records.") and kind in ("added", "removed"):
            value = _field(change, "new") if kind == "added" else _field(change, "old")
            messages.append(f"DNS {path.rsplit('.', 1)[-1]} record {kind}: {value}")
        elif path == "anti_spoofing.findings" and kind == "added":
            messages.append(f"New email-spoofing finding: {_field(change, 'new')}")
        elif path == "web.missing_security_headers" and kind == "added":
            messages.append(f"Security header no longer sent: {_field(change, 'new')}")
        elif path == "whois.registrar" and kind == "changed":
            messages.append(f"Registrar changed: {_field(change, 'old')} -> {_field(change, 'new')}")
    return messages


_clock_lock = threading.Lock()
_last_timestamp = datetime.min.replace(tzinfo=timezone.utc)


def _next_timestamp() -> datetime:
    """Current UTC time, strictly later than the previous call.

    The Windows clock can return the same value for saves made a few
    milliseconds apart; entry ids sort by this time, so they must not tie.
    """
    global _last_timestamp
    with _clock_lock:
        now = datetime.now(timezone.utc)
        if now <= _last_timestamp:
            now = _last_timestamp + timedelta(microseconds=1)
        _last_timestamp = now
        return now


def _comparable(data: Any) -> Dict[str, Any]:
    return data if isinstance(data, dict) else {"items": data}


def _field(change: Any, name: str) -> Any:
    return change.get(name) if isinstance(change, dict) else getattr(change, name)


def _path(entry_id: str) -> Path:
    if not _ID_PATTERN.fullmatch(entry_id):
        raise ValueError("invalid history entry id")
    return history_dir() / f"{entry_id}.json"
