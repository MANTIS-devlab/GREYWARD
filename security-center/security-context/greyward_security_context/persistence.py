"""Bounded, user-scoped startup/persistence inspection.

This module intentionally knows a small allow-list of user startup surfaces. It
does not walk a user's home directory or inspect running processes.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

MAX_FILES = 128
MAX_FILE_BYTES = 256 * 1024
MAX_EVENTS = 32
SCHEMA = "greyward.security.persistence/v1"


@dataclass(frozen=True)
class Surface:
    category: str
    relative_paths: tuple[str, ...]
    suffixes: tuple[str, ...] = ()
    recursive: bool = False


SURFACES = (
    Surface("XDG autostart", (".config/autostart",), (".desktop",), True),
    Surface("User systemd", (".config/systemd/user",), (".service", ".timer"), True),
    Surface("Shell startup", (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile")),
    Surface(
        "Browser native messaging",
        (
            ".config/chromium/NativeMessagingHosts",
            ".config/google-chrome/NativeMessagingHosts",
            ".config/microsoft-edge/NativeMessagingHosts",
            ".mozilla/native-messaging-hosts",
        ),
        (".json",),
        True,
    ),
    Surface("Background agents", (".config/environment.d",), (".conf",), True),
)


def _safe_path(home: Path, relative: str) -> Path:
    candidate = (home / relative).resolve()
    if candidate == home.resolve() or home.resolve() not in candidate.parents:
        raise ValueError("persistence path escaped home")
    return candidate


def _fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            remaining = MAX_FILE_BYTES
            while remaining:
                chunk = stream.read(min(8192, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
    except (OSError, ValueError):
        return "unreadable"
    return digest.hexdigest()[:24]


def _files_for_surface(home: Path, surface: Surface) -> Iterable[Path]:
    for relative in surface.relative_paths:
        root = _safe_path(home, relative)
        if root.is_file():
            yield root
            continue
        if not root.is_dir():
            continue
        iterator = root.rglob("*") if surface.recursive else root.iterdir()
        for candidate in sorted(iterator, key=lambda item: item.as_posix()):
            if candidate.is_file() and (not surface.suffixes or candidate.suffix in surface.suffixes):
                yield candidate


def _logical_id(home: Path, path: Path) -> str:
    # The relative logical identifier is bounded and contains no home path.
    return path.relative_to(home).as_posix()[:160]


def snapshot(home: Path | str, *, max_files: int = MAX_FILES) -> dict:
    """Return a deterministic, redacted snapshot of approved surfaces."""
    home = Path(home).expanduser().resolve()
    entries: list[dict] = []
    seen: set[str] = set()
    for surface in SURFACES:
        for path in _files_for_surface(home, surface):
            logical_id = _logical_id(home, path)
            if logical_id in seen:
                continue
            seen.add(logical_id)
            entries.append({
                "category": surface.category,
                "id": logical_id,
                "fingerprint": _fingerprint(path),
            })
            if len(entries) >= max_files:
                break
        if len(entries) >= max_files:
            break
    entries.sort(key=lambda item: (item["category"], item["id"]))
    return {"schema": SCHEMA, "entries": entries}


def _index(value: Mapping) -> dict[tuple[str, str], dict]:
    result = {}
    for item in value.get("entries", []):
        if not isinstance(item, dict):
            continue
        category, item_id = item.get("category"), item.get("id")
        if isinstance(category, str) and isinstance(item_id, str):
            result[(category, item_id)] = {
                "category": category,
                "id": item_id[:160],
                "fingerprint": str(item.get("fingerprint", ""))[:24],
            }
    return result


def diff(previous: Mapping, current: Mapping, *, max_events: int = MAX_EVENTS) -> list[dict]:
    """Return only meaningful additions, removals, and content changes."""
    before, after = _index(previous), _index(current)
    changes = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old is None:
            change = "added"
        elif new is None:
            change = "removed"
        elif old["fingerprint"] != new["fingerprint"]:
            change = "changed"
        else:
            continue
        category = (new or old)["category"]
        title = {
            "XDG autostart": "Application configured to start automatically",
            "User systemd": "User background service or timer changed",
            "Shell startup": "Shell startup configuration changed",
            "Browser native messaging": "Browser integration changed",
            "Background agents": "Background agent configuration changed",
        }.get(category, "Persistence configuration changed")
        changes.append({
            "kind": "PERSISTENCE_CHANGE_DETECTED",
            "category": category,
            "change": change,
            "title": title,
            "detail": f"{title}: {change}.",
            "id": (new or old)["id"],
        })
    return changes[:max_events]


class PersistenceMonitor:
    """Persist one bounded baseline and emit a change only once per update."""

    def __init__(self, home: Path | str | None = None, state_path: Path | str | None = None):
        self.home = Path(home or os.environ.get("HOME", "~")).expanduser().resolve()
        self.state_path = Path(state_path or (Path(os.environ.get("XDG_STATE_HOME", self.home / ".local/state")) / "greyward-security-context" / "persistence-baseline.json"))

    def _load(self) -> dict | None:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def scan(self) -> list[dict]:
        current = snapshot(self.home)
        previous = self._load()
        changes = [] if previous is None else diff(previous, current)
        observed_at = time.time()
        recent = [entry for entry in (previous or {}).get('recent_changes', []) if 0 <= observed_at - entry.get('observed_at', 0) < 300]
        recent.extend({**change, 'observed_at': observed_at} for change in changes)
        current['recent_changes'] = recent[-MAX_EVENTS:]
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".new")
        temporary.write_text(json.dumps(current, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, self.state_path)
        return changes

    def recent_changes(self) -> list[dict]:
        """Bounded observations, not unresolved findings or a second monitor."""
        current = time.time()
        return [entry for entry in (self._load() or {}).get('recent_changes', []) if 0 <= current - entry.get('observed_at', 0) < 300][-MAX_EVENTS:]
