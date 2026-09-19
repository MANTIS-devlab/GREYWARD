"""GREYWARD-owned Feodo recommended-feed snapshot handling.

The module deliberately owns only feed retrieval, validation, normalization,
and bounded status reporting. OpenSnitch remains the enforcement engine.
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
FEODO_PROVIDER = "feodo-recommended"
SNAPSHOT_SCHEMA = "greyward.feodo/v1"
SNAPSHOT_PATH = Path("/var/lib/greyward/opensnitch/feodo-snapshot.json")
MAX_FEED_BYTES = 4 * 1024 * 1024
MAX_INDICATORS = 4096
FETCH_TIMEOUT_SECONDS = 20


def _clean(value: Any, maximum: int = 160) -> str:
    return "".join(character for character in str(value or "") if character.isprintable())[:maximum]


def _atomic_json(path: Path, value: dict[str, Any], mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".feodo-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def default_snapshot() -> dict[str, Any]:
    return {
        "schema": SNAPSHOT_SCHEMA,
        "provider": FEODO_PROVIDER,
        "state": "INITIALIZING",
        "fetched_at": None,
        "last_successful_update": None,
        "indicator_count": 0,
        "indicators": [],
        "error": "The first Feodo snapshot has not been received yet.",
    }


def load_snapshot() -> dict[str, Any]:
    try:
        value = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_snapshot()
    if not isinstance(value, dict) or value.get("schema") != SNAPSHOT_SCHEMA:
        return default_snapshot()
    indicators = value.get("indicators")
    if not isinstance(indicators, list):
        return default_snapshot()
    normalized = []
    for item in indicators[:MAX_INDICATORS]:
        if not isinstance(item, dict):
            continue
        try:
            address = str(ipaddress.ip_address(str(item.get("ip") or "")))
            port = int(item.get("port"))
        except (ValueError, TypeError):
            continue
        if not 1 <= port <= 65535:
            continue
        normalized.append({
            "ip": address,
            "port": port,
            "malware": _clean(item.get("malware"), 96) or None,
        })
    value["indicators"] = normalized
    value["indicator_count"] = len(normalized)
    value["provider"] = FEODO_PROVIDER
    value["state"] = str(value.get("state") or "ERROR").upper()
    if value["state"] not in {"READY", "EMPTY", "STALE", "ERROR", "INITIALIZING"}:
        value["state"] = "ERROR"
    return value


def _normalize_entry(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    try:
        address = str(ipaddress.ip_address(str(item.get("ip_address") or "")))
        port = int(item.get("port"))
    except (ValueError, TypeError):
        return None
    if not 1 <= port <= 65535:
        return None
    return {
        "ip": address,
        "port": port,
        "malware": _clean(item.get("malware"), 96) or None,
    }


def normalize_feed(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("The Feodo response must be a JSON array.")
    indicators: dict[tuple[str, int], dict[str, Any]] = {}
    for item in payload:
        normalized = _normalize_entry(item)
        if normalized is None:
            raise ValueError("The Feodo response contains an invalid IP or port.")
        key = (normalized["ip"], normalized["port"])
        indicators.setdefault(key, normalized)
        if len(indicators) > MAX_INDICATORS:
            raise ValueError("The Feodo response exceeds the indicator limit.")
    return list(indicators.values())


def fetch_feed() -> bytes:
    request = urllib.request.Request(
        FEODO_URL,
        headers={"Accept": "application/json", "User-Agent": "GREYWARD-Feodo-Updater/1"},
    )
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        data = response.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("The Feodo response is larger than the safety limit.")
    return data


def update_feed(fetcher=fetch_feed, path: Path = SNAPSHOT_PATH) -> dict[str, Any]:
    current = load_snapshot() if path == SNAPSHOT_PATH else _load_snapshot_from(path)
    try:
        raw = fetcher()
        if len(raw) > MAX_FEED_BYTES:
            raise ValueError("The Feodo response is larger than the safety limit.")
        payload = json.loads(raw.decode("utf-8"))
        indicators = normalize_feed(payload)
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        updated = {
            "schema": SNAPSHOT_SCHEMA,
            "provider": FEODO_PROVIDER,
            "state": "READY" if indicators else "EMPTY",
            "fetched_at": timestamp,
            "last_successful_update": timestamp,
            "indicator_count": len(indicators),
            "indicators": indicators,
            "error": None,
        }
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OSError, urllib.error.URLError) as error:
        updated = dict(current)
        updated["state"] = "STALE" if current.get("last_successful_update") else "ERROR"
        updated["error"] = _clean(error, 240) or "The Feodo update failed."
    _atomic_json(path, updated)
    return updated


def _load_snapshot_from(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_snapshot()
    if not isinstance(value, dict):
        return default_snapshot()
    return value


def matching_indicator(connection: Any, snapshot: dict[str, Any] | None = None) -> dict[str, Any] | None:
    address = str(getattr(connection, "dst_ip", "") or "")
    try:
        address = str(ipaddress.ip_address(address))
        port = int(getattr(connection, "dst_port", 0) or 0)
    except (ValueError, TypeError):
        return None
    source = snapshot or load_snapshot()
    for indicator in source.get("indicators", []):
        if indicator.get("ip") == address and int(indicator.get("port", 0) or 0) == port:
            return dict(indicator)
    return None


def threat_status(policy: dict[str, Any], activity: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    snapshot = load_snapshot()
    config = policy.get("threat_intel") if isinstance(policy, dict) else None
    enabled = bool(config.get("enabled", True)) if isinstance(config, dict) else True
    blocked = [
        item for item in (activity or [])
        if isinstance(item, dict)
        and item.get("decision") == "BLOCKED"
        and isinstance(item.get("threat"), dict)
    ]
    return {
        "enabled": enabled,
        "provider": FEODO_PROVIDER,
        "state": "DISABLED" if not enabled else snapshot.get("state", "ERROR"),
        "last_successful_update": snapshot.get("last_successful_update"),
        "indicator_count": int(snapshot.get("indicator_count", 0) or 0),
        "last_error": snapshot.get("error"),
        "recent_blocked_connections": blocked[-64:][::-1],
    }
