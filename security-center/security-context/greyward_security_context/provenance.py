"""Bounded file provenance and metadata-sanitized copy operations.

This module reports only evidence that GREYWARD can derive locally.  It never
turns a missing signal into a trust decision and never overwrites the source.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

from .safe_open import SafeOpenError, validate_path

MAX_DETAIL = 240
TEXT_TYPES = {".txt", ".csv", ".log", ".md", ".markdown", ".json", ".xml"}
IMAGE_TYPES = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff"}


def _file_ref(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()[:16]


def _source(events, ref: str) -> dict:
    for event in events:
        if not isinstance(event, dict) or event.get("file_ref") != ref:
            continue
        url = event.get("download_url") or event.get("origin_url")
        application = event.get("application") or event.get("creator") or event.get("downloaded_by")
        mechanism = event.get("transfer_mechanism") or event.get("mechanism")
        if isinstance(url, str) and url.startswith(("https://", "http://")):
            detail = f"Downloaded from: {url[:MAX_DETAIL]}"
            if isinstance(application, str) and application:
                detail += f" · by {application[:80]}"
            return {"state": "KNOWN", "detail": detail[:MAX_DETAIL]}
        if isinstance(application, str) and application:
            return {"state": "KNOWN", "detail": f"Created or received by: {application[:120]}"}
        if isinstance(mechanism, str) and mechanism:
            return {"state": "KNOWN", "detail": f"Received through: {mechanism[:120]}"}
    return {"state": "UNKNOWN", "detail": "GREYWARD has no captured origin evidence for this file."}


def _firefox_evidence(path: Path) -> dict:
    """Read Firefox's existing download annotation for this exact file."""
    roots = (Path.home() / ".config/mozilla/firefox", Path.home() / ".mozilla/firefox")
    destination = path.as_uri()
    for root in roots:
        for database in root.glob("*/places.sqlite"):
            try:
                with tempfile.TemporaryDirectory(prefix="greyward-firefox-") as snapshot_dir:
                    snapshot = Path(snapshot_dir) / "places.sqlite"
                    shutil.copy2(database, snapshot)
                    for suffix in ("-wal", "-shm"):
                        sidecar = database.with_name(database.name + suffix)
                        if sidecar.is_file():
                            shutil.copy2(sidecar, snapshot.with_name(snapshot.name + suffix))
                    connection = sqlite3.connect(snapshot, timeout=1)
                    rows = connection.execute(
                        "SELECT p.url, a.name, z.content, z.dateAdded "
                        "FROM moz_annos z "
                        "JOIN moz_anno_attributes a ON a.id = z.anno_attribute_id "
                        "JOIN moz_places p ON p.id = z.place_id "
                        "WHERE a.name IN ('downloads/destinationFileURI', 'downloads/metaData')"
                    ).fetchall()
                    connection.close()
            except (OSError, sqlite3.Error):
                continue
            by_url = {}
            for url, name, content, date_added in rows:
                by_url.setdefault(url, {})[name] = (content, date_added)
            for url, annotations in by_url.items():
                destination_entry = annotations.get("downloads/destinationFileURI")
                if not destination_entry:
                    continue
                parsed = urlparse(str(destination_entry[0]))
                if parsed.scheme != "file":
                    continue
                try:
                    downloaded_path = Path(unquote(parsed.path)).resolve()
                except (OSError, RuntimeError):
                    continue
                if downloaded_path != path:
                    continue
                timestamp = destination_entry[1]
                metadata = annotations.get("downloads/metaData")
                if metadata:
                    try:
                        timestamp = int(json.loads(metadata[0]).get("endTime", timestamp * 1000))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass
                try:
                    numeric = float(timestamp)
                    seconds = numeric / (1000000 if numeric > 100000000000000 else 1000)
                    occurred_at = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                except (TypeError, ValueError, OSError, OverflowError):
                    occurred_at = ""
                source_url = str(url) if str(url).startswith(("https://", "http://")) else ""
                source_detail = f"Downloaded from: {source_url[:MAX_DETAIL]}" if source_url else "Downloaded by Firefox."
                return {
                    "source": {"state": "KNOWN", "detail": source_detail},
                    "source_url": {"state": "KNOWN", "detail": source_url} if source_url else {"state": "UNKNOWN", "detail": "No source URL was recorded."},
                    "downloaded_by": {"state": "KNOWN", "detail": "Firefox"},
                    "occurred_at": occurred_at,
                }
    return {}


def _observed(events, ref: str) -> list[dict]:
    return [event for event in events if isinstance(event, dict) and event.get("file_ref") == ref]
def _signature(path: Path) -> dict:
    signature = next((path.with_name(path.name + suffix) for suffix in (".asc", ".sig") if path.with_name(path.name + suffix).is_file()), None)
    if signature is None:
        return {"state": "UNKNOWN", "detail": "No detached signature was found."}
    gpgv = shutil.which("gpgv")
    if not gpgv:
        return {"state": "UNAVAILABLE", "detail": "A detached signature exists, but signature verification is unavailable."}
    result = subprocess.run([gpgv, "--status-fd", "1", str(signature), str(path)], capture_output=True, text=True, timeout=10, check=False)
    valid = result.returncode == 0 and any(line.startswith("[GNUPG:] VALIDSIG ") for line in result.stdout.splitlines())
    if valid:
        return {"state": "VALID", "detail": "Detached signature verification succeeded with the available trust database."}
    return {"state": "INVALID", "detail": "Detached signature verification failed or its signer is not trusted."}


def provenance(raw_path: str, events=(), roots=None) -> dict:
    path = validate_path(raw_path, roots)
    ref = _file_ref(path)
    file_events = _observed(events, ref)
    firefox = _firefox_evidence(path)
    scans = [{"state": str(event.get("state", "UNKNOWN")), "detail": str(event.get("detail", ""))[:MAX_DETAIL], "occurred_at": str(event.get("occurred_at", ""))}
             for event in file_events if event.get("kind") == "USB_SCAN_RESULT"]
    safe_open = [{"state": "OBSERVED", "detail": "Safe Open context was used for this file.", "occurred_at": str(event.get("occurred_at", ""))}
                 for event in file_events if event.get("kind") == "SAFE_OPEN_RESULT"]
    sanitization = [{"state": str(event.get("state", "UNKNOWN")), "detail": str(event.get("detail", ""))[:MAX_DETAIL], "occurred_at": str(event.get("occurred_at", ""))}
                    for event in file_events if event.get("kind") == "SANITIZATION_RESULT"]
    first = str(file_events[0].get("occurred_at", "")) if file_events else firefox.get("occurred_at", "")
    last = str(file_events[-1].get("occurred_at", "")) if file_events else firefox.get("occurred_at", "")
    observed_unknown = {"state": "UNKNOWN", "detail": "Before GREYWARD monitoring or no file event has been observed."}
    unknown_source = {"state": "UNKNOWN", "detail": "Unknown origin."}
    return {
        "schema": "greyward.security.provenance/v1",
        "file_name": path.name[:160],
        "file_ref": ref,
        "source": firefox.get("source", _source(events, ref)),
        "source_url": firefox.get("source_url", unknown_source),
        "downloaded_by": firefox.get("downloaded_by", unknown_source),
        "first_observed": {"state": "KNOWN", "occurred_at": first} if first else observed_unknown,
        "last_observed": {"state": "KNOWN", "occurred_at": last} if last else observed_unknown,
        "scan": scans[-4:] or [{"state": "UNKNOWN", "detail": "This file has not been scanned by GREYWARD."}],
        "signature": _signature(path),
        "safe_open": safe_open[-4:] or [{"state": "UNKNOWN", "detail": "This file has never been opened with Safe Open."}],
        "sanitization": sanitization[-4:] or [{"state": "UNKNOWN", "detail": "No sanitized copy has been created."}],
        "trust": "UNKNOWN",
        "limitation": "Provenance is context, not proof that this file is safe.",
    }
def _output_path(path: Path) -> Path:
    base = path.with_name(f"{path.stem} (sanitized){path.suffix}")
    for index in range(100):
        candidate = base if index == 0 else path.with_name(f"{path.stem} (sanitized {index + 1}){path.suffix}")
        if not candidate.exists():
            return candidate
    raise SafeOpenError("A bounded sanitized-copy name could not be allocated.")


def sanitize_copy(raw_path: str, roots=None) -> dict:
    path = validate_path(raw_path, roots)
    destination = _output_path(path)
    suffix = path.suffix.lower()
    if suffix in TEXT_TYPES:
        shutil.copyfile(path, destination)
        method = "plain-text copy; no embedded metadata format is defined"
    elif suffix in IMAGE_TYPES:
        try:
            from PIL import Image
        except ImportError as error:
            raise SafeOpenError("Image metadata sanitization is unavailable; no copy was created.") from error
        try:
            with Image.open(path) as image:
                pixels = list(image.getdata()) if image.mode not in {"1", "L", "P", "RGB", "RGBA"} else None
                clean = Image.new(image.mode, image.size)
                if pixels is not None:
                    clean.putdata(pixels)
                else:
                    clean.putdata(list(image.getdata()))
                save_kwargs = {"format": image.format} if image.format else {}
                clean.save(destination, **save_kwargs)
        except Exception as error:
            destination.unlink(missing_ok=True)
            raise SafeOpenError("Image metadata sanitization failed; no copy was created.") from error
        method = "image rewritten without source metadata"
    elif suffix == ".pdf" and shutil.which("exiftool"):
        result = subprocess.run([shutil.which("exiftool"), "-all=", "-o", str(destination), str(path)], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0 or not destination.is_file():
            destination.unlink(missing_ok=True)
            raise SafeOpenError("PDF metadata sanitization failed; no copy was created.")
        method = "PDF metadata removed by exiftool"
    else:
        raise SafeOpenError("This file type is unsupported by the GREYWARD metadata sanitizer; the original was unchanged.")
    return {"ok": True, "state": "SANITIZED", "source_name": path.name[:160], "output": str(destination), "method": method[:MAX_DETAIL], "original_unchanged": True}





