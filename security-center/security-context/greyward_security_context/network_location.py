"""Privacy-preserving local endpoint-country resolution.

The resolver never performs a network lookup. It combines independently
installed local sources when available and always makes a deterministic
choice when sources disagree. The confidence metadata lets the UI show the
country without presenting an unresolved disagreement as certainty.
"""

from __future__ import annotations

import csv
import ipaddress
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path


_DATABASE_CANDIDATES = (
    Path("/var/lib/GeoIP/GeoLite2-Country.mmdb"),
    Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
    Path("/usr/share/GeoIP/GeoIP2-Country.mmdb"),
)
_SECONDARY_DATABASE_CANDIDATES = (
    Path("/var/lib/GeoIP/GeoIP2-Country.mmdb"),
    Path("/usr/share/GeoIP/GeoIP2-Country.mmdb"),
)
_GEOFEED_CANDIDATES = (
    Path("/var/lib/greyward/security-context/geofeed.csv"),
    Path("/usr/share/greyward/security-context/geofeed.csv"),
)
_LEGACY_DATABASE_CANDIDATES = (
    Path("/usr/share/GeoIP/GeoIP.dat"),
    Path("/usr/share/GeoIP/GeoIPCountry.dat"),
)
_COUNTRY_RE = re.compile(r'"([A-Z]{2})"')
_LEGACY_COUNTRY_RE = re.compile(r"(?:Country Edition|country):\s*([A-Z]{2})\b", re.IGNORECASE)
_COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
_CC_TLD_COUNTRIES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())


def _configured_path(variable: str) -> Path | None:
    value = os.environ.get(variable, "").strip()
    return Path(value) if value else None


def _database_path() -> Path | None:
    configured = _configured_path("GREYWARD_GEOIP_DB")
    candidates = (configured,) if configured else _DATABASE_CANDIDATES
    return next((path for path in candidates if path and path.is_file()), None)


def _secondary_database_path(primary: Path | None) -> Path | None:
    configured = _configured_path("GREYWARD_GEOIP_DB_SECONDARY")
    candidates = (configured,) if configured else _SECONDARY_DATABASE_CANDIDATES
    primary_resolved = primary.resolve() if primary else None
    return next((path for path in candidates if path and path.is_file() and path.resolve() != primary_resolved), None)


def _geofeed_path() -> Path | None:
    configured = _configured_path("GREYWARD_GEOFEED_DB")
    candidates = (configured,) if configured else _GEOFEED_CANDIDATES
    return next((path for path in candidates if path and path.is_file()), None)


def _legacy_database_path() -> Path | None:
    configured = _configured_path("GREYWARD_GEOIP_LEGACY_DB")
    candidates = (configured,) if configured else _LEGACY_DATABASE_CANDIDATES
    return next((path for path in candidates if path and path.is_file()), None)


def _public_address(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _country_code(value: object) -> str:
    candidate = str(value or "").strip().upper()
    return candidate if _COUNTRY_CODE_RE.fullmatch(candidate) else ""


def country_hint_for_host(value: str | None) -> str:
    """Return a deliberately weak country hint from a hostname ccTLD.

    This is only a last-resort presentation hint. It never overrides an IP
    source because a domain namespace does not prove where its server lives.
    """

    host = str(value or "").strip().rstrip(".").lower()
    if not host or "://" in host:
        return ""
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    else:
        try:
            ipaddress.ip_address(host)
            return ""
        except ValueError:
            pass
    labels = host.split(".")
    suffix = labels[-1] if labels else ""
    # The United Kingdom uses .uk while its ISO alpha-2 code is GB.
    if suffix == "uk":
        return "GB"
    return suffix.upper() if suffix.upper() in _CC_TLD_COUNTRIES else ""


def _country_from_mmdb(address: str, database: Path | None) -> str:
    if database is None:
        return ""
    try:
        result = subprocess.run(
            ["mmdblookup", "--file", str(database), "--ip", address, "country", "iso_code"],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    match = _COUNTRY_RE.search(result.stdout or "")
    return _country_code(match.group(1) if match else "")


def _country_from_legacy_geoip(address: str, database: Path | None) -> str:
    """Read the packaged, local GeoIP Country database through geoiplookup."""

    if database is None:
        return ""
    try:
        result = subprocess.run(
            ["geoiplookup", "-f", str(database), address],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    match = _LEGACY_COUNTRY_RE.search(result.stdout or "")
    return _country_code(match.group(1) if match else "")


@lru_cache(maxsize=16)
def _geofeed_entries(path_value: str, modified_ns: int, size: int) -> tuple[tuple[object, str], ...]:
    """Read RFC 8805-style prefix,country rows from a local file only."""

    del modified_ns, size  # Cache invalidation is provided by the cache key.
    entries: list[tuple[object, str]] = []
    try:
        with Path(path_value).open("r", encoding="utf-8", errors="replace", newline="") as stream:
            for row in csv.reader(stream):
                if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                    continue
                try:
                    network = ipaddress.ip_network(row[0].strip(), strict=False)
                except ValueError:
                    continue
                country = _country_code(row[1] if len(row) > 1 else "")
                if country:
                    entries.append((network, country))
    except OSError:
        return ()
    return tuple(sorted(entries, key=lambda item: (-item[0].prefixlen, str(item[0]), item[1])))


def _country_from_geofeed(address: str, path: Path | None) -> str:
    if path is None:
        return ""
    try:
        stat = path.stat()
    except OSError:
        return ""
    for network, country in _geofeed_entries(str(path), stat.st_mtime_ns, stat.st_size):
        if ipaddress.ip_address(address) in network:
            return country
    return ""


def _resolution_uncached(value: str | None) -> dict[str, object]:
    address = _public_address(str(value or "").strip())
    if not address:
        return {"country_code": "", "confidence": "NONE", "converged": False, "source_count": 0}

    primary = _database_path()
    secondary = _secondary_database_path(primary)
    sources = (
        ("geoip", _country_from_mmdb(address, primary), 4),
        ("geoip-secondary", _country_from_mmdb(address, secondary), 3),
        ("geoip-legacy", _country_from_legacy_geoip(address, _legacy_database_path()), 2),
        ("geofeed", _country_from_geofeed(address, _geofeed_path()), 1),
    )
    votes = [(name, country, weight) for name, country, weight in sources if country]
    if not votes:
        return {"country_code": "", "confidence": "NONE", "converged": False, "source_count": 0}

    totals: dict[str, int] = {}
    counts: dict[str, int] = {}
    for _, country, weight in votes:
        totals[country] = totals.get(country, 0) + weight
        counts[country] = counts.get(country, 0) + 1
    selected = min(totals, key=lambda country: (-totals[country], -counts[country], country))
    converged = len(totals) == 1
    confidence = "HIGH" if converged and len(votes) >= 2 else "MEDIUM" if converged else "LOW"
    return {"country_code": selected, "confidence": confidence, "converged": converged, "source_count": len(votes)}


@lru_cache(maxsize=4096)
def country_resolution_for_destination(ip: str | None, host: str | None) -> dict[str, object]:
    """Resolve an endpoint locally, using a labelled ccTLD hint only last."""

    resolution = dict(country_resolution_for_ip(ip))
    if resolution["country_code"]:
        resolution["source"] = "LOCAL"
        return resolution
    hint = country_hint_for_host(host)
    if hint:
        return {
            "country_code": hint,
            "confidence": "VERY_LOW",
            "converged": False,
            "source_count": 0,
            "source": "DOMAIN_SUFFIX",
        }
    resolution["source"] = "NONE"
    return resolution


@lru_cache(maxsize=4096)
def country_resolution_for_ip(value: str | None) -> dict[str, object]:
    """Return a local resolution, retaining a deterministic country on conflict."""

    return _resolution_uncached(value)


@lru_cache(maxsize=4096)
def country_code_for_ip(value: str | None) -> str:
    """Return the selected ISO-3166 alpha-2 country, or ``""``."""

    return str(country_resolution_for_ip(value)["country_code"] or "")
