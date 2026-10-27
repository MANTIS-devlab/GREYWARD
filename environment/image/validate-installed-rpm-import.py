#!/usr/bin/env python3
"""Verify an explicit import of the runtime RPM artifacts installed on .150.

This is an internal test-image path. It records that the packages were copied
from an installed, RPM-verified system; it does not claim that their sources
were rebuilt or audited by the image build.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess


EXPECTED = {
    "greyward-dms": "dms",
    "greyward-security-center": "center",
    "greyward-security-context": "context",
    "greyward-application-security-experimental": "appsec",
    "greyward-application-enrollment": "enrollment",
}


def read_manifest(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise ValueError("Malformed or duplicate import-manifest key: " + line)
        values[key] = value
    return values


def rpm_value(path, query):
    return subprocess.run(
        ["rpm", "-qp", "--qf", query, str(path)], check=True,
        text=True, stdout=subprocess.PIPE,
    ).stdout.strip()


def validate(manifest_path, rpm_paths):
    manifest = read_manifest(manifest_path)
    required = {
        "schema": "greyward.security-center-installed-import/v1",
        "origin": "bare-metal-.150",
        "source_validation": "not-performed",
    }
    for key, value in required.items():
        if manifest.get(key) != value:
            raise ValueError(f"Import manifest {key} must be {value}")
    if not manifest.get("captured_at"):
        raise ValueError("Import manifest is missing captured_at")

    selected = {}
    for path in rpm_paths:
        name = rpm_value(path, "%{NAME}")
        if name not in EXPECTED or name in selected:
            raise ValueError("Unexpected or duplicate imported RPM: " + name)
        selected[name] = path
    if set(selected) != set(EXPECTED):
        raise ValueError("Import must contain exactly the five approved .150 runtime RPMs")

    for name, label in EXPECTED.items():
        path = selected[name]
        prefix = label + "_"
        expected_filename = manifest.get(prefix + "filename")
        expected_sha256 = manifest.get(prefix + "sha256", "")
        expected_nevra = manifest.get(prefix + "nevra")
        expected_header = manifest.get(prefix + "header_sha1", "")
        if path.name != expected_filename:
            raise ValueError(f"Imported {name} filename does not match the manifest")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError(f"Invalid SHA-256 pin for {name}")
        if not re.fullmatch(r"[0-9a-f]{40}", expected_header):
            raise ValueError(f"Invalid RPM header identity for {name}")
        with path.open("rb") as stream:
            sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        if sha256 != expected_sha256:
            raise ValueError(f"Imported {name} bytes differ from the captured .150 RPM")
        nevra = rpm_value(path, "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}")
        header = rpm_value(path, "%{SHA1HEADER}").lower()
        if nevra != expected_nevra or header != expected_header:
            raise ValueError(f"Imported {name} RPM identity differs from the captured .150 package")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--rpm", type=Path, action="append", required=True)
    args = parser.parse_args()
    validate(args.manifest, args.rpm)
    print("Installed .150 RPM import matches all five SHA-256 and RPM header pins")
