"""Tests for the explicit .150 installed-RPM import path used by test ISOs."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "installed_rpm_import", ROOT / "environment/image/validate-installed-rpm-import.py"
)
importer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(importer)


class InstalledRpmImportTests(unittest.TestCase):
    def test_accepts_exact_captured_rpms(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = {
                "greyward-dms": ("greyward-dms-1.6.2-26.fc44.x86_64.rpm", "d" * 40),
                "greyward-security-center": ("greyward-security-center-0.1.0-115.fc44.x86_64.rpm", "c" * 40),
                "greyward-security-context": ("greyward-security-context-0.1.0-108.fc44.noarch.rpm", "e" * 40),
                "greyward-application-security-experimental": ("greyward-application-security-experimental-0.1.0-69.fc44.x86_64.rpm", "a" * 40),
                "greyward-application-enrollment": ("greyward-application-enrollment-0.1.0-60.fc44.x86_64.rpm", "b" * 40),
            }
            selected = []
            lines = [
                "schema=greyward.security-center-installed-import/v1",
                "origin=bare-metal-.150",
                "source_validation=not-performed",
                "captured_at=2026-10-19",
            ]
            query_results = {}
            for name, (filename, header) in artifacts.items():
                path = root / filename
                data = name.encode()
                path.write_bytes(data)
                sha = hashlib.sha256(data).hexdigest()
                label = importer.EXPECTED[name]
                nevra = filename[:-4]
                lines.extend((
                    f"{label}_filename={filename}",
                    f"{label}_sha256={sha}",
                    f"{label}_nevra={nevra}",
                    f"{label}_header_sha1={header}",
                ))
                selected.append(path)
                query_results[(str(path), "%{NAME}")] = name
                query_results[(str(path), "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}")] = nevra
                query_results[(str(path), "%{SHA1HEADER}")] = header
            manifest = root / "capture.tsv"
            manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")

            def fake_run(args, **kwargs):
                class Result:
                    stdout = query_results[(args[-1], args[3])]
                return Result()

            with patch.object(importer.subprocess, "run", side_effect=fake_run):
                importer.validate(manifest, selected)

    def test_rejects_same_version_with_different_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = {
                "greyward-dms": ("greyward-dms-1.6.2-26.fc44.x86_64.rpm", "d" * 40),
                "greyward-security-center": ("greyward-security-center-0.1.0-115.fc44.x86_64.rpm", "c" * 40),
                "greyward-security-context": ("greyward-security-context-0.1.0-108.fc44.noarch.rpm", "e" * 40),
                "greyward-application-security-experimental": ("greyward-application-security-experimental-0.1.0-69.fc44.x86_64.rpm", "a" * 40),
                "greyward-application-enrollment": ("greyward-application-enrollment-0.1.0-60.fc44.x86_64.rpm", "b" * 40),
            }
            selected = []
            lines = [
                "schema=greyward.security-center-installed-import/v1",
                "origin=bare-metal-.150",
                "source_validation=not-performed",
                "captured_at=2026-10-19",
            ]
            query_results = {}
            for name, (filename, header) in artifacts.items():
                path = root / filename
                data = name.encode()
                path.write_bytes(data)
                label = importer.EXPECTED[name]
                nevra = filename[:-4]
                lines.extend((
                    f"{label}_filename={filename}",
                    f"{label}_sha256={hashlib.sha256(data).hexdigest()}",
                    f"{label}_nevra={nevra}",
                    f"{label}_header_sha1={header}",
                ))
                selected.append(path)
                query_results[(str(path), "%{NAME}")] = name
                query_results[(str(path), "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}")] = nevra
                query_results[(str(path), "%{SHA1HEADER}")] = header
            manifest = root / "capture.tsv"
            manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
            selected[0].write_bytes(b"same NEVRA, different RPM bytes")

            def fake_run(args, **kwargs):
                class Result:
                    stdout = query_results[(args[-1], args[3])]
                return Result()

            with patch.object(importer.subprocess, "run", side_effect=fake_run):
                with self.assertRaisesRegex(ValueError, "bytes differ"):
                    importer.validate(manifest, selected)

    def test_rejects_manifest_that_claims_source_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "capture.tsv"
            manifest.write_text(
                "schema=greyward.security-center-installed-import/v1\n"
                "origin=bare-metal-.150\nsource_validation=passed\n"
                "captured_at=2026-10-19\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "source_validation"):
                importer.validate(manifest, [])


if __name__ == "__main__":
    unittest.main()
