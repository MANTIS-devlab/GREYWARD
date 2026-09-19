#!/usr/bin/env python3
"""Validate a GREYWARD ISO using the names Linux Anaconda will see.

Windows mounts ISO9660 media using short names and loses Rock Ridge names such
as ``external-rpms.txt``. Reading the image directly avoids false failures in
the VMware preflight while still checking the exact media contents.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import sys
from pathlib import PurePosixPath

try:
    import pycdlib
except ImportError as exc:  # pragma: no cover - environment dependency
    print(f"VMWARE_ISO_VALIDATION=FAIL: pycdlib is required ({exc})")
    raise SystemExit(2)


STATIC_REQUIRED = {
    "packages.txt",
    "repositories.txt",
    "external-rpms.txt",
    "install-dms.sh",
    "install-offline-flatpaks.sh",
    "provision.sh",
    "provision-firstboot.sh",
    "provision-firstboot.service",
    "firstboot-status.sh",
    "firstboot-status.service",
    "production-acceptance.sh",
    "payload.sha256",
    "manifest.json",
    "artifact-policy.json",
    "security-center-contract.tsv",
    "offline/manifest.json",
    "offline/rpm/repodata/repomd.xml",
    "offline/comps.xml",
    "offline/installer-packages.ks",
    "offline/flatpak-inventory.tsv",
}


class IsoTree:
    root = "/GREYWARD/PRODUCTION"

    def __init__(self, path: str) -> None:
        self.iso = pycdlib.PyCdlib()
        self.iso.open(path)
        self.files: dict[str, str] = {}
        self._index()

    @staticmethod
    def _record_name(record, is_file: bool) -> str:
        try:
            return record.rock_ridge.name().decode("utf-8")
        except Exception:
            value = record.file_identifier().decode("ascii", "replace")
            return value.split(";", 1)[0] if is_file else value

    def _index(self) -> None:
        directory_names = {self.root: ""}
        for dirname, dirs, files in self.iso.walk(iso_path=self.root):
            for directory in dirs:
                iso_path = f"{dirname}/{directory}"
                record = self.iso.get_record(iso_path=iso_path)
                directory_names[iso_path] = self._record_name(record, False)
            for filename in files:
                iso_path = f"{dirname}/{filename}"
                record = self.iso.get_record(iso_path=iso_path)
                components: list[str] = []
                current = dirname
                while current != self.root:
                    components.insert(0, directory_names[current])
                    current = current.rsplit("/", 1)[0]
                components.append(self._record_name(record, True))
                relative = "/".join(components).strip("/").lower()
                self.files[relative] = iso_path

    def read(self, relative: str) -> bytes:
        iso_path = self.files[relative.lower()]
        target = io.BytesIO()
        self.iso.get_file_from_iso_fp(target, iso_path=iso_path)
        return target.getvalue()

    def read_iso_path(self, iso_path: str) -> bytes:
        target = io.BytesIO()
        self.iso.get_file_from_iso_fp(target, iso_path=iso_path)
        return target.getvalue()

    def close(self) -> None:
        self.iso.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", required=True)
    args = parser.parse_args()
    tree = IsoTree(args.iso)
    failures: list[str] = []
    try:
        required = set(STATIC_REQUIRED)
        provision = tree.read("provision.sh").decode("utf-8")
        required.update(
            match.group(1).lower()
            for match in re.finditer(r'test\s+-r\s+"\$stage/([^"]+)"', provision)
        )
        for relative in sorted(required):
            if relative.lower() not in tree.files:
                failures.append(f"ISO production payload is missing: {relative}")

        for package in ("greyward-security-center", "greyward-security-context", "greyward-branding"):
            matches = sorted(
                relative
                for relative in tree.files
                if PurePosixPath(relative).parent == PurePosixPath("rpms")
                and PurePosixPath(relative).name.startswith(package + "-")
                and PurePosixPath(relative).suffix == ".rpm"
            )
            if len(matches) != 1:
                failures.append(
                    f"ISO RPM closure has {len(matches)} copies of {package} (expected 1)."
                )

        if failures:
            print("VMWARE_ISO_VALIDATION=FAIL")
            for failure in failures:
                print(failure)
            return 1

        try:
            installer = tree.read_iso_path("/INSTALLER.KS;1").decode("utf-8")
        except (KeyError, UnicodeDecodeError, pycdlib.pycdlibexception.PyCdlibInvalidInput):
            failures.append("ISO is missing a readable root installer.ks")
        else:
            required_installer_fragments = {
                "media_root": "installer.ks does not resolve the mounted production payload",
                "payload copy did not create": "installer.ks does not verify the target payload marker after copy",
                'cp -a "$media_stage/." "$target_stage/"': "installer.ks does not copy the resolved production stage",
                'target_stage=/mnt/sysroot/usr/lib/greyward/installer/production': "installer.ks does not place the production payload on the installed root filesystem",
            }
            for fragment, message in required_installer_fragments.items():
                if fragment not in installer:
                    failures.append(message)
            if "/run/install/repo/greyward/production/." in installer:
                failures.append("installer.ks still uses the obsolete single-path production copy")
            if "target_stage=/mnt/sysroot/var/lib/greyward/installer/production" in installer:
                failures.append("installer.ks still stages production under the variable /var mount")

        if failures:
            print("VMWARE_ISO_VALIDATION=FAIL")
            for failure in failures:
                print(failure)
            return 1

        manifest = tree.read("payload.sha256").decode("utf-8")
        hash_failures = 0
        for line in manifest.splitlines():
            match = re.fullmatch(r"([0-9a-fA-F]{64})\s+(.+)", line)
            if not match:
                print(f"Malformed payload manifest line: {line}")
                hash_failures += 1
                continue
            expected, relative = match.groups()
            relative = relative.removeprefix("./").lower()
            if relative not in tree.files:
                print(f"Manifest file missing from ISO: {relative}")
                hash_failures += 1
                continue
            actual = hashlib.sha256(tree.read(relative)).hexdigest()
            if actual.lower() != expected.lower():
                print(f"Payload hash mismatch: {relative} (expected {expected}, got {actual})")
                hash_failures += 1
        if hash_failures:
            print(f"VMWARE_ISO_VALIDATION=FAIL_HASHES ({hash_failures})")
            return 1

        print(f"VMWARE_ISO_VALIDATION=PASS required_paths={len(required)}")
        return 0
    finally:
        tree.close()


if __name__ == "__main__":
    sys.exit(main())
