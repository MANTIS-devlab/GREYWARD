#!/usr/bin/env python3
"""Reject stale/missing Software startup inputs before and after ISO composition."""

import argparse
from pathlib import Path


INPUTS = {
    "flatpak/greyward-software": "environment/flatpak/greyward-software",
    "flatpak/greyward-bazaar-start": "environment/flatpak/greyward-bazaar-start",
    "provision.sh": "environment/production/provision.sh",
}


def verify(repo: Path, stage: Path) -> None:
    for embedded, source in INPUTS.items():
        expected = (repo / source).read_bytes().replace(b"\r\n", b"\n")
        actual = stage / embedded
        if not actual.is_file() or actual.is_symlink():
            raise ValueError(f"Software input missing or not a regular file: {embedded}")
        if actual.read_bytes() != expected:
            raise ValueError(f"Software input differs from canonical source: {embedded}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.repo, args.stage)
    except (OSError, ValueError) as error:
        parser.exit(1, f"SOFTWARE_INPUT_VALIDATION=FAIL: {error}\n")
    print("SOFTWARE_INPUT_VALIDATION=PASS")


if __name__ == "__main__":
    main()
