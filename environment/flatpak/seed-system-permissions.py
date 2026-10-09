#!/usr/bin/python3
"""Seed fresh-install defaults without resetting reviewed Flatpak policy.

Only two fixed distributor defaults; no generic policy/UI execution interface.
Any existing system global/app override is retained. User overrides are never
written. Readback confirms the default record, not effective resource coverage.
"""
import configparser
import json
import os
import subprocess
import sys

DEFAULTS = (
    ("io.github.kolunmi.Bazaar", "--filesystem=xdg-config/bazaar:ro", "filesystems", "xdg-config/bazaar:ro"),
    ("org.kde.haruna", "--unshare=network", "shared", "!network"),
)


class DefaultPolicyError(RuntimeError):
    pass


def seed_defaults(provider):
    global_policy = provider(["override", "--system", "--show"])
    results = []
    for app, option, key, token in DEFAULTS:
        current = provider(["override", "--system", "--show", app])
        if global_policy.strip() or current.strip():
            results.append({"application": app, "decision": "PRESERVED"})
            continue
        provider(["override", "--system", option, app])
        readback = provider(["override", "--system", "--show", app])
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        try:
            parser.read_string(readback)
            values = parser.get("Context", key, fallback="").split(";")
        except configparser.Error as failure:
            raise DefaultPolicyError("Default configuration readback unavailable") from failure
        if token not in values:
            raise DefaultPolicyError("Default configuration readback failed")
        results.append({"application": app, "decision": "SEEDED"})
    return results


def installed_provider(arguments):
    try:
        result = subprocess.run(["/usr/bin/flatpak", *arguments], close_fds=True,
                                capture_output=True, timeout=8, check=True,
                                env={"PATH": "/usr/bin:/bin", "HOME": "/root", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as failure:
        raise DefaultPolicyError("System Flatpak default provider unavailable") from failure
    if len(result.stdout) > 256 * 1024:
        raise DefaultPolicyError("System Flatpak default metadata exceeds budget")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as failure:
        raise DefaultPolicyError("System Flatpak default metadata is invalid") from failure


if __name__ == "__main__":
    try:
        if os.getuid() != 0 or os.geteuid() != 0 or len(sys.argv) != 1:
            raise DefaultPolicyError("Fixed root provisioning entrypoint required")
        print(json.dumps({"schema": "greyward.flatpak-defaults/v1", "results": seed_defaults(installed_provider)}))
    except DefaultPolicyError as failure:
        print(str(failure), file=sys.stderr)
        raise SystemExit(1)
