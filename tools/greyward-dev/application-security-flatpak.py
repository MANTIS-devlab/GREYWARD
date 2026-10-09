#!/usr/bin/python3
"""Read-only installed Flatpak probe using disposable user overrides.

Never changes installed applications or the active user's override directory.
No permission contents/environment values are written to receipts.
"""
import configparser
import json
import os
import pathlib
import re
import runpy
import subprocess
import tempfile


def command(arguments, directory=None):
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    if directory is not None:
        environment["FLATPAK_USER_DIR"] = str(directory)
    result = subprocess.run(["/usr/bin/flatpak", *arguments], env=environment,
                            capture_output=True, check=True, timeout=5)
    if len(result.stdout) > 256 * 1024:
        raise RuntimeError("Fixed provider metadata exceeds probe budget")
    return result.stdout.decode("utf-8")


def context(reference, directory):
    text = command(["info", "--system", "--show-permissions", reference], directory)
    parser = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    parser.optionxform = str
    parser.read_string(text)
    return dict(parser["Context"]) if parser.has_section("Context") else {}


def permits(values, key, item):
    return item in values.get(key, "").split(";")


def main():
    if os.getuid() == 0:
        raise RuntimeError("Run the read-only probe as the unprivileged builder")
    refs = command(["list", "--app", "--system", "--columns=ref"]).splitlines()
    reference = next((ref for ref in refs if re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+", ref)), None)
    if reference is None:
        raise RuntimeError("No supported installed system application for the probe")
    app_id = reference.split("/")[0]
    with tempfile.TemporaryDirectory(prefix="greyward-flatpak-read-") as temporary:
        directory = pathlib.Path(temporary)
        overrides = directory / "overrides"
        overrides.mkdir(mode=0o700)
        global_override = overrides / "global"
        app_override = overrides / app_id
        global_override.write_text("[Context]\nshared=!network;\nfilesystems=!home;/tmp/greyward-synthetic-flatpak:ro;\n")
        global_state = context(reference, directory)
        assert not permits(global_state, "shared", "network")
        assert not permits(global_state, "filesystems", "home")
        assert permits(global_state, "filesystems", "/tmp/greyward-synthetic-flatpak:ro")
        app_override.write_text("[Context]\nshared=network;\nfilesystems=home;\n")
        app_state = context(reference, directory)
        assert permits(app_state, "shared", "network")
        assert permits(app_state, "filesystems", "home")
        assert permits(app_state, "filesystems", "/tmp/greyward-synthetic-flatpak:ro")
        app_override.write_text("[Context]\nshared=!network;\nfilesystems=!home;\n")
        denied_state = context(reference, directory)
        assert not permits(denied_state, "shared", "network")
        assert not permits(denied_state, "filesystems", "home")
        assert permits(denied_state, "filesystems", "/tmp/greyward-synthetic-flatpak:ro")
    # Exercise the production seeding decisions with the real provider, writing
    # only a disposable user installation. Never run the root entrypoint or
    # modify system/active-account overrides from this development probe.
    seed = runpy.run_path("/var/tmp/greyward-application-security-build/environment/flatpak/seed-system-permissions.py")["seed_defaults"]
    with tempfile.TemporaryDirectory(prefix="greyward-flatpak-defaults-") as temporary:
        directory = pathlib.Path(temporary)
        def provider(arguments):
            return command(["--user" if item == "--system" else item for item in arguments], directory)
        first = seed(provider)
        assert [item["decision"] for item in first] == ["SEEDED", "SEEDED"]
        originals = {path.name: path.read_bytes() for path in (directory / "overrides").iterdir()}
        assert [item["decision"] for item in seed(provider)] == ["PRESERVED", "PRESERVED"]
        assert originals == {path.name: path.read_bytes() for path in (directory / "overrides").iterdir()}
        (directory / "overrides/global").write_text("[Context]\nfilesystems=!home;/tmp/greyward-synthetic-flatpak:ro;\n")
        before = {path.name: path.read_bytes() for path in (directory / "overrides").iterdir()}
        assert [item["decision"] for item in seed(provider)] == ["PRESERVED", "PRESERVED"]
        assert before == {path.name: path.read_bytes() for path in (directory / "overrides").iterdir()}
    print(json.dumps({"schema": "greyward.application-security.flatpak-probe/v1",
                      "passed": True, "checks": 14, "installed_applications_changed": False,
                      "active_user_overrides_changed": False}))


if __name__ == "__main__":
    main()
