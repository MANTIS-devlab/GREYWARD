#!/usr/bin/env python3
"""Portable, explicit runtime baseline for the standalone installer.

Package versions are floors, not a disk clone. Only repository-selected desktop
preferences are imported; machine identity, accounts and secrets are never read.
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCHEMA = "greyward.runtime-baseline/v1"
CONFIG = "environment/session/dankmaterialshell/settings.json"
TERMINAL = "environment/production/dconf/50-greyward-blackbox"
SAFE_TERMINAL = {"font", "opacity", "theme-dark", "theme-light", "style-preference",
                 "terminal-padding", "terminal-cell-height", "terminal-cell-width",
                 "show-headerbar", "show-scrollbars", "scrollback-lines",
                 "cursor-shape", "cursor-blink-mode", "easy-copy-paste"}
# These packages are historical development-host residue, not GREYWARD
# production inputs. They are intentionally excluded from the portable RPM
# floor so a retired Kitty/Tabby package on .149 cannot block a valid image.
OMITTED_RPM_NAMES = {
    "kitty", "kitty-kitten", "kitty-shell-integration", "kitty-terminfo",
    "tabby",
}


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def policy(repo):
    repo = Path(repo)
    # Bind the capture to the actual configuration/assets, including dirty
    # working-tree changes. Commit IDs alone cannot identify this project state.
    sources = {}
    for folder in ("environment/production", "environment/session", "environment/flatpak", "environment/patches", "branding"):
        for path in sorted((repo / folder).rglob("*")):
            if path.is_file() and not any(p in ("__pycache__", ".work") for p in path.parts):
                content = path.read_bytes()
                if path.suffix not in (".png", ".jpg", ".jpeg", ".woff", ".woff2"):
                    content = content.replace(b"\r\n", b"\n")
                sources[path.relative_to(repo).as_posix()] = hashlib.sha256(content).hexdigest()
    return {"source_files": sources, "dms": read(repo / CONFIG), "terminal": sorted(SAFE_TERMINAL),
            "flatpaks": sorted({"io.github.kolunmi.Bazaar"} | {
                line.split("|")[0].strip() for line in
                (repo / "environment/flatpak/default-applications.list").read_text().splitlines()
                if line.strip() and not line.startswith("#")})}


def portable(value, default, key=""):
    # Preserve topology-independent defaults for paths and output selection.
    if any(word in key.lower() for word in ("path", "file", "screen", "monitor")):
        return default
    if isinstance(default, dict):
        value = value if isinstance(value, dict) else {}
        return {k: portable(value.get(k, v), v, k) for k, v in default.items()}
    if isinstance(default, list):
        # Bar configuration is a controlled product surface. Never import a
        # different set of bars, plugins or monitor names from a personal session.
        if key == "barConfigs" and isinstance(value, list):
            by_id = {v.get("id"): v for v in value if isinstance(v, dict)}
            return [portable(by_id.get(v.get("id"), v), v) for v in default]
        return default
    if type(value) is not type(default):
        return default
    if isinstance(value, str) and ("/" in value or "\\" in value or "\n" in value):
        return default
    return value


def packages():
    rows = run("rpm", "-qa", "--qf", "%{NAME}\t%{ARCH}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n")
    result = {}
    import rpm
    for row in rows.splitlines():
        name, arch, epoch, version, release = row.split("\t")
        if name == "gpg-pubkey" or name in OMITTED_RPM_NAMES or arch == "(none)":
            continue
        key = name + "." + arch
        evr = [epoch, version, release]
        if key not in result or rpm.labelCompare(tuple(evr), tuple(result[key])) > 0:
            result[key] = evr
    return result


def capture(policy_path, output):
    p = read(policy_path)
    if run("rpm", "-E", "%fedora") != "44":
        raise ValueError("Baseline must be captured on Fedora 44")
    dms = read(Path.home() / ".config/DankMaterialShell/settings.json")
    term = {}
    for key in p["terminal"]:
        value = run("gsettings", "get", "com.raggesilver.BlackBox", key)
        if "\n" in value or len(value) > 200:
            raise ValueError("Invalid terminal preference: " + key)
        term[key] = value
    refs = {}
    for app in p["flatpaks"]:
        refs[app] = {"ref": run("flatpak", "info", "--system", "--show-ref", app),
                     "commit": run("flatpak", "info", "--system", "--show-commit", app)}
    baseline = {"schema": SCHEMA, "fedora": "44", "policy_sha256": digest(p),
                "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "rpms": packages(), "flatpaks": refs,
                "dms": portable(dms, p["dms"]), "terminal": term,
                "source_files": p["source_files"],
                "omitted_dms_keys": sorted(set(dms) - set(p["dms"])),
                "normalized_dms_keys": sorted(k for k in p["dms"] if dms.get(k) != portable(dms, p["dms"])[k]),
                "scope": "RPM version floors for installed matching packages; selected system Flatpak commits; portable DMS and terminal preferences. Repository owns branding, plugins, shell, security policy and Labwc configuration. No user data or machine configuration."}
    validate(baseline)
    write(output, baseline)


def validate(b):
    if b.get("schema") != SCHEMA or b.get("fedora") != "44":
        raise ValueError("Unsupported baseline schema or Fedora release")
    if not b.get("rpms") or not b.get("flatpaks"):
        raise ValueError("Empty baseline")
    for name, evr in b["rpms"].items():
        if not re.fullmatch(r"[A-Za-z0-9_+.-]+", name) or len(evr) != 3:
            raise ValueError("Invalid RPM baseline")
        if not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_+.~^:-]+", v) for v in evr):
            raise ValueError("Invalid RPM version")
    for app, entry in b["flatpaks"].items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", app):
            raise ValueError("Invalid Flatpak ID")
        if not re.fullmatch(r"[0-9a-f]{64}", entry["commit"]):
            raise ValueError("Invalid Flatpak commit")
        if not re.fullmatch(r"app/" + re.escape(app) + r"/x86_64/[A-Za-z0-9_.-]+", entry["ref"]):
            raise ValueError("Invalid Flatpak ref")


def stage(repo, baseline, destination):
    b = read(baseline)
    validate(b)
    p = policy(repo)
    if b["policy_sha256"] != digest(p):
        raise ValueError("Baseline policy differs from source. Recapture after reviewing configuration changes.")
    if set(b["flatpaks"]) != set(p["flatpaks"]) or set(b["terminal"]) != SAFE_TERMINAL:
        raise ValueError("Baseline preference/application scope differs from source")
    if portable(b["dms"], p["dms"]) != b["dms"]:
        raise ValueError("Non-portable baseline settings")
    dest = Path(destination)
    write(dest / "dankmaterialshell/settings.json", b["dms"])
    path = dest / "dconf/50-greyward-blackbox"
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0]
        if key in b["terminal"]:
            value = b["terminal"][key]
            if not isinstance(value, str) or "\n" in value or "\r" in value or len(value) > 200:
                raise ValueError("Invalid terminal setting")
            lines[i] = key + "=" + value
    path.write_text("\n".join(lines) + "\n")
    write(dest / "artifacts/runtime-baseline.json", b)
    # Keep an install-time verifier alongside its immutable input.
    (dest / "baseline.py").write_bytes(Path(__file__).read_bytes())


def verify(baseline):
    b = read(baseline)
    validate(b)
    import rpm
    current = packages()
    errors = []
    # A dev-only package absent from the target is not an install request.
    for name, wanted in b["rpms"].items():
        if name in current and rpm.labelCompare(tuple(current[name]), tuple(wanted)) < 0:
            errors.append("RPM below baseline: " + name)
    for app, wanted in b["flatpaks"].items():
        if run("flatpak", "info", "--system", "--show-commit", app) != wanted["commit"]:
            errors.append("Flatpak differs from baseline: " + app)
        if run("flatpak", "info", "--system", "--show-ref", app) != wanted["ref"]:
            errors.append("Flatpak ref differs from baseline: " + app)
    if errors:
        raise ValueError("\n".join(errors))
    print("Runtime package baseline verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    q = sub.add_parser("policy"); q.add_argument("--repo", required=True); q.add_argument("--output", required=True)
    q = sub.add_parser("capture"); q.add_argument("--policy", required=True); q.add_argument("--output", required=True)
    q = sub.add_parser("stage"); q.add_argument("--repo", required=True); q.add_argument("--baseline", required=True); q.add_argument("--destination", required=True)
    q = sub.add_parser("verify"); q.add_argument("--baseline", required=True)
    q = sub.add_parser("flatpak-args"); q.add_argument("--baseline", required=True)
    a = parser.parse_args()
    if a.command == "policy": write(a.output, policy(a.repo))
    elif a.command == "capture": capture(a.policy, a.output)
    elif a.command == "stage": stage(a.repo, a.baseline, a.destination)
    elif a.command == "verify": verify(a.baseline)
    else:
        b = read(a.baseline); validate(b)
        for entry in b["flatpaks"].values(): print(entry["ref"] + "\t" + entry["commit"])


if __name__ == "__main__":
    main()
