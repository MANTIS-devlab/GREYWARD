#!/usr/bin/env python3
"""Resolve the standalone installer payload on a networked Fedora 44 builder.

All package operations use disposable roots, never the builder's RPM database.
No ISO is published until RPM resolution and Flatpak installation work without
network access. This is a dependency test, not a substitute for a clean VM boot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

BOOT_PACKAGES = """kernel kernel-modules kernel-modules-extra grub2-efi-x64
grub2-efi-x64-modules shim-x64 grub2-pc grub2-pc-modules grub2-tools-extra grubby efibootmgr dosfstools mtools
btrfs-progs cryptsetup lvm2 xfsprogs e2fsprogs authselect systemd-udev
nvme-cli
NetworkManager chrony dnf5 dnf-plugins-core plymouth plymouth-scripts
plymouth-plugin-script plymouth-plugin-label dracut curl ca-certificates patch
tar gzip util-linux""".split()
EXCLUDED = "openssh-server,gnome-initial-setup,gnome-session-wayland-session,initial-setup,initial-setup-gui"


def run(*args, env=None, capture=False):
    result = subprocess.run(list(map(str, args)), check=True, env=env,
                            text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def lines(path):
    return [line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def download(url, path):
    # The dedicated builder has a working IPv4 route but an unreliable IPv6
    # path.  Keep this build-host workaround here; it is not embedded in the
    # installed system or the production ISO.
    run("curl", "--ipv4", "--http1.1", "--fail", "--location", "--retry", "10",
        "--retry-all-errors", "--connect-timeout", "30", "--max-time", "300",
        "--proto", "=https", "--tlsv1.2", url, "-o", path)


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def pinned(source, name):
    match = re.search(r"^(?:readonly )?" + name + r"='([^']+)'$", source, re.M)
    if not match:
        raise ValueError("Missing canonical pin: " + name)
    return match[1]


def rpm_inventory(paths):
    inventory = {}
    for path in paths:
        value = run("rpm", "-qp", "--qf", "%{NAME}.%{ARCH}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}",
                    path, capture=True).split("|")
        if len(value) != 4 or value[0] in inventory:
            raise ValueError("Duplicate or invalid RPM: " + str(path))
        inventory[value[0]] = value[1:]
    return inventory


def check_floors(inventory, baseline):
    import rpm
    from baseline import OMITTED_RPM_NAMES
    for name, version in inventory.items():
        if name.rsplit(".", 1)[0] in OMITTED_RPM_NAMES:
            continue
        floor = baseline["rpms"].get(name)
        if floor and rpm.labelCompare(tuple(version), tuple(floor)) < 0:
            raise ValueError("Repository package is older than .149: " + name)


def prepare_repositories(stage, work, offline):
    """Only Fedora and the canonical COPRs; never copy the host's repo config."""
    configs = work / "repos"
    configs.mkdir()
    future = offline / "update-repos"
    future.mkdir()
    keys = offline / "keys"
    keys.mkdir()
    fedora_key = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64")
    shutil.copyfile(fedora_key, keys / "fedora-44.gpg")
    repositories = [
        ("fedora", "metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64", "fedora-44.gpg"),
        ("updates", "metalink=https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64", "fedora-44.gpg"),
    ]
    for copr in lines(stage / "repositories.txt"):
        if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", copr):
            raise ValueError("Invalid canonical COPR: " + copr)
        name = "greyward-copr-" + copr.replace("/", "-")
        key = name + ".gpg"
        download(f"https://download.copr.fedorainfracloud.org/results/{copr}/pubkey.gpg", keys / key)
        source = f"baseurl=https://download.copr.fedorainfracloud.org/results/{copr}/fedora-$releasever-$basearch/"
        repositories.append((name, source, key))
        # Fedora's own repository package owns Fedora repo configuration.
        (future / (name + ".repo")).write_text(
            f"[{name}]\nname=GREYWARD runtime — {copr}\n{source}\nenabled=1\ngpgcheck=1\n"
            f"gpgkey=file:///etc/pki/rpm-gpg/{key}\nskip_if_unavailable=False\n")
    for name, source, key in repositories:
        (configs / (name + ".repo")).write_text(
            f"[{name}]\nname={name}\n{source}\nenabled=1\ngpgcheck=1\n"
            f"gpgkey=file://{keys / key}\nskip_if_unavailable=False\n")
    return configs


def build_rpms(stage, work, offline, baseline):
    configs = prepare_repositories(stage, work, offline)
    repo = offline / "rpm"
    packages = repo / "Packages"
    packages.mkdir(parents=True)
    root = work / "rpm-root"
    root.mkdir()
    staged = sorted((stage / "rpms").glob("*.rpm"))
    run("dnf5", "-y", f"--installroot={root}", "--releasever=44",
        "--setopt=ip_resolve=4",
        "--setopt=retries=10", "--setopt=max_parallel_downloads=1",
        "--setopt=timeout=120",
        f"--setopt=reposdir={configs}", "--setopt=keepcache=True",
        f"--exclude={EXCLUDED}", "install", "--downloadonly", "@core",
        *BOOT_PACKAGES, *lines(stage / "packages.txt"), *staged)
    for rpm_path in sorted(root.rglob("*.rpm")) + staged:
        target = packages / rpm_path.name
        if target.exists() and digest(target) != digest(rpm_path):
            raise ValueError("RPM filename collision: " + rpm_path.name)
        shutil.copyfile(rpm_path, target)
    export_core_group(root, configs, offline / "comps.xml")
    return verify_rpms(stage, work, offline, baseline)


def export_core_group(root, configs, destination):
    """Preserve the merged Fedora core group used by the download transaction.

    Anaconda selects @core even with an explicit Kickstart package list. RPM
    metadata alone is therefore not an installable repository for this ISO.
    """
    import libdnf5
    base = libdnf5.base.Base()
    base.load_config()
    config = base.get_config()
    config.get_installroot_option().set(str(root))
    config.get_reposdir_option().set([str(configs)])
    config.get_cachedir_option().set(str(root / "var/cache/libdnf5"))
    config.get_system_cachedir_option().set(str(root / "var/cache/libdnf5"))
    config.get_cacheonly_option().set("all")
    config.get_optional_metadata_types_option().set(["comps"])
    base.get_vars().set("releasever", "44")
    base.setup()
    sack = base.get_repo_sack()
    sack.create_repos_from_system_configuration()
    sack.load_repos(libdnf5.repo.Repo.Type_AVAILABLE)
    query = libdnf5.comps.GroupQuery(base)
    query.filter_groupid(["core"])
    groups = list(query)
    if len(groups) != 1:
        raise ValueError("Expected exactly one merged Fedora core group")
    groups[0].serialize(str(destination))
    prune_excluded_group_packages(destination)


def prune_excluded_group_packages(path):
    """The local group must not request packages production intentionally omits."""
    tree = ET.parse(path)
    excluded = set(EXCLUDED.split(","))
    for packages in tree.findall(".//packagelist"):
        for package in list(packages):
            if (package.text or "").strip() in excluded:
                packages.remove(package)
    tree.write(path, encoding="utf-8", xml_declaration=True)


def verify_installer_repository(repo, verify_root, selection=()):
    """Resolve Anaconda's implicit requests too, with no installed RPMs/network."""
    verify_root.mkdir()
    run("unshare", "--net", "dnf5", "-y", f"--installroot={verify_root}",
        "--releasever=44", "--disablerepo=*", f"--repofrompath=greyward-media,file://{repo}",
        "--enablerepo=greyward-media", "--setopt=greyward-media.gpgcheck=0",
        f"--exclude={EXCLUDED}", "--setopt=install_weak_deps=False",
        "install", "--downloadonly", "@core", *BOOT_PACKAGES, *selection)


def verify_signatures(packages, staged, offline):
    # Upstream signatures are checked in a separate trust database. Local
    # GREYWARD/OpenSnitch inputs have already passed build.sh's hash contract.
    # rpm transitions to a confined SELinux domain. Keep its small temporary
    # trust database under /var/tmp, independent of build-volume labels.
    with tempfile.TemporaryDirectory(prefix="greyward-rpm-trust-", dir="/var/tmp") as temporary:
        trust = Path(temporary)
        if Path("/sys/fs/selinux/enforce").exists():
            run("chcon", "--reference=/usr/lib/sysimage/rpm", trust)
        run("rpm", f"--dbpath={trust}", "--initdb")
        for key in (offline / "keys").glob("*.gpg"):
            run("rpm", f"--dbpath={trust}", "--import", key)
        local_names = {p.name for p in staged}
        for package in packages.glob("*.rpm"):
            if package.name not in local_names:
                result = run("rpmkeys", f"--dbpath={trust}", "--checksig", package, capture=True)
                if "signatures OK" not in result:
                    raise ValueError("Unsigned upstream RPM: " + package.name)


def verify_rpms(stage, work, offline, baseline):
    repo = offline / "rpm"
    packages = repo / "Packages"
    staged = sorted((stage / "rpms").glob("*.rpm"))
    inventory = rpm_inventory(sorted(packages.glob("*.rpm")))
    if len(inventory) < 100:
        raise ValueError("Incomplete base package closure")
    check_floors(inventory, baseline)
    verify_signatures(packages, staged, offline)
    run("createrepo_c", "--groupfile", offline / "comps.xml", repo)
    # Keep explicit selection and the local @core metadata Anaconda requires.
    selection = sorted(inventory)
    local_inventory = rpm_inventory(staged)
    (offline / "installer-packages.ks").write_text(
        "%packages --exclude-weakdeps\n" + "\n".join(n for n in selection if n not in local_inventory)
        + "\n-openssh-server\n%end\n")
    # A new RPM database, empty cache, one local repo, and no network interface.
    # --downloadonly solves the complete transaction without running scriptlets.
    verify_installer_repository(repo, work / "rpm-verify", selection)
    return inventory


def build_sources(stage, offline):
    source = (stage / "install-dms.sh").read_text()
    version = pinned(source, "DMS_VERSION")
    archive = offline / "dms-full-amd64.tar.gz"
    download(f"https://github.com/AvengeMedia/DankMaterialShell/releases/download/{version}/dms-full-amd64.tar.gz", archive)
    if digest(archive) != pinned(source, "DMS_ARCHIVE_SHA256"):
        raise ValueError("DMS archive checksum mismatch")
    sources = (stage / "zsh/sources.env").read_text()
    vendor = offline / "zsh-vendor"
    vendor.mkdir()
    for name in ("GREYWARD_OH_MY_ZSH", "GREYWARD_POWERLEVEL10K"):
        ref, url = pinned(sources, name + "_REF"), pinned(sources, name + "_REPO")
        if not re.fullmatch("[0-9a-f]{40}", ref) or not url.startswith("https://github.com/"):
            raise ValueError("Invalid shell source pin")
        destination = vendor / ref
        run("git", "init", "--bare", destination)
        run("git", "-C", destination, "fetch", "--depth=1", url, ref)
        run("git", "-C", destination, "update-ref", "refs/heads/greyward", "FETCH_HEAD")
        if run("git", "-C", destination, "rev-parse", "refs/heads/greyward", capture=True) != ref:
            raise ValueError("Shell source commit mismatch")
        if name == "GREYWARD_POWERLEVEL10K":
            # Powerlevel10k otherwise downloads gitstatusd when the user opens
            # their first terminal. Its pinned installer verifies build.info's
            # SHA-256; keep the resulting binary in a shared read-only cache.
            with tempfile.TemporaryDirectory(prefix="gitstatus-", dir=offline) as temporary:
                tree = Path(temporary)
                run("git", "-C", destination, "archive", f"--output={tree / 'source.tar'}", ref, "gitstatus")
                run("tar", "-xf", tree / "source.tar", "-C", tree)
                cache = offline / "gitstatus"
                cache.mkdir()
                env = dict(os.environ, GITSTATUS_CACHE_DIR=str(cache))
                run("sh", tree / "gitstatus/install", "-f", "-s", "linux", "-m", "x86_64", env=env)
                run("unshare", "--net", "sh", tree / "gitstatus/install", "-n", "-s", "linux", "-m", "x86_64", env=env)
    (vendor / "required").touch()


def flatpak_env(path):
    path.mkdir()
    # Flatpak otherwise keeps consulting /var/lib/flatpak. That can make an
    # offline dependency check pass only because the builder already has the
    # requested runtime installed. Keep both installations disposable.
    directories = ("data", "config", "cache", "system", "system-cache", "user")
    for name in directories:
        (path / name).mkdir(parents=True, exist_ok=True)
    return dict(os.environ, XDG_DATA_HOME=str(path / "data"), XDG_CONFIG_HOME=str(path / "config"),
                XDG_CACHE_HOME=str(path / "cache"), FLATPAK_SYSTEM_DIR=str(path / "system"),
                FLATPAK_SYSTEM_CACHE_DIR=str(path / "system-cache"), FLATPAK_USER_DIR=str(path / "user"))


def prepare_sideload_repo(repo, offline_refs):
    """Turn create-usb's collection mirror into an installable local repo.

    Flatpak 1.18 can create a sideload repository whose refs are present under
    refs/mirrors but whose summary has zero branches. The resulting media then
    fails with "Nothing matches ... in remote" on a clean target. Preserve the
    mirror refs and publish copies as ordinary heads with a fresh summary; the
    first-boot installer uses this local summary, not Flathub's network URL.
    """
    mirror = repo / "refs/mirrors/org.flathub.Stable"
    heads = repo / "refs/heads"
    copied = []
    for source in sorted(mirror.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(mirror)
        target = heads / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(str(relative))
    if not copied:
        raise ValueError("Flatpak create-usb produced no collection refs")
    for ref in offline_refs:
        if ref not in copied:
            raise ValueError("Flatpak sideload repo is missing selected ref: " + ref)
    run("flatpak", "build-update-repo", repo, "--collection-id=org.flathub.Stable")
    return copied


def build_flatpaks(stage, work, offline, baseline):
    remote = offline / "flathub.flatpakrepo"
    download("https://dl.flathub.org/repo/flathub.flatpakrepo", remote)
    source_env = flatpak_env(work / "flatpak-source")
    run("flatpak", "--user", "config", "--set", "languages", "*", env=source_env)
    run("flatpak", "--user", "remote-add", "--from", "flathub", remote, env=source_env)
    run("flatpak", "--user", "remote-modify", "--collection-id=org.flathub.Stable", "flathub", env=source_env)
    refs = []
    for item in baseline["flatpaks"].values():
        ref, commit = item["ref"], item["commit"]
        run("flatpak", "--user", "install", "--noninteractive", "flathub", ref, env=source_env)
        run("flatpak", "--user", "update", "--noninteractive", f"--commit={commit}", ref, env=source_env)
        # An older selected app commit can use an older runtime branch than
        # today's app. Updating to a commit does not install that runtime.
        runtime = run("flatpak", "--user", "info", "--show-runtime", ref, env=source_env, capture=True)
        run("flatpak", "--user", "install", "--noninteractive", "flathub", "runtime/" + runtime, env=source_env)
        refs.append(ref)
    destination = offline / "flatpak"
    destination.mkdir()
    run("flatpak", "--user", "create-usb", destination, *refs, env=source_env)
    repo = destination / ".ostree/repo"
    prepare_sideload_repo(repo, refs)
    inventory = "\n".join(f"{ref}\t{baseline['flatpaks'][ref.split('/', 2)[1]]['commit']}"
                           for ref in refs)
    (offline / "flatpak-inventory.tsv").write_text(inventory + "\n")
    # Prove actual installation, including dependencies, with no host Flatpak
    # installation/cache and no network. Do not downgrade signature checking.
    test_env = flatpak_env(work / "flatpak-verify")
    run("unshare", "--net", "bash", stage / "install-offline-flatpaks.sh", stage, "--user", env=test_env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--stage")
    mode.add_argument("--verify-media-repo")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run via sudo: isolated DNF roots and offline network namespaces require root")
    if args.verify_media_repo:
        repo = Path(args.verify_media_repo).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix=".media-repo-check-", dir=repo.parent) as temporary:
            verify_installer_repository(repo, Path(temporary) / "root")
        return
    stage = Path(args.stage).resolve(strict=True)
    offline = stage / "offline"
    baseline = json.loads((stage / "artifacts/runtime-baseline.json").read_text())
    from baseline import validate
    validate(baseline)
    offline.mkdir()  # refuse stale or partly prepared payloads
    try:
        with tempfile.TemporaryDirectory(prefix=".offline-build-", dir=stage.parent) as temporary:
            work = Path(temporary)
            inventory = build_rpms(stage, work, offline, baseline)
            build_sources(stage, offline)
            build_flatpaks(stage, work, offline, baseline)
        (offline / "manifest.json").write_text(json.dumps({
            "schema": "greyward.offline-payload/v1", "rpm_inventory": inventory,
            "baseline_sha256": digest(stage / "artifacts/runtime-baseline.json"),
            "networkless_rpm_resolution": True, "networkless_flatpak_installation": True,
            "installer_implicit_dependencies_verified": True,
            "core_comps_sha256": digest(offline / "comps.xml"),
            "clean_vm_installation_tested": False,
        }, indent=2) + "\n")
    finally:
        # build-iso.sh normally runs as the unprivileged repository owner.
        uid, gid = stage.stat().st_uid, stage.stat().st_gid
        for directory, dirs, files in os.walk(offline):
            os.chown(directory, uid, gid)
            for name in dirs + files:
                os.chown(Path(directory) / name, uid, gid, follow_symlinks=False)


if __name__ == "__main__":
    main()
