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
import time
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


def acquisition_cache(stage):
    """Persistent download objects; never reuse an RPM/verification database."""
    root = Path(os.environ.get('GREYWARD_ACQUISITION_CACHE', str(stage.parent / '.greyward-acquisition-cache')))
    if root.is_symlink():
        raise ValueError('Acquisition cache must not be a symlink')
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def cache_inventory(root):
    return {str(p.relative_to(root)): p.stat().st_size for p in root.rglob('*') if p.is_file()}


def received_bytes():
    """Builder interface traffic, including metadata and unrelated background traffic."""
    return sum(int(row.split(':', 1)[1].split()[0]) for row in Path('/proc/net/dev').read_text().splitlines()[2:]
               if row.split(':', 1)[0].strip() != 'lo')


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
    release = json.loads((stage / 'dms-release.json').read_text())
    pins = {'dms-greeter' if k == 'greeter' else k: v
            for k, v in release['compatibility'].items()
            if k in {'quickshell', 'labwc', 'uwsm', 'greeter'}}
    selection = [p for p in lines(stage / 'packages.txt') if p not in pins]
    selection += [f'{name}-{version}' for name, version in sorted(pins.items())]
    cache = acquisition_cache(stage) / 'dnf'
    cache.mkdir(exist_ok=True)
    run("dnf5", "-y", f"--installroot={root}", "--releasever=44",
        "--setopt=ip_resolve=4",
        "--setopt=retries=10", "--setopt=max_parallel_downloads=1",
        "--setopt=timeout=120",
        f"--setopt=reposdir={configs}", "--setopt=keepcache=True",
        f"--setopt=cachedir={cache}", f"--setopt=system_cachedir={cache}", '--refresh',
        f"--exclude={EXCLUDED}", "install", f'--store={work / "selected-transaction"}', "@core",
        *BOOT_PACKAGES, *selection, *staged)
    # Store the fresh solve without executing it. Export exactly its selected
    # objects, never all versions left in the persistent acquisition cache.
    for rpm_path in sorted((work / 'selected-transaction').rglob('*.rpm')) + staged:
        target = packages / rpm_path.name
        if target.exists() and digest(target) != digest(rpm_path):
            raise ValueError("RPM filename collision: " + rpm_path.name)
        shutil.copyfile(rpm_path, target)
    inventory = rpm_inventory(sorted(packages.glob('*.rpm')))
    retain_rpm_objects(root, configs, cache, packages)
    for name, expected in pins.items():
        actual = inventory.get(name + ('.noarch' if name == 'uwsm' else '.x86_64'))
        version = (actual[0] + ':' if ':' in expected else '') + '-'.join(actual[1:]) if actual else None
        if version != expected:
            raise ValueError('Offline DMS compatibility tuple mismatch: ' + name)
    export_core_group(root, configs, offline / "comps.xml", cache)
    return verify_rpms(stage, work, offline, baseline)


def retain_rpm_objects(root, configs, cache, packages):
    """DNF --store bypasses keepcache; retain selected objects at DNF's own paths."""
    import libdnf5
    base = libdnf5.base.Base()
    base.load_config()
    config = base.get_config()
    config.get_installroot_option().set(str(root))
    config.get_reposdir_option().set([str(configs)])
    config.get_cachedir_option().set(str(cache))
    config.get_system_cachedir_option().set(str(cache))
    config.get_cacheonly_option().set('all')
    base.get_vars().set('releasever', '44')
    base.setup()
    base.get_repo_sack().create_repos_from_system_configuration()
    base.get_repo_sack().load_repos(libdnf5.repo.Repo.Type_AVAILABLE)
    for package in libdnf5.rpm.PackageQuery(base):
        source = packages / Path(package.get_location()).name
        if not source.is_file():
            continue
        target = Path(package.get_package_path())
        target.resolve().relative_to(cache.resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or digest(target) != digest(source):
            temporary = target.with_name(target.name + '.retaining')
            shutil.copyfile(source, temporary)
            temporary.replace(target)


def verify_flatpak_seed(seed, baseline):
    """A reviewed explicit input, never an ambient host installation/cache."""
    receipt = seed / 'seed.json'
    value = json.loads(receipt.read_text())
    if value.get('schema') != 'greyward.flatpak-seed/v1' or value.get('flatpaks') != baseline['flatpaks']:
        raise ValueError('Flatpak seed does not match the selected baseline')
    files = value.get('files', {})
    actual = {p.relative_to(seed).as_posix() for p in seed.rglob('*') if p.is_file() and p != receipt}
    if not files or set(files) != actual:
        raise ValueError('Flatpak seed inventory differs from its receipt')
    for name, expected in files.items():
        path = seed / name
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            raise ValueError('Flatpak seed contains a symlink')
        path.resolve().relative_to(seed.resolve())
        if digest(path) != expected:
            raise ValueError('Flatpak seed checksum mismatch: ' + name)
    repo = seed / '.ostree/repo'
    for item in baseline['flatpaks'].values():
        if (repo / 'refs/heads' / item['ref']).read_text().strip() != item['commit']:
            raise ValueError('Flatpak seed ref differs from selected commit')
    return digest(receipt)


def export_core_group(root, configs, destination, cache=None):
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
    config.get_cachedir_option().set(str(cache or root / "var/cache/libdnf5"))
    config.get_system_cachedir_option().set(str(cache or root / "var/cache/libdnf5"))
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
    # DMS is a local RPM in the transaction closure, not a second archive install.
    release = json.loads((stage / "dms-release.json").read_text())
    if release["schema"] != "greyward.dms-release/v1":
        raise ValueError("Invalid DMS release manifest")
    runtimes = list((stage / "rpms").glob("greyward-dms-*.rpm"))
    if len(runtimes) != 1:
        raise ValueError("Exactly one packaged DMS runtime is required")
    sources = (stage / "zsh/sources.env").read_text()
    vendor = offline / "zsh-vendor"
    vendor.mkdir()
    for name in ("GREYWARD_OH_MY_ZSH", "GREYWARD_POWERLEVEL10K"):
        ref, url = pinned(sources, name + "_REF"), pinned(sources, name + "_REPO")
        if not re.fullmatch("[0-9a-f]{40}", ref) or not url.startswith("https://github.com/"):
            raise ValueError("Invalid shell source pin")
        source_cache = acquisition_cache(stage) / 'sources'
        source_cache.mkdir(exist_ok=True)
        key = hashlib.sha256((url + '\n' + ref).encode()).hexdigest()
        cached = source_cache / key
        if not cached.exists():
            with tempfile.TemporaryDirectory(prefix='fetch-', dir=source_cache) as temporary:
                checkout = Path(temporary) / 'repo'
                run('git', 'init', '--bare', checkout)
                run('git', '-C', checkout, 'fetch', '--depth=1', url, ref)
                run('git', '-C', checkout, 'update-ref', 'refs/heads/greyward', 'FETCH_HEAD')
                run('git', '-C', checkout, 'fsck', '--strict')
                checkout.rename(cached)
        if run('git', '-C', cached, 'rev-parse', 'refs/heads/greyward', capture=True) != ref:
            raise ValueError('Corrupt cached shell source pin')
        run('git', '-C', cached, 'fsck', '--strict')
        destination = vendor / ref
        shutil.copytree(cached, destination)
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
                cache = source_cache / ('gitstatus-' + ref)
                cache.mkdir(exist_ok=True)
                env = dict(os.environ, GITSTATUS_CACHE_DIR=str(cache))
                if not any(cache.iterdir()):
                    run("sh", tree / "gitstatus/install", "-f", "-s", "linux", "-m", "x86_64", env=env)
                run("unshare", "--net", "sh", tree / "gitstatus/install", "-n", "-s", "linux", "-m", "x86_64", env=env)
                shutil.copytree(cache, offline / 'gitstatus')
    (vendor / "required").touch()


def flatpak_env(path, reuse=False):
    path.mkdir(parents=True, exist_ok=reuse)
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
    seed_path = os.environ.get('GREYWARD_FLATPAK_SEED')
    if seed_path:
        seed = Path(seed_path).resolve(strict=True)
        seed_digest = verify_flatpak_seed(seed, baseline)
        cached = acquisition_cache(stage) / 'flatpak-seeds' / seed_digest
        if not cached.exists():
            cached.parent.mkdir(exist_ok=True)
            shutil.copytree(seed, cached)
        if verify_flatpak_seed(cached, baseline) != seed_digest:
            raise ValueError('Cached Flatpak seed receipt differs from the selected input')
        (offline / 'flatpak-seed-receipt.json').write_text(json.dumps({
            'schema': 'greyward.flatpak-seed-input/v1', 'receipt_sha256': seed_digest,
            'flatpaks': baseline['flatpaks'],
        }, indent=2) + '\n')
        destination = offline / 'flatpak'
        destination.mkdir()
        shutil.copytree(cached / '.ostree', destination / '.ostree')
        refs = [item['ref'] for item in baseline['flatpaks'].values()]
        finish_flatpak_verification(stage, work, offline, baseline, refs)
        return
    source_env = flatpak_env(acquisition_cache(stage) / 'flatpak-source', reuse=True)
    run("flatpak", "--user", "config", "--set", "languages", "*", env=source_env)
    run("flatpak", "--user", "remote-add", '--if-not-exists', "--from", "flathub", remote, env=source_env)
    run("flatpak", "--user", "remote-modify", "--collection-id=org.flathub.Stable", "flathub", env=source_env)
    origin = 'flathub'
    refs = []
    for item in baseline["flatpaks"].values():
        ref, commit = item["ref"], item["commit"]
        present = subprocess.run(['flatpak', '--user', 'info', '--show-commit', ref],
                                 env=source_env, capture_output=True, text=True)
        if present.returncode != 0 or present.stdout.strip() != commit:
            run("flatpak", "--user", "install", "--noninteractive", '--or-update', origin, ref, env=source_env)
            if run('flatpak', '--user', 'info', '--show-commit', ref, env=source_env, capture=True) != commit:
                run("flatpak", "--user", "update", "--noninteractive", f"--commit={commit}", ref, env=source_env)
        # An older selected app commit can use an older runtime branch than
        # today's app. Updating to a commit does not install that runtime.
        runtime = run("flatpak", "--user", "info", "--show-runtime", ref, env=source_env, capture=True)
        present_runtime = subprocess.run(['flatpak', '--user', 'info', 'runtime/' + runtime],
                                         env=source_env, capture_output=True)
        if present_runtime.returncode != 0:
            run("flatpak", "--user", "install", "--noninteractive", origin, "runtime/" + runtime, env=source_env)
        refs.append(ref)
    destination = offline / "flatpak"
    destination.mkdir()
    run("flatpak", "--user", "create-usb", destination, *refs, env=source_env)
    repo = destination / ".ostree/repo"
    prepare_sideload_repo(repo, refs)
    finish_flatpak_verification(stage, work, offline, baseline, refs)


def finish_flatpak_verification(stage, work, offline, baseline, refs):
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
    import fcntl
    cache = acquisition_cache(stage)
    lock = (cache / '.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX)
    before = cache_inventory(cache)
    received_before = received_bytes()
    timings = {}
    try:
        with tempfile.TemporaryDirectory(prefix=".offline-build-", dir=stage.parent) as temporary:
            work = Path(temporary)
            started = time.monotonic(); inventory = build_rpms(stage, work, offline, baseline)
            timings['rpm_acquire_and_verify_seconds'] = time.monotonic() - started
            started = time.monotonic(); build_sources(stage, offline)
            timings['source_acquire_seconds'] = time.monotonic() - started
            started = time.monotonic(); build_flatpaks(stage, work, offline, baseline)
            timings['flatpak_acquire_and_verify_seconds'] = time.monotonic() - started
        after = cache_inventory(cache)
        (offline / 'acquisition-metrics.json').write_text(json.dumps({
            'timings': timings, 'cache_bytes_before': sum(before.values()),
            'cache_bytes_after': sum(after.values()),
            'new_object_bytes': sum(size for name, size in after.items() if name not in before),
            'builder_received_bytes': received_bytes() - received_before,
            'note': 'Object bytes are retained cache growth. Interface bytes include metadata and concurrent builder traffic.',
        }, indent=2) + '\n')
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
