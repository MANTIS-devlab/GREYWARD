#!/usr/bin/env python3
"""Offline, exact-preimage DMS shell assembly. Never modifies upstream backend."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_receipt(root):
    files = {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}
    digest = hashlib.sha256(''.join(f'{name}\0{value}\n' for name, value in sorted(files.items())).encode()).hexdigest()
    return files, digest


def extract(archive, destination):
    with tarfile.open(archive) as stream:
        # Python's data filter rejects traversal, escaping links and special files.
        stream.extractall(destination, filter='data')


def apply_exact(root, text):
    """Require exact hunk positions and bytes: no offsets, fuzz or conflict repair."""
    touched = []
    for section in re.split(r'(?m)^--- a/quickshell/dms/', text)[1:]:
        lines = section.splitlines(keepends=True)
        name = lines[0].strip()
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name or lines[1].strip() != '+++ b/quickshell/dms/' + name:
            raise ValueError('Unsafe or mismatched patch path')
        target = root / name
        original = target.read_bytes().decode().splitlines(keepends=True)
        output, cursor = [], 0
        hunks = list(re.finditer(r'(?m)^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', section))
        if not hunks:
            raise ValueError('Patch has no hunks')
        for i, match in enumerate(hunks):
            entries = section[match.end():hunks[i+1].start() if i+1 < len(hunks) else len(section)].splitlines(keepends=True)
            if any(x[:1] not in {' ', '+', '-'} for x in entries):
                raise ValueError('Unsupported patch entry')
            old = [x[1:] for x in entries if x[0] in ' -']
            new = [x[1:] for x in entries if x[0] in ' +']
            start = int(match[1]) - (1 if old else 0)
            if len(old) != int(match[2] or 1) or len(new) != int(match[4] or 1):
                raise ValueError('Hunk length mismatch')
            if start < cursor or original[start:start+len(old)] != old:
                raise ValueError(f'Changed preimage/hunk position: {name}:{start+1}')
            output.extend(original[cursor:start]); output.extend(new)
            cursor = start + len(old)
        output.extend(original[cursor:])
        target.write_bytes(''.join(output).encode())
        touched.append(name)
    if not touched:
        raise ValueError('Empty/unrecognized patch')
    return touched


def assemble(manifest, source, vendor, patches, output):
    release = json.loads(Path(manifest).read_text())
    if release['schema'] != 'greyward.dms-release/v1':
        raise ValueError('Unknown release schema')
    if Path('/usr/bin/rpm').exists():
        for package, expected in release['build']['requiredPackages'].items():
            actual = subprocess.check_output(['/usr/bin/rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', package], text=True)
            if actual != expected:
                raise ValueError(f'Unpinned Fedora build input: {package} {actual}')
    for name, archive in [('source', source), ('vendor', vendor)]:
        if sha(archive) != release['inputs'][name]['sha256']:
            raise ValueError(f'{name} archive checksum mismatch')
    if output.exists():
        raise ValueError('Assembly output must be new')
    output.mkdir(parents=True)
    extract(source, output / 'source')
    extract(vendor, output / 'vendor')
    upstream = output / 'source' / release['inputs']['source']['root']
    core = output / 'vendor' / release['inputs']['vendor']['root']
    # Vendored release must have the same backend sources as the full archive.
    for folder in ('cmd', 'internal', 'pkg'):
        def inventory(base):
            return {p.relative_to(base).as_posix(): sha(p) for p in (base / folder).rglob('*')
                    if p.is_file() and 'shellembed/dist' not in p.as_posix()}
        if inventory(upstream / 'core') != inventory(core):
            raise ValueError(f'Backend source inventory/content mismatch: {folder}')
    module = (core / 'go.mod').read_text()
    if release['dankgo'] not in module or f'go {release["build"]["minimumGo"]}' not in module:
        raise ValueError('Go/dependency pin mismatch')
    shell = output / 'shell'
    shutil.copytree(upstream / 'quickshell', shell, ignore=shutil.ignore_patterns('.qmlls.ini', '.git'))
    changelog = (shell / 'Services/ChangelogService.qml').read_text()
    if 'currentVersion: "1.6"' not in changelog or '"/.changelog-"' not in changelog:
        raise ValueError('Changelog migration marker contract changed')
    expected = {item['file'] for item in release['patches']}
    if {p.name for p in patches.glob('*.patch')} != expected:
        raise ValueError('Unlisted or missing patch')
    touched = set()
    for item in release['patches']:
        patch = patches / item['file']
        if sha(patch) != item['sha256']:
            raise ValueError(f'Patch digest mismatch: {patch.name}')
        for name, digest in item['preimages'].items():
            if sha(shell / name) != digest:
                raise ValueError(f'Changed preimage: {name}')
        changed = apply_exact(shell, patch.read_bytes().decode())
        if set(changed) != set(item['preimages']):
            raise ValueError('Patch file inventory mismatch')
        touched.update(changed)
    files, digest = tree_receipt(shell)
    counts = {'qmlFiles': sum(name.endswith('.qml') and not name.startswith('DankCommon/') for name in files),
              'commonQmlFiles': sum(name.startswith('DankCommon/') and name.endswith('.qml') for name in files),
              'commonFiles': sum(name.startswith('DankCommon/') for name in files)}
    if any(release['shell'].get(key) != value for key, value in counts.items()):
        raise ValueError('Inherited shell file counts mismatch')
    if digest != release['shell']['sha256'] or len(touched) != release['shell']['patchedFiles']:
        raise ValueError('Assembled shell receipt mismatch')
    receipt = dict(release, shellFiles=files)
    (output / 'release.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return upstream, core, shell


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('manifest', 'source', 'vendor', 'patches', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assemble(args.manifest, args.source, args.vendor, args.patches, args.output)
