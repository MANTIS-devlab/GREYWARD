#!/usr/bin/env python3
"""Repackage one locked DMS RPM with closed artwork or ordinary-plugin changes.

No compiler input or executable changes. Normal source builds remain available;
this path requires the predecessor RPM recorded in the canonical manifest.
Artwork changes require protected-profile migration. --plugins-only preserves
the complete executable/shell payload and the existing protected generation.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(files):
    return hashlib.sha256(''.join(f'{name}\0{value}\n' for name, value in sorted(files.items())).encode()).hexdigest()


def update_plugins(payload, manifest, receipt, source_root=ROOT):
    """Refuse stale sources, undeclared deltas and changes outside visual adapters."""
    pin = manifest['build']['pluginUpdate']
    allowed = {'greywardSecure/SecureWidget.qml', 'greywardSecure/StatusCard.qml',
               'greywardSecure/plugin.json'}
    old = receipt['firstPartyFiles']
    if (old != receipt['firstPartySources'] or tree_digest(old) != pin['baseFirstPartySha256']
            or set(pin['changedFirstPartyFiles']) != allowed
            or pin['requiresProtectedMigration'] is not False):
        raise ValueError('Invalid ordinary-plugin predecessor or change scope.')
    plugins = source_root / manifest['firstPartyDirectory']
    new = {p.relative_to(plugins).as_posix(): digest(p)
           for p in plugins.rglob('*') if p.is_file()}
    if (new != manifest['firstPartySources'] or set(old) != set(new)
            or {name for name in new if old[name] != new[name]} != allowed):
        raise ValueError('Changed first-party sources exceed the reviewed visual update.')
    installed = payload / 'etc/xdg/quickshell/dms-plugins'
    actual = {p.relative_to(installed).as_posix(): digest(p)
              for p in installed.rglob('*') if p.is_file()}
    if actual != old:
        raise ValueError('Predecessor plugin payload mismatch.')
    for name in allowed:
        shutil.copyfile(plugins / name, installed / name)
    receipt['firstPartyFiles'] = new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_rpm', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--plugins-only', action='store_true',
                        help='Use the closed ordinary-plugin update pin; preserve the protected shell.')
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error('Build only as an unprivileged account.')
    manifest = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
    pin = manifest['build']['pluginUpdate' if args.plugins_only else 'artworkUpdate']
    if digest(args.base_rpm) != pin['baseRpmSha256']:
        parser.error('Predecessor RPM does not match the reviewed artifact.')
    if subprocess.check_output(['rpm', '-qp', '--scripts', str(args.base_rpm)], text=True).strip():
        parser.error('Predecessor unexpectedly contains scriptlets.')
    if args.plugins_only:
        identity = subprocess.check_output(['rpm', '-qp', '--qf', '%{NEVRA}', str(args.base_rpm)], text=True)
        if identity != pin['basePackage'] or not re.fullmatch(r'greyward-dms-[0-9.]+-[0-9.]+\.fc44\.x86_64', identity):
            parser.error('Predecessor package identity mismatch.')
    args.output.mkdir()  # Never reuse a prior or partial build.
    out = args.output.resolve()
    for name in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
        (out / name).mkdir()
    payload = out / 'SOURCES/payload'
    payload.mkdir()
    stream = subprocess.Popen(['rpm2cpio', str(args.base_rpm.resolve())], stdout=subprocess.PIPE)
    try:
        subprocess.run(['cpio', '-idm', '--quiet', '--no-absolute-filenames'], cwd=payload,
                       stdin=stream.stdout, check=True)
    finally:
        stream.stdout.close()
    if stream.wait() != 0:
        raise ValueError('Cannot read locked RPM.')
    runtime = payload / ('usr/lib/greyward/dms/' + manifest['releaseId'])
    receipt = json.loads((runtime / 'release.json').read_text())
    for key in ('releaseId', 'dms', 'dankCommon', 'dankgo', 'inputs', 'patches', 'firstPartySources', 'compatibility'):
        if key == 'firstPartySources' and args.plugins_only:
            continue
        if receipt[key] != manifest[key]:
            raise ValueError('Unreviewed predecessor change: ' + key)
    files = {p.relative_to(runtime / 'shell').as_posix(): digest(p)
             for p in (runtime / 'shell').rglob('*') if p.is_file()}
    if (files != receipt['shellFiles'] or tree_digest(files) != pin['baseShellSha256']):
        raise ValueError('Predecessor shell readback mismatch.')
    expected = manifest['build']['packageOnlyRuntime']
    for key, path in (
        ('binarySha256', runtime / 'bin/dms'),
        ('usbguardApprovalSha256', payload / 'usr/libexec/greyward-usbguard-approval'),
        ('usbguardAuthApprovalSha256', payload / 'usr/libexec/greyward-usbguard-auth-approval'),
    ):
        if digest(path) != expected[key]:
            raise ValueError('Executable changed: ' + key)
    if args.plugins_only:
        update_plugins(payload, manifest, receipt)
    else:
        if pin['changedShellFiles'] != ['assets/greyward-settings.svg']:
            raise ValueError('Only the reviewed Settings artwork may change.')
        asset = ROOT / 'branding/source/greyward-settings.svg'
        addition = ROOT / 'environment/session/dms-2.0/assets/greyward-settings.svg'
        if digest(asset) != digest(addition):
            raise ValueError('Canonical Settings artwork drift.')
        shutil.copyfile(asset, runtime / 'shell/assets/greyward-settings.svg')
        files['assets/greyward-settings.svg'] = digest(asset)
    if (tree_digest(files) != manifest['shell']['sha256'] or
            files['assets/greyward-settings.svg'] != manifest['shellAdditions']['files']['assets/greyward-settings.svg']):
        raise ValueError('Successor shell readback mismatch.')
    for name, sha in manifest['firstPartySources'].items():
        if digest(payload / 'etc/xdg/quickshell/dms-plugins' / name) != sha:
            raise ValueError('Plugin mismatch: ' + name)
    receipt.update(manifest)
    receipt['shellFiles'] = files
    (runtime / 'release.json').write_text(json.dumps(receipt, indent=2) + '\n')
    requirements = subprocess.check_output(['rpm', '-qp', '--requires', str(args.base_rpm)], text=True).splitlines()
    requirements = [r for r in requirements if not r.startswith(('rpmlib(', 'config('))]
    version, release = manifest['dms']['tag'][1:], manifest['build']['rpmRelease']
    spec = f'''%global __os_install_post %{{nil}}
Name: greyward-dms
Version: {version}
Release: {release}%{{?dist}}
Summary: GREYWARD pinned DMS desktop with coordinated Settings artwork
License: GPL-3.0-only AND MIT
AutoReqProv: no
Provides: greyward-dms = {version}-7%{{?dist}}
'''
    spec += ''.join('Requires: ' + value + '\n' for value in requirements)
    if args.plugins_only:
        predecessor = pin['basePackage'].removeprefix('greyward-dms-').removesuffix('.x86_64')
        spec += 'Provides: greyward-dms = ' + predecessor + '\n'
    spec += '''%description
Validated predecessor executables and shell, with the single manifest-locked
Settings SVG update. Activate through the protected-profile migration.
%prep
%build
%install
mkdir -p %{buildroot}
cp -a %{_sourcedir}/payload/. %{buildroot}/
%files
%defattr(-,root,root,-)
%config /etc/greyward/dms-release
/usr/bin/dms
/usr/libexec/greyward-dms-verify
/usr/libexec/greyward-usbguard-approval
/usr/libexec/greyward-usbguard-auth-approval
/etc/xdg/quickshell/dms-plugins
'''
    spec += '/usr/lib/greyward/dms/' + manifest['releaseId'] + '\n'
    if args.plugins_only:
        spec = spec.replace('with coordinated Settings artwork', 'with accepted ordinary-plugin presentation')
        spec = spec.replace('Validated predecessor executables and shell, with the single manifest-locked\nSettings SVG update. Activate through the protected-profile migration.',
                            'Validated predecessor executables and protected shell, with manifest-locked\nordinary Security Center presentation. No protected-profile migration.')
    path = out / 'SPECS/greyward-dms.spec'
    path.write_text(spec)
    temporary = out / 'tmp'
    temporary.mkdir(mode=0o700)
    subprocess.run(['rpmbuild', '--define', '_topdir ' + str(out),
                    '--define', '_tmppath ' + str(temporary), '-bb', str(path)], check=True)


if __name__ == '__main__':
    main()
