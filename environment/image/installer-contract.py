#!/usr/bin/env python3
"""Check the proven interactive installer boundary on composed media."""
import argparse
import configparser
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import tempfile

BRANDING = (
    'etc/anaconda/profile.d/greyward.conf',
    'usr/share/anaconda/pixmaps/greyward-anaconda.css',
    'usr/share/anaconda/pixmaps/greyward-anaconda-logo.png',
)
BOOT_CONFIGS = ('EFI/BOOT/grub.cfg', 'EFI/BOOT/BOOT.conf', 'boot/grub2/grub.cfg')
LABEL = 'GREYWARD-INSTALLER-44'


def archive_files(compressed):
    """Read newc members without extracting archive paths or symlinks."""
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError('Oversized installer branding archive')
    files = {}
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        if header[:6] != b'070701':
            raise ValueError('Invalid newc installer branding archive')
        fields = [int(header[6 + n * 8:14 + n * 8], 16) for n in range(13)]
        mode, size, name_size = fields[1], fields[6], fields[11]
        name_end = offset + 110 + name_size
        if name_size < 1 or name_end > len(data) or data[name_end - 1] != 0:
            raise ValueError('Truncated archive member name')
        name = data[offset + 110:name_end - 1].decode('utf-8')
        start = (name_end + 3) & ~3
        end = start + size
        if end > len(data):
            raise ValueError('Truncated archive member')
        if name == 'TRAILER!!!':
            return files
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or name in files:
            raise ValueError('Unsafe or duplicate archive member')
        if not stat.S_ISREG(mode):
            raise ValueError('Unexpected non-file branding member')
        files[name] = data[start:end]
        offset = (end + 3) & ~3
    raise ValueError('Missing archive trailer')


def validate(installer, configs, branding, expected):
    failures = []
    # The native Anaconda preamble owns the interactive pages. No replacement
    # account or storage implementation is introduced here.
    commands = []
    for line in installer.splitlines():
        line = line.strip()
        if line.startswith('%post'):
            break
        tokens = shlex.split(line, comments=True)
        if tokens:
            commands.append(tokens)
    for forbidden in ('user', 'rootpw', 'autostep', '%pre', 'part', 'partition',
                      'logvol', 'volgroup', 'raid', 'reqpart', 'ignoredisk'):
        if any(c[0] == forbidden for c in commands):
            failures.append('Installer interactions preseeded or bypassed: ' + forbidden)
    for required in (['graphical'], ['cdrom'], ['zerombr'],
                     ['clearpart', '--all', '--initlabel'],
                     ['autopart', '--type=btrfs', '--encrypted'], ['reboot', '--eject'],
                     ['%include', '/run/install/repo/greyward/production/offline/installer-packages.ks']):
        if commands.count(required) != 1:
            failures.append('Known-good installer command changed: ' + ' '.join(required))
    for name, config in configs.items():
        kernels = [shlex.split(line) for line in config.splitlines()
                   if re.match(r'^\s*linux(?:efi)?\s', line)]
        if not kernels:
            failures.append('No installer kernel entry in ' + name)
        if not re.search(r'set\s+default=["\']?0["\']?', config):
            failures.append('Default installer entry changed in ' + name)
        for args in kernels:
            for key, value in (
                ('inst.stage2', 'hd:LABEL=' + LABEL),
                ('inst.ks', 'hd:LABEL=' + LABEL + ':/installer.ks'),
                ('inst.updates', 'hd:LABEL=' + LABEL + ':/updates.img'),
                ('inst.profile', 'greyward'),
            ):
                actual = [a for a in args if a.startswith(key + '=')]
                if actual != [key + '=' + value]:
                    failures.append('Wrong ' + key + ' routing in ' + name)
            if 'rd.plymouth=0' in args or 'plymouth.enable=0' in args:
                failures.append('GREYWARD LUKS presentation disabled in ' + name)
    if set(branding) != set(BRANDING):
        failures.append('Missing or unexpected Anaconda customization members')
    for name in BRANDING:
        if name not in branding or branding[name] != expected.get(name):
            failures.append('Anaconda customization differs from selected branding RPM: ' + name)
    if BRANDING[0] in branding:
        profile = configparser.ConfigParser()
        profile.read_string(branding[BRANDING[0]].decode('utf-8'))
        if profile.get('Profile', 'profile_id', fallback='') != 'greyward':
            failures.append('GREYWARD Anaconda profile missing')
        if profile.get('Profile', 'base_profile', fallback='') != 'fedora':
            failures.append('Native Fedora installer profile changed')
        for setting in ('hidden_spokes', 'hidden_webui_pages'):
            if profile.get('User Interface', setting, fallback=None) != '':
                failures.append('Native interactive pages suppressed: ' + setting)
    if failures:
        raise ValueError('\n'.join(failures))
    return {
        'state': 'PASS',
        'scope': 'Composed-media contract; actual interactive/install acceptance remains separate.',
        'boot_configs': sorted(configs),
        'branding_sha256': {p: hashlib.sha256(branding[p]).hexdigest() for p in BRANDING},
    }


def inspect_iso(iso, branding_root):
    with tempfile.TemporaryDirectory(prefix='greyward-installer-contract-') as directory:
        root = Path(directory)
        sources = ('installer.ks', 'updates.img') + BOOT_CONFIGS
        command = ['xorriso', '-osirrox', 'on', '-indev', str(iso)]
        for source in sources:
            destination = root / source
            destination.parent.mkdir(parents=True, exist_ok=True)
            command.extend(['-extract', '/' + source, str(destination)])
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        report = subprocess.check_output(
            ['xorriso', '-indev', str(iso), '-report_el_torito', 'plain'],
            text=True, stderr=subprocess.DEVNULL,
        )
        entries = [line.split() for line in report.splitlines()
                   if line.startswith('El Torito boot img :') and ' UEFI ' in line]
        if len(entries) != 1:
            raise ValueError('Expected one bootable EFI image')
        # Fedora's EFI FAT image is an appended partition, outside the ISO tree.
        # Inspect its real boot configuration as well as the Rock Ridge copies.
        lba = int(entries[0][-1])
        efi_config = root / 'embedded-efi-grub.cfg'
        subprocess.run(
            ['mcopy', '-i', str(iso) + '@@' + str(lba * 2048),
             '::/EFI/BOOT/grub.cfg', str(efi_config)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        configs = {p: (root / p).read_text() for p in BOOT_CONFIGS}
        configs['embedded-efi/grub.cfg'] = efi_config.read_text()
        return validate(
            (root / 'installer.ks').read_text(),
            configs,
            archive_files((root / 'updates.img').read_bytes()),
            {p: (branding_root / p).read_bytes() for p in BRANDING},
        )


if __name__ == '__main__':
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--branding-root', type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(inspect_iso(arguments.iso, arguments.branding_root), indent=2))
