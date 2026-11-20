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
INSTALLER_UI = (
    'usr/lib64/python3.14/site-packages/pyanaconda/ui/gui/__init__.py',
    'usr/lib64/python3.14/site-packages/pyanaconda/ui/gui/greyward_keyboard.py',
    'usr/lib64/python3.14/site-packages/pyanaconda/ui/tui/__init__.py',
    'usr/lib64/python3.14/site-packages/pyanaconda/startup_utils.py',
)
UPDATES = BRANDING + INSTALLER_UI
BOOT_CONFIGS = ('EFI/BOOT/grub.cfg', 'EFI/BOOT/BOOT.conf', 'boot/grub2/grub.cfg')
LABEL = 'GREYWARD-INSTALLER-44'
MENU_ENTRIES = (
    ('Install GREYWARD', {'quiet'}),
    ('Verify media and install GREYWARD', {'rd.live.check', 'quiet'}),
    ('Install GREYWARD with diagnostic logs', {'loglevel=7', 'inst.loglevel=debug'}),
)
PACKAGE_SELECTION = 'greyward/production/offline/installer-packages.ks'


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


def validate(installer, configs, branding, expected, package_selection):
    failures = []
    # The native Anaconda preamble owns the interactive pages. No replacement
    # account or storage implementation is introduced here.
    commands = []
    preamble, _, scripts = installer.partition('%pre --erroronfail\n')
    if not scripts.startswith(
        "# Abort before storage UI if the installer overlay did not apply.\n"
        "set -eu\n"
        "gui=/usr/lib64/python3.14/site-packages/pyanaconda/ui/gui\n"
        "test -s \"$gui/greyward_keyboard.py\"\n"
        "grep -Fq 'if not confirm_keyboard(self.mainWindow._stack):' \"$gui/__init__.py\"\n"
        "grep -Fq 'GREYWARD requires the graphical keyboard confirmation' \"$gui/../tui/__init__.py\"\n"
        "%end\n"
    ) or installer.count('%pre ') != 1:
        failures.append('Missing or changed installer keyboard guard')
    for line in preamble.splitlines():
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
    if [c for c in commands if c[0] == 'lang'] != [['lang', 'en_US.UTF-8']]:
        failures.append('Initial installer language must be English (en_US.UTF-8)')
    if any(c[0] == 'keyboard' for c in commands):
        failures.append('Keyboard layout must remain interactive, not Kickstart-confirmed')
    # Hiding software selection is valid only with an explicit nonempty local
    # package selection. Full dependency closure is verified by build-offline.
    selection = [line.strip() for line in package_selection.splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
    if (not selection or selection[0] != '%packages --exclude-weakdeps'
            or selection[-1] != '%end'
            or selection.count('%end') != 1
            or not any(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]*', p)
                       for p in selection[1:-1])
            or any(p.startswith(('%', '@')) for p in selection[1:-1])):
        failures.append('Hidden software page requires explicit nonempty ISO-local packages')
    for name, config in configs.items():
        entries = re.findall(r"^menuentry '([^']+)' \{\n(.*?)^}", config, re.M | re.S)
        declared_entries = re.findall(r'^\s*(?:menuentry|submenu)\s', config, re.M)
        if ([title for title, _ in entries] != [title for title, _ in MENU_ENTRIES]
                or len(declared_entries) != len(MENU_ENTRIES)):
            failures.append('Unexpected boot menu entries in ' + name)
        kernels = []
        for (_, body), (_, expected_flags) in zip(entries, MENU_ENTRIES):
            commands = [shlex.split(line) for line in body.splitlines() if line.strip()]
            if (len(commands) != 2
                    or commands[0][:2] != ['linux', '/images/pxeboot/vmlinuz']
                    or commands[1] != ['initrd', '/images/pxeboot/initrd.img']):
                failures.append('Invalid kernel or initramfs entry in ' + name)
                continue
            actual_flags = set(commands[0]) & {
                'quiet', 'rd.live.check', 'loglevel=7', 'inst.loglevel=debug',
                'nomodeset', 'inst.rescue', 'inst.text', 'inst.cmdline',
            }
            if actual_flags != expected_flags:
                failures.append('Incorrect boot mode in ' + name)
            kernels.append(commands[0])
        if not re.search(r'set\s+default=["\']?0["\']?', config):
            failures.append('Default installer entry changed in ' + name)
        for args in kernels:
            if any(a.startswith(('inst.keymap=', 'vconsole.keymap=', 'rd.vconsole.keymap='))
                   for a in args):
                failures.append('Boot keymap must not bypass native keyboard selection in ' + name)
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
    if set(branding) != set(UPDATES):
        failures.append('Missing or unexpected Anaconda customization members')
    for name in UPDATES:
        if name not in branding or branding[name] != expected.get(name):
            failures.append('Anaconda customization differs from selected build input: ' + name)
    if BRANDING[0] in branding:
        profile = configparser.ConfigParser()
        profile.read_string(branding[BRANDING[0]].decode('utf-8'))
        if profile.get('Profile', 'profile_id', fallback='') != 'greyward':
            failures.append('GREYWARD Anaconda profile missing')
        if profile.get('Profile', 'base_profile', fallback='') != 'fedora':
            failures.append('Native Fedora installer profile changed')
        for setting, allowed in (
                ('hidden_spokes', ['SoftwareSelectionSpoke', 'KeyboardSpoke']),
                ('hidden_webui_pages', ['anaconda-screen-software-selection'])):
            if profile.get('User Interface', setting, fallback='').split() != allowed:
                failures.append('Unexpected native interactive pages suppressed: ' + setting)
        if profile.getboolean('Localization', 'use_geolocation', fallback=True):
            failures.append('Installer language/layout must not be inferred from GeoIP')
    if failures:
        raise ValueError('\n'.join(failures))
    return {
        'state': 'PASS',
        'scope': 'Composed-media contract; actual interactive/install acceptance remains separate.',
        'boot_configs': sorted(configs),
        'updates_sha256': {p: hashlib.sha256(branding[p]).hexdigest() for p in UPDATES},
    }


def inspect_iso(iso, branding_root):
    with tempfile.TemporaryDirectory(prefix='greyward-installer-contract-') as directory:
        root = Path(directory)
        digest_path = 'greyward/production/payload.sha256'
        sources = ('installer.ks', 'updates.img', PACKAGE_SELECTION, digest_path) + BOOT_CONFIGS
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
                   if line.startswith('El Torito boot img :')]
        if sorted(entry[6:8] for entry in entries) != [['BIOS', 'y'], ['UEFI', 'y']]:
            raise ValueError('Expected one bootable BIOS image and one bootable UEFI image')
        # Fedora's EFI FAT image is an appended partition, outside the ISO tree.
        # Inspect its real boot configuration as well as the Rock Ridge copies.
        lba = int(next(entry[-1] for entry in entries if entry[6] == 'UEFI'))
        efi_config = root / 'embedded-efi-grub.cfg'
        subprocess.run(
            ['mcopy', '-i', str(iso) + '@@' + str(lba * 2048),
             '::/EFI/BOOT/grub.cfg', str(efi_config)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        config_paths = {name: root / name for name in BOOT_CONFIGS}
        config_paths['embedded-efi/grub.cfg'] = efi_config
        configs = {}
        for name, path in config_paths.items():
            subprocess.run(['grub2-script-check', str(path)], check=True)
            configs[name] = path.read_text()
        installer = (root / 'installer.ks').read_text()
        payload_sha = hashlib.sha256((root / digest_path).read_bytes()).hexdigest()
        if re.findall(r"^expected_payload='([^']+)'$", installer, re.M) != [payload_sha]:
            raise ValueError('Installer media recovery digest does not match the embedded payload')
        return validate(
            installer,
            configs,
            archive_files((root / 'updates.img').read_bytes()),
            {p: (branding_root / p).read_bytes() for p in UPDATES},
            (root / PACKAGE_SELECTION).read_text(),
        )


if __name__ == '__main__':
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--branding-root', type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(inspect_iso(arguments.iso, arguments.branding_root), indent=2))
