#!/usr/bin/env python3
"""Replace Lorax's stock x86 menu while preserving its firmware setup."""
import argparse
from pathlib import Path
import subprocess
import tempfile

BOOT_CONFIGS = ('EFI/BOOT/grub.cfg', 'EFI/BOOT/BOOT.conf', 'boot/grub2/grub.cfg')
MENU = (
    ('Install GREYWARD', 'quiet'),
    ('Verify media and install GREYWARD', 'rd.live.check quiet'),
    ('Install GREYWARD with diagnostic logs', 'loglevel=7 inst.loglevel=debug'),
)
MARKER = '### BEGIN /etc/grub.d/10_linux ###'


def rewrite(config):
    header, marker, _ = config.partition(MARKER)
    if not marker or header.count('set default="1"') != 1:
        raise ValueError('Unexpected Fedora GRUB header')
    search = next(line for line in header.splitlines()
                  if line.startswith('search --no-floppy --set=root -l '))
    label = search.split("'")[1]
    if label != 'Fedora-E-dvd-x86_64-44':
        raise ValueError('Unexpected Fedora installer volume label')
    header = header.replace('set default="1"', 'set default="0"')
    entries = [
        f"menuentry '{title}' {{\n"
        f"  linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL={label} {options}\n"
        "  initrd /images/pxeboot/initrd.img\n"
        "}\n"
        for title, options in MENU
    ]
    return header + marker + '\n' + ''.join(entries)


def compose(source, output):
    with tempfile.TemporaryDirectory(prefix='greyward-menu-') as directory:
        root = Path(directory)
        extract = ['xorriso', '-osirrox', 'on', '-indev', str(source)]
        remap = ['xorriso', '-indev', str(source), '-outdev', str(output),
                 '-boot_image', 'any', 'replay']
        for index, path in enumerate(BOOT_CONFIGS):
            local = root / str(index)
            extract.extend(['-extract', '/' + path, str(local)])
            remap.extend(['-map', str(local), '/' + path])
        subprocess.run(extract, check=True)
        for local in root.iterdir():
            local.write_text(rewrite(local.read_text()))
        subprocess.run(remap, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_iso', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    compose(args.base_iso, args.output)
