#!/usr/bin/python3 -I
"""Validate real Plymouth syntax, optionally checking installed initramfs copies.

Does not start a daemon, open a display, or interact with password input.
"""
import argparse
import ctypes
import hashlib
from pathlib import Path
import subprocess
import sys


THEME = Path('/usr/share/plymouth/themes/greyward')


def validate_script(path):
    data = path.read_bytes()
    if not data or b'\r' in data or b'\x00' in data:
        raise ValueError(f'{path}: empty script, CR/CRLF or NUL bytes are forbidden')
    data.decode('utf-8', errors='strict')
    plugins = [Path('/usr/lib64/plymouth/script.so'), Path('/usr/lib/plymouth/script.so')]
    plugin = next((p for p in plugins if p.is_file()), None)
    if plugin is None:
        raise ValueError('Plymouth script plugin is missing')
    library = ctypes.CDLL(str(plugin))
    library.script_parse_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.script_parse_string.restype = ctypes.c_void_p
    library.script_parse_op_free.argtypes = [ctypes.c_void_p]
    parsed = library.script_parse_string(data, str(path).encode())
    if not parsed:
        raise ValueError(f'{path}: native Plymouth parser rejected the theme')
    library.script_parse_op_free(parsed)
    return plugin


def read_image(image, name):
    return subprocess.check_output(['lsinitrd', '-f', name.lstrip('/'), str(image)])


def validate_image(image, plugin):
    if not image.is_file():
        raise ValueError(f'missing initramfs: {image}')
    listing = subprocess.check_output(['lsinitrd', str(image)], text=True)
    for required in (str(plugin).lstrip('/'),
                     str(plugin.parent / 'renderers/drm.so').lstrip('/'),
                     str(plugin.parent / 'renderers/frame-buffer.so').lstrip('/'),
                     str(plugin.parent / 'label-freetype.so').lstrip('/'),
                     'usr/share/fonts/Plymouth.ttf'):
        if not any(line.endswith(' ' + required) or (' ' + required + ' -> ') in line
                   for line in listing.splitlines()):
            raise ValueError(f'{image.name}: missing Plymouth dependency {required}')
    for name in ('greyward.script', 'greyward.plymouth', 'greyward-symbol-256.png'):
        source = THEME / name
        if read_image(image, str(source)) != source.read_bytes():
            raise ValueError(f'{image.name}: stale or invalid {name}; rebuild this initramfs')
    conf = read_image(image, '/etc/plymouth/plymouthd.conf').decode('utf-8')
    import configparser
    config = configparser.ConfigParser()
    config.read_string(conf)
    if config.get('Daemon', 'Theme', fallback='') != 'greyward':
        raise ValueError(f'{image.name}: GREYWARD is not the selected initramfs theme')
    print(f'OK {image.name}: theme bytes, fonts and graphical plugins')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script', type=Path, default=THEME / 'greyward.script')
    parser.add_argument('--initramfs', type=Path, action='append', default=[])
    args = parser.parse_args()
    try:
        plugin = validate_script(args.script)
        print(f'OK Plymouth parser: {hashlib.sha256(args.script.read_bytes()).hexdigest()}')
        for image in args.initramfs:
            validate_image(image, plugin)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'GREYWARD boot theme validation failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
