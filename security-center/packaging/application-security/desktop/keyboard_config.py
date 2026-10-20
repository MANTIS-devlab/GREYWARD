#!/usr/bin/python3 -I
"""Read and validate the keyboard selected for the installed system.

Anaconda/systemd-localed stores the XKB selection in the system-keyboard
InputClass. GREYWARD copies that data into root-owned session inputs; it never
sources a user-writable environment file for a protected compositor.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import tomllib

try:
    import pwd
except ImportError:  # The parser is also exercised by repository checks on Windows.
    pwd = None

SCHEMA = 'greyward.keyboard-settings/v1'
LOCAL_CONFIG = Path('/etc/X11/xorg.conf.d/00-keyboard.conf')
SETTINGS_FILE = Path('/etc/greyward/keyboard.json')
ENV_FILE = Path('/etc/greyward/keyboard.env')
GREETER_CONFIG = Path('/etc/greetd/config.toml')
SKEL_ENV = Path('/etc/skel/.config/labwc/environment')
PROTECTED_KEYBOARD = Path('/usr/lib/greyward/application-security/desktop/keyboard.json')
_MODEL = re.compile(r'[A-Za-z0-9_+-]{1,128}\Z')
_LAYOUT = re.compile(r'[A-Za-z0-9_+-]{1,64}(?:,[A-Za-z0-9_+-]{1,64})*\Z')
_VARIANT = re.compile(r'[A-Za-z0-9_+-]{0,64}(?:,[A-Za-z0-9_+-]{0,64})*\Z')
_OPTIONS = re.compile(r'[A-Za-z0-9_:,+-]{0,256}\Z')
_DEFAULT_ARRANGEMENTS = {
    'be': 'AZERTY',
    'ch': 'QWERTZ',
    'de': 'QWERTZ',
    'fr': 'AZERTY',
    'gb': 'QWERTY',
    'us': 'QWERTY',
}
_VARIANT_ARRANGEMENTS = {
    'azerty': 'AZERTY',
    'bepo': 'BÉPO',
    'colemak': 'COLEMAK',
    'dvorak': 'DVORAK',
    'latin9': 'AZERTY',
    'latin9_nodeadkeys': 'AZERTY',
    'nodeadkeys': 'AZERTY',
    'oss': 'AZERTY',
    'qwerty': 'QWERTY',
    'qwertz': 'QWERTZ',
}


def validate_settings(data):
    if not isinstance(data, dict) or data.get('schema') != SCHEMA:
        raise ValueError('Unsupported GREYWARD keyboard settings')
    model = data.get('model', 'pc105')
    layout = data.get('layout')
    variant = data.get('variant', '')
    options = data.get('options', '')
    if not isinstance(model, str) or not _MODEL.fullmatch(model):
        raise ValueError('Invalid XKB model')
    if not isinstance(layout, str) or not _LAYOUT.fullmatch(layout):
        raise ValueError('Invalid XKB layout')
    if not isinstance(variant, str) or not _VARIANT.fullmatch(variant):
        raise ValueError('Invalid XKB variant')
    if not isinstance(options, str) or not _OPTIONS.fullmatch(options):
        raise ValueError('Invalid XKB options')
    layouts = layout.split(',')
    variants = variant.split(',') if variant else []
    if variants and len(variants) > len(layouts):
        raise ValueError('XKB variants do not match the selected layouts')
    return {'schema': SCHEMA, 'model': model, 'layout': layout,
            'variant': variant, 'options': options}


def parse_localed_config(text):
    section = None
    section_type = None
    target_sections = 0
    settings = {}
    for original in text.splitlines():
        line = original.split('#', 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r'Section\s+"([^"]+)"', line, re.IGNORECASE)
        if match:
            if section == 'system-keyboard':
                raise ValueError('Nested system keyboard section')
            section = None
            section_type = match.group(1).casefold()
            continue
        if re.fullmatch(r'EndSection', line, re.IGNORECASE):
            section = None
            section_type = None
            continue
        if section is None:
            identifier = (section_type == 'inputclass' and re.fullmatch(
                r'Identifier\s+"system-keyboard"', line, re.IGNORECASE))
            if identifier:
                section = 'system-keyboard'
                target_sections += 1
            continue
        option = re.fullmatch(
            r'Option\s+"(XkbModel|XkbLayout|XkbVariant|XkbOptions)"\s+"([^"]*)"',
            line, re.IGNORECASE)
        if option:
            key = option.group(1).casefold()
            if key in settings:
                raise ValueError(f'Duplicate system keyboard option: {key}')
            settings[key] = option.group(2)
    if target_sections != 1:
        raise ValueError('Anaconda/systemd-localed keyboard record is missing or ambiguous')
    return validate_settings({
        'schema': SCHEMA,
        'model': settings.get('xkbmodel', 'pc105') or 'pc105',
        'layout': settings.get('xkblayout', ''),
        'variant': settings.get('xkbvariant', ''),
        'options': settings.get('xkboptions', ''),
    })


def _trusted_regular_file(path, *, maximum=65536):
    path = Path(path)
    for parent in (path, *path.parents):
        metadata = parent.lstat()
        if parent.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError(f'Keyboard input is not root-controlled: {parent}')
    metadata = path.stat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_size > maximum):
        raise ValueError(f'Unsafe keyboard input: {path}')
    return path.read_text(encoding='utf-8')


def installed_settings(path=LOCAL_CONFIG):
    return parse_localed_config(_trusted_regular_file(path))


def environment(settings):
    settings = validate_settings(settings)
    result = {
        'XKB_DEFAULT_MODEL': settings['model'],
        'XKB_DEFAULT_LAYOUT': settings['layout'],
    }
    if settings['variant']:
        result['XKB_DEFAULT_VARIANT'] = settings['variant']
    if settings['options']:
        result['XKB_DEFAULT_OPTIONS'] = settings['options']
    return result


def display_layout_label(settings):
    """Return a short, safe label for the keyboard layout shown in auth UI."""
    settings = validate_settings(settings)
    layouts = settings['layout'].split(',')
    variants = settings['variant'].split(',') if settings['variant'] else []
    labels = []
    for index, layout in enumerate(layouts):
        code = layout.upper()
        variant = variants[index].casefold() if index < len(variants) else ''
        arrangement = (_VARIANT_ARRANGEMENTS.get(variant)
                       or _DEFAULT_ARRANGEMENTS.get(layout.casefold()))
        labels.append(f'{code} · {arrangement}' if arrangement else code)
    label = ' / '.join(labels)
    return label[:48]


def canonical_json(settings):
    return (json.dumps(validate_settings(settings), sort_keys=True, indent=2) + '\n').encode()


def canonical_environment(settings):
    values = environment(settings)
    return ''.join(f'{key}={value}\n' for key, value in values.items()).encode()


def _atomic_root_write(path, content, mode=0o644):
    path = Path(path)
    parent = path.parent
    metadata = parent.lstat()
    if parent.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError(f'Unsafe GREYWARD keyboard settings directory: {parent}')
    if path.exists() or path.is_symlink():
        _trusted_regular_file(path)
    fd, temporary = tempfile.mkstemp(prefix='.keyboard-', dir=parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_installed_settings():
    if os.geteuid() != 0:
        raise PermissionError('Root is required to save installed keyboard settings')
    SETTINGS_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    settings = installed_settings()
    _atomic_root_write(SETTINGS_FILE, canonical_json(settings))
    _atomic_root_write(ENV_FILE, canonical_environment(settings))
    return settings


def load_saved_settings(path=SETTINGS_FILE):
    data = json.loads(_trusted_regular_file(path))
    return validate_settings(data)


def _env_file_values(path):
    values = {}
    for line in _trusted_regular_file(path).splitlines():
        if not line:
            continue
        key, separator, value = line.partition('=')
        if not separator or key in values or key not in {
                'XKB_DEFAULT_MODEL', 'XKB_DEFAULT_LAYOUT',
                'XKB_DEFAULT_VARIANT', 'XKB_DEFAULT_OPTIONS'}:
            raise ValueError('Invalid generated XKB environment file')
        values[key] = value
    return values


def verify_installed():
    expected = installed_settings()
    saved = load_saved_settings()
    if saved != expected:
        raise ValueError('Saved GREYWARD keyboard settings differ from Anaconda selection')
    expected_env = environment(expected)
    if _env_file_values(ENV_FILE) != expected_env:
        raise ValueError('GREYWARD XKB environment differs from Anaconda selection')

    config = tomllib.loads(_trusted_regular_file(GREETER_CONFIG))
    command = config.get('default_session', {}).get('command', '')
    words = shlex.split(command)
    supplied = {}
    for word in words:
        key, separator, value = word.partition('=')
        if separator and key.startswith('XKB_DEFAULT_'):
            supplied[key] = value
    if supplied != expected_env:
        raise ValueError('GREYWARD greeter XKB settings differ from Anaconda selection')

    if pwd is None:
        raise RuntimeError('Installed keyboard verification requires a POSIX account database')
    paths = [(SKEL_ENV, 0)]
    for account in pwd.getpwall():
        if account.pw_uid >= 1000 and account.pw_dir.startswith('/home/'):
            paths.append((Path(account.pw_dir) / '.config/labwc/environment',
                          account.pw_uid))
    for path, owner in paths:
        if owner:
            metadata = path.lstat()
            if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != owner or metadata.st_nlink != 1
                    or metadata.st_mode & 0o022 or metadata.st_size > 65536):
                raise ValueError(f'Unsafe Labwc user keyboard environment: {path}')
            content = path.read_text(encoding='utf-8')
        else:
            content = _trusted_regular_file(path)
        parsed = {}
        for line in content.splitlines():
            key, separator, value = line.partition('=')
            if separator and key in expected_env:
                parsed[key] = value
        if parsed != expected_env:
            raise ValueError(f'Labwc session XKB defaults differ from Anaconda selection: {path}')

    protected = validate_settings(json.loads(_trusted_regular_file(PROTECTED_KEYBOARD)))
    if protected != expected:
        raise ValueError('Protected Labwc XKB settings differ from Anaconda selection')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--write-installed', action='store_true')
    group.add_argument('--print-installed-json', action='store_true')
    group.add_argument('--verify-installed', action='store_true')
    options = parser.parse_args()
    if options.write_installed:
        print(json.dumps(write_installed_settings(), sort_keys=True))
    elif options.print_installed_json:
        print(canonical_json(installed_settings()).decode(), end='')
    else:
        print(json.dumps(verify_installed(), sort_keys=True))


if __name__ == '__main__':
    main()
