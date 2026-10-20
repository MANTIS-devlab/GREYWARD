"""Unprivileged desktop application display catalog; never launches an entry.

Desktop names/icons are presentation, not authorization. The root policy service
still resolves and reviews the selected executable and user scope independently.
"""
import base64
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import threading
import time

_LIMIT = 256
_CACHE = None
_LOCK = threading.Lock()
_SEARCH_PATH = '/usr/local/bin:/usr/bin:/usr/sbin'
_RUNTIME = {'sh', 'bash', 'zsh', 'python', 'python3', 'node', 'java', 'ruby', 'perl', 'flatpak', 'bwrap', 'env'}


def launch_target(command):
    """Read a desktop command's executable only; never execute shell syntax."""
    try:
        args = shlex.split(command)
    except ValueError:
        return None, 'ambiguous'
    if not args:
        return None, 'ambiguous'
    if Path(args[0]).name == 'env':
        args = args[1:]
        while args and (args[0] == '--' or ('=' in args[0] and not args[0].startswith('-'))):
            args = args[1:]
    if not args or args[0].startswith(('-', '%')):
        return None, 'ambiguous'
    target = args[0]
    if Path(target).name in ('flatpak', 'bwrap'):
        return None, 'flatpak'
    if Path(target).name in _RUNTIME or Path(target).name.startswith(('python3.', 'python2.')):
        return None, 'shared_runtime'
    path = target if target.startswith('/') else shutil.which(target, path=_SEARCH_PATH)
    return path, None if path else 'unavailable'


def elf_target(path):
    try:
        resolved = Path(path).resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            return None
        with resolved.open('rb') as stream:
            return str(resolved) if stream.read(4) == b'\x7fELF' else None
    except (OSError, ValueError, TypeError):
        return None


def packaged_target(desktop, launcher):
    """Resolve packaged shell wrappers by a unique same-name ELF in that RPM.

    No shell interpretation, package-specific mapping, or generic interpreter
    scope. Multiple candidates remain unsupported rather than guessed.
    """
    if not desktop or not str(desktop).startswith('/usr/share/applications/'):
        return None
    try:
        result = subprocess.run(['/usr/bin/rpm', '-qf', '--qf', '[%{FILENAMES}\n]', str(desktop)],
                                capture_output=True, timeout=2, check=False)
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
            return None
        name = Path(launcher).name
        candidates = {value for value in (elf_target(p) for p in result.stdout.decode('utf-8', errors='replace').splitlines()
                                         if Path(p).name == name) if value}
        return next(iter(candidates)) if len(candidates) == 1 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def describe(info):
    path, reason = launch_target(info.get_commandline() or '')
    if getattr(info, 'get_string', lambda key: None)('X-Flatpak'):
        path, reason = None, 'flatpak'
    resolved = elf_target(path) if path else None
    if path and not resolved:
        resolved = packaged_target(getattr(info, 'get_filename', lambda: None)(), path)
        reason = None if resolved else 'launcher'
    if resolved and Path(resolved).is_relative_to(Path.home()):
        resolved, reason = None, 'unavailable'
    return {'id': str(info.get_id() or '')[:256], 'name': str(info.get_display_name() or info.get_name() or '')[:160],
            'path': resolved or '', 'supported': bool(resolved), 'reason': reason or '', 'icon': ''}


def installed_catalog():
    global _CACHE
    with _LOCK:
        if _CACHE and time.monotonic() < _CACHE[0]:
            return _CACHE[1]
        from gi.repository import Gio
        import gi
        gi.require_version('Gtk', '3.0')
        from gi.repository import Gtk, GdkPixbuf
        theme = Gtk.IconTheme.new()
        schema = Gio.SettingsSchemaSource.get_default().lookup('org.gnome.desktop.interface', True)
        theme.set_custom_theme(Gio.Settings.new_full(schema, None, None).get_string('icon-theme') if schema else 'hicolor')
        all_infos = list(Gio.AppInfo.get_all())
        seen = {getattr(a, 'get_filename', lambda: None)() for a in all_infos}
        # Session environments may omit export roots; list actual installations
        # without starting flatpak or trusting a process display name.
        for base in (Path('/var/lib/flatpak/exports/share'), Path.home()/'.local/share/flatpak/exports/share'):
            theme.append_search_path(str(base/'icons'))
            try:
                for filename in sorted((base/'applications').glob('*.desktop'))[:1024]:
                    if str(filename) not in seen:
                        entry = Gio.DesktopAppInfo.new_from_filename(str(filename))
                        if entry:
                            all_infos.append(entry)
                            seen.add(str(filename))
            except OSError:
                continue
        infos = sorted((a for a in all_infos if a.should_show()), key=lambda a: (a.get_display_name() or '').casefold())
        items, size, deadline = [], 0, time.monotonic() + 5
        for info in infos[:_LIMIT]:
            if time.monotonic() > deadline:
                break
            record = describe(info)
            try:
                icon = info.get_icon()
                if isinstance(icon, Gio.FileIcon):
                    filename = icon.get_file().get_path()
                else:
                    found = theme.choose_icon(icon.get_names(), 48, Gtk.IconLookupFlags.FORCE_SIZE) if icon else None
                    filename = found.get_filename() if found else None
                if filename and Path(filename).stat().st_size <= 524288 and size < 524288:
                    image = GdkPixbuf.Pixbuf.new_from_file_at_scale(filename, 48, 48, True)
                    ok, encoded = image.save_to_bufferv('png', [], [])
                    if ok and len(encoded) <= 16384:
                        record['icon'] = 'data:image/png;base64,' + base64.b64encode(encoded).decode('ascii')
                        size += len(record['icon'])
            except Exception:
                pass  # Missing/unreadable icons have the existing functional fallback.
            items.append(record)
        value = {'items': items, 'total': len(infos), 'truncated': len(items) < len(infos),
                 'source': 'gio-desktop-applications', 'identity_scope': 'reviewed-executable-path'}
        _CACHE = (time.monotonic() + 30, value)
        return value
