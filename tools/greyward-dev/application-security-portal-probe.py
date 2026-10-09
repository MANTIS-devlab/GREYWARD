#!/usr/bin/python3
"""Synthetic document-portal probes in the fixed, separate confined account."""
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import dbus


def main():
    home = Path.home()
    if home != Path('/home/greyward-guard-probe') or os.getuid() == 0:
        raise SystemExit('Run only in the separately enrolled probe account')
    context = Path('/proc/self/attr/current').read_text().rstrip('\x00').strip()
    if context.split(':')[2] != 'greyward_guard_t':
        raise SystemExit('Probe requires the confined subject context')
    portal = dbus.Interface(dbus.SessionBus().get_object(
        'org.freedesktop.portal.Documents', '/org/freedesktop/portal/documents'),
        'org.freedesktop.portal.Documents')
    mount = Path(bytes(portal.GetMountPoint(timeout=5)).rstrip(b'\x00').decode())
    results = []
    exports = []

    def flatpak_document(alias, name, expected_read):
        """Fixed runtime probe; never a caller-supplied command or root launch."""
        script = r'''
ordinary=false
original=false
protected_present=false
protected_failed=false
test "$(cat "$1" 2>/dev/null)" = ordinary && ordinary=true
test "$(cat /home/greyward-guard-probe/ordinary.txt 2>/dev/null)" = ordinary && original=true
test -f /home/greyward-guard-probe/protected/credential && protected_present=true
if ! head -c 1 /home/greyward-guard-probe/protected/credential >/dev/null 2>/dev/null; then protected_failed=true; fi
context=$(cat /proc/self/attr/current | tr -d '\000')
caps=$(grep '^CapEff:' /proc/self/status | awk '{print $2}')
printf '{"ordinary":%s,"original":%s,"protected_present":%s,"protected_failed":%s,"context":"%s","caps":"%s"}\n' "$ordinary" "$original" "$protected_present" "$protected_failed" "$context" "$caps"
'''
        task = None
        try:
            task = subprocess.run(['/usr/bin/flatpak', 'run', '--system', '--unshare=network',
                '--no-session-bus', '--no-a11y-bus', '--nodevice=all', '--nosocket=session-bus',
                '--nosocket=system-bus', '--nosocket=wayland', '--nosocket=x11', '--nosocket=fallback-x11',
                '--filesystem=home', '--command=sh', 'com.brave.Browser/x86_64/stable',
                '-c', script, 'greyward-fixed-document-probe', str(alias)],
                env={'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                     'XDG_RUNTIME_DIR': '/run/user/1002', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1002/bus'},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, check=False)
            if len(task.stdout) > 2048:
                raise ValueError('Oversized fixed document fixture output')
            value = json.loads(task.stdout)
            established = (task.returncode == 0 and isinstance(value, dict) and
                value.get('context', '').split(':')[2] == 'greyward_guard_t' and value.get('caps') == '0000000000000000')
            results.extend([
                {'test': name + '_document_read', 'passed': established and value.get('ordinary') is expected_read},
                {'test': name + '_broad_home_remains', 'passed': established and value.get('original') is True},
                {'test': name + '_protected_read_failed', 'passed': established and
                    value.get('protected_present') is True and value.get('protected_failed') is True},
                {'test': name + '_ordinary_subject', 'passed': established},
            ])
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError) as error:
            # Fixed synthetic startup diagnostics only, never product history or
            # command/environment/secret contents. Do not misreport a failure.
            diagnostic = None if task is None else ''.join(character for character in
                task.stderr[:512].decode('utf-8', errors='replace') if character.isprintable()).replace(str(home), '[PROBE_HOME]')
            results.append({'test': name + '_document_flow', 'state': 'UNAVAILABLE', 'passed': False,
                            'failure': type(error).__name__, 'startup_diagnostic': diagnostic})

    def document_reference(value):
        # The pinned provider uses xdp_generate_token(), including underscores;
        # this is an opaque path component, not an application-security ID.
        reference = str(value)
        if (not reference or len(reference) > 64 or
            any(not (character.isascii() and (character.isalnum() or character in '_-')) for character in reference)):
            raise RuntimeError('Invalid ordinary document reference')
        return reference

    def inspect_export(name, path, protected, request, relative=None):
        """Exercise the actual portal, then check its FUSE view and clean up."""
        try:
            reference = str(request())
        except dbus.DBusException as error:
            # InvalidArgument deliberately conceals inaccessible FD details.
            # This is an export rejection test, not authoritative attribution.
            error_name = error.get_dbus_name()
            results.append({'test': name + '_export', 'passed': protected and
                error_name in {'org.freedesktop.portal.Error.NotAllowed',
                               'org.freedesktop.portal.Error.PermissionDenied',
                               'org.freedesktop.portal.Error.InvalidArgument'},
                'error': error_name})
            return
        if not reference:
            results.append({'test': name + '_export', 'passed': False,
                            'error': 'MissingDocumentReference'})
            return
        exports.append(reference)
        alias = mount / reference / (relative or path.name)
        try:
            data = alias.read_bytes()
        except OSError as error:
            results.append({'test': name + '_alias_read', 'passed': protected and
                error.errno in {errno.EACCES, errno.EPERM},
                'error': errno.errorcode.get(error.errno, 'UNKNOWN')})
        else:
            results.append({'test': name + '_alias_read',
                            'passed': not protected and data == b'ordinary\n'})
        # Even an inaccessible export fails the first-release prohibition.
        results.append({'test': name + '_export', 'passed': not protected})

    try:
        for name, path, protected in (
            ('ordinary', home / 'ordinary.txt', False),
            ('protected', home / 'protected' / 'credential', True),
            ('hardlink', home / 'credential-hardlink', True),
        ):
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise RuntimeError('Fixture is not a valid regular file descriptor')
                label = os.getxattr(path, 'security.selinux').decode().rstrip('\x00')
                if protected and label.split(':')[2] != 'greyward_guard_secret_t':
                    raise RuntimeError('Protected fixture lost its label')
                inspect_export(name + '_add', path, protected, lambda:
                    portal.Add(dbus.types.UnixFd(descriptor), False, False, timeout=5))
                inspect_export(name + '_add_full', path, protected, lambda:
                    portal.AddFull(dbus.Array([dbus.types.UnixFd(descriptor)], signature='h'),
                                   dbus.UInt32(0), '', dbus.Array([], signature='s'), timeout=5)[0][0])
            finally:
                os.close(descriptor)
            parent_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                filename = dbus.ByteArray(os.fsencode(path.name) + b'\x00')
                inspect_export(name + '_add_named', path, protected, lambda:
                    portal.AddNamed(dbus.types.UnixFd(parent_fd), filename, False, False, timeout=5))
                inspect_export(name + '_add_named_full', path, protected, lambda:
                    portal.AddNamedFull(dbus.types.UnixFd(parent_fd), filename,
                                       dbus.UInt32(0), '', dbus.Array([], signature='s'), timeout=5)[0])
            finally:
                os.close(parent_fd)
        descriptor = os.open(home / 'protected', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            inspect_export('protected_directory', home / 'protected', True, lambda:
                portal.AddFull(dbus.Array([dbus.types.UnixFd(descriptor)], signature='h'),
                               dbus.UInt32(8), '', dbus.Array([], signature='s'), timeout=5)[0][0],
                relative='credential')
        finally:
            os.close(descriptor)
        # Preserve ordinary save-as; then replace its target with a protected
        # symlink to exercise an already-created pathname/FUSE export.
        for method in ('AddNamed', 'AddNamedFull'):
            path = home / ('ordinary-save-' + method + '.txt')
            if os.path.lexists(path):
                raise RuntimeError('Save-as fixture already exists; review before retrying')
            parent_fd = os.open(home, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                filename = dbus.ByteArray(os.fsencode(path.name) + b'\x00')
                if method == 'AddNamed':
                    reference = str(portal.AddNamed(dbus.types.UnixFd(parent_fd), filename,
                                                   False, False, timeout=5))
                else:
                    reference = str(portal.AddNamedFull(dbus.types.UnixFd(parent_fd), filename,
                        dbus.UInt32(0), '', dbus.Array([], signature='s'), timeout=5)[0])
                if not reference:
                    raise RuntimeError('Save-as returned no document reference')
                exports.append(reference)
                alias = mount / reference / path.name
                alias.write_bytes(b'ordinary\n')
                results.append({'test': method + '_save_as',
                    'passed': alias.read_bytes() == b'ordinary\n' and path.read_bytes() == b'ordinary\n'})
                path.unlink()
                path.symlink_to(home / 'protected' / 'credential')
                try:
                    alias.read_bytes()
                except OSError as error:
                    results.append({'test': method + '_replaced_alias', 'passed': error.errno in
                        {errno.EACCES, errno.EPERM, errno.ELOOP, errno.ENOENT},
                        'error': errno.errorcode.get(error.errno, 'UNKNOWN')})
                else:
                    results.append({'test': method + '_replaced_alias', 'passed': False})
            finally:
                os.close(parent_fd)
                # Only this exclusive, synthetic fixture is removed.
                if os.path.lexists(path):
                    path.unlink()
        # Actual Flatpak selected-document flow: a native chooser-side caller
        # exports only ordinary synthetic input and grants this fixed test app
        # read access. App ID metadata here is not grant-bearing code identity.
        descriptor = os.open(home / 'ordinary.txt', os.O_PATH | os.O_CLOEXEC)
        try:
            reference = str(portal.AddFull(dbus.Array([dbus.types.UnixFd(descriptor)], signature='h'),
                dbus.UInt32(0), 'com.brave.Browser', dbus.Array(['read'], signature='s'), timeout=5)[0][0])
        finally:
            os.close(descriptor)
        reference = document_reference(reference)
        exports.append(reference)
        alias = mount / reference / 'ordinary.txt'
        permissions = portal.Info(reference, timeout=5)[1]
        results.append({'test': 'flatpak_grant_readback', 'passed':
            list(permissions.get('com.brave.Browser', [])) == ['read']})
        flatpak_document(alias, 'flatpak_selected', True)
        portal.RevokePermissions(reference, 'com.brave.Browser', dbus.Array(['read'], signature='s'), timeout=5)
        permissions = portal.Info(reference, timeout=5)[1]
        results.append({'test': 'flatpak_revoke_readback', 'passed':
            'read' not in permissions.get('com.brave.Browser', [])})
        # New opens only: this does not recall already-read data or descriptors.
        # Broad home still exposes the original ordinary path after revocation.
        flatpak_document(alias, 'flatpak_revoked', False)

        # Delete temporary exports before restarting the provider; they are not
        # persistent and would otherwise leave misleading cleanup failures.
        for temporary in exports:
            portal.Delete(temporary, timeout=5)
        exports.clear()
        descriptor = os.open(home / 'ordinary.txt', os.O_PATH | os.O_CLOEXEC)
        try:
            reference = document_reference(portal.AddFull(
                dbus.Array([dbus.types.UnixFd(descriptor)], signature='h'), dbus.UInt32(2),
                'com.brave.Browser', dbus.Array(['read'], signature='s'), timeout=5)[0][0])
        finally:
            os.close(descriptor)
        exports.append(reference)
        # Only this account's user provider is restarted. No graphical service,
        # system portal or recovery account is touched.
        subprocess.run(['/usr/bin/systemctl', '--user', 'restart', 'xdg-document-portal.service'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True, timeout=8)
        portal = dbus.Interface(dbus.SessionBus().get_object(
            'org.freedesktop.portal.Documents', '/org/freedesktop/portal/documents'),
            'org.freedesktop.portal.Documents')
        mount = Path(bytes(portal.GetMountPoint(timeout=5)).rstrip(b'\x00').decode())
        info_path, permissions = portal.Info(reference, timeout=5)
        results.append({'test': 'flatpak_persistent_readback', 'passed':
            bytes(info_path).rstrip(b'\x00') == os.fsencode(home / 'ordinary.txt') and
            list(permissions.get('com.brave.Browser', [])) == ['read']})
        flatpak_document(mount / reference / 'ordinary.txt', 'flatpak_persistent', True)
    finally:
        for reference in exports:
            try:
                portal.Delete(reference, timeout=5)
            except dbus.DBusException as error:
                results.append({'test': 'export_cleanup', 'passed': False,
                                'error': error.get_dbus_name()})
    passed = all(item['passed'] for item in results)
    print(json.dumps({'schema': 'greyward.application-security.probe/v1',
                      'scope': 'synthetic-document-portal', 'passed': passed,
                      'results': results}, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
