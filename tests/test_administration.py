"""Admission input and immutable-file contracts without changing a live account."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import os
import subprocess
import sys
import hashlib
import stat
from unittest.mock import patch
from types import SimpleNamespace

if os.name != 'posix':
    raise unittest.SkipTest('Linux admission and descriptor contracts; run on Fedora')

import fcntl

PATH = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/administration/worker.py'
SPEC = importlib.util.spec_from_file_location('administration_worker', PATH)
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)

class AdministrationRequestTests(unittest.TestCase):
    def test_private_password_helper_requires_the_matching_fedora_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ['terminal', 'worker.py', 'fonts.conf', 'unix_chkpwd']:
                (base/name).write_bytes(b'prepared:'+name.encode())
            desktop = b'prepared desktop manifest'
            # This is a generation-binding unit test, not installed Fedora PAM
            # acceptance. Ubuntu places unix_chkpwd elsewhere; use explicit
            # immutable synthetic tool generations rather than host binaries.
            tool_bytes = {p: b'packaged:' + p.encode()
                          for p in ['/usr/bin/sudo', '/usr/bin/bash', '/usr/bin/unix_chkpwd']}
            tools = {p: hashlib.sha256(value).hexdigest() for p, value in tool_bytes.items()}
            (base/'unix_chkpwd').write_bytes(tool_bytes['/usr/bin/unix_chkpwd'])
            manifest = {'schema':'greyward.administration/v1',
                        'desktop':hashlib.sha256(desktop).hexdigest(),
                        'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in base.iterdir()},
                        'tools':tools}
            original_stat, original_read = Path.lstat, Path.read_bytes
            def metadata(path):
                if str(path) in tool_bytes:
                    return SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o555, st_nlink=1)
                value = original_stat(path)
                return SimpleNamespace(st_uid=0, st_mode=value.st_mode & ~0o022,
                                       st_nlink=value.st_nlink)
            def read(path):
                if str(path) in tool_bytes:
                    return tool_bytes[str(path)]
                return desktop if str(path).endswith('/desktop/desktop.json') else original_read(path)
            with patch.object(WORKER, 'BASE', base), patch.object(WORKER, 'private_json', return_value=manifest), \
                 patch.object(Path, 'lstat', metadata), patch.object(Path, 'read_bytes', read):
                self.assertEqual(WORKER.generation(), manifest)
                (base/'unix_chkpwd').write_bytes(b'replaced helper')
                manifest['files']['unix_chkpwd'] = hashlib.sha256(b'replaced helper').hexdigest()
                with self.assertRaisesRegex(RuntimeError, 'Mismatched Fedora password helper'):
                    WORKER.generation()

    def test_child_receives_only_request_and_status_descriptors(self):
        with tempfile.TemporaryFile() as source:
            source.write(b'prepared'); source.seek(0)
            incoming = fcntl.fcntl(source.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
            reader, writer = os.pipe()
            outgoing = fcntl.fcntl(writer, fcntl.F_DUPFD_CLOEXEC, 10)
            leak = fcntl.fcntl(source.fileno(), fcntl.F_DUPFD, 20)
            os.close(writer)
            try:
                code = "import os; assert os.read(3,8)==b'prepared'; os.write(4,b'accepted');\ntry: os.fstat(20)\nexcept OSError: pass\nelse: raise AssertionError('Inherited handle')"
                result = subprocess.run([sys.executable, '-I', '-c', code],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, close_fds=False,
                    preexec_fn=lambda: WORKER.bind_descriptors(incoming, outgoing), timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(os.read(reader, 8), b'accepted')
            finally:
                for fd in [incoming, reader, outgoing, leak]: os.close(fd)

    def test_preserves_argument_boundaries_including_shell_metacharacters(self):
        value = ['--', '/usr/bin/printf', '%s', '$(touch forbidden); spaces']
        self.assertEqual(WORKER.validated_arguments(value), value)

    def test_rejects_missing_wrongly_typed_and_oversized_requests(self):
        for value in [[], '-i', [1], ['x'] * 129, ['x' * 16385]]:
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                WORKER.validated_arguments(value)

    def test_rejects_terminal_control_and_multiline_injection(self):
        for value in ['\x1b[2J', 'one\ntwo', 'one\rtwo', '\0', '\x7f', '\u202ereversed', '\u2066hidden']:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                WORKER.validated_arguments(['--', value])

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'Linux descriptor contract')
    def test_private_input_rejects_links_and_unsafe_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'request'
            source.write_text('{}')
            source.chmod(0o666)
            with self.assertRaises(RuntimeError):
                WORKER.private_json(source)
            link = Path(directory) / 'link'
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(OSError):
                WORKER.private_json(link)

if __name__ == '__main__':
    unittest.main()
