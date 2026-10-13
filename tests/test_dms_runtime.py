import importlib.machinery
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import contextlib
import io
import json
import stat

path = Path(__file__).resolve().parents[1] / 'environment/session/greyward-dms-runtime-check'
loader = importlib.machinery.SourceFileLoader('runtime_check', str(path))
module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(module)


class NativeLockReadinessTests(unittest.TestCase):
    def run_check(self, desktop_only):
        server = {'apiVersion': 34, 'capabilities': ['dgop']}
        unsafe_lock = {'loginctlLocked': False, 'shouldLock': True, 'sessionLockSecure': False}
        with mock.patch.dict(module.os.environ, {'DMS_SOCKET': '/run/test-shell.sock'}), \
             mock.patch.object(module.os, 'getuid', return_value=1001, create=True), \
             mock.patch.object(module.Path, 'stat', return_value=SimpleNamespace(
                 st_mode=stat.S_IFSOCK | 0o600, st_uid=1001)), \
             mock.patch.object(module, 'request', side_effect=[server, {'network': {}}, {'pong': True}]), \
             mock.patch.object(module.subprocess, 'check_output', side_effect=['""', json.dumps(unsafe_lock)]) as ipc, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            module.check(desktop_only=desktop_only)
            return json.loads(output.getvalue()), ipc.call_count

    def test_surface_ordering_never_claims_native_lock_readiness(self):
        output, calls = self.run_check(True)
        self.assertEqual(output['state'], 'SHELL_READY')
        self.assertNotIn('nativeLockSecure', output)
        self.assertEqual(calls, 1)

    def test_full_check_still_rejects_an_unsecured_requested_lock(self):
        with self.assertRaisesRegex(ValueError, 'Native lock surface'):
            self.run_check(False)

    def test_unlocked_and_secure_locked_states_are_ready(self):
        for locked in (False, True):
            module.validate_lock_status(dict(loginctlLocked=locked, shouldLock=locked, sessionLockSecure=locked))

    def test_lost_surface_cannot_be_ready(self):
        for hint, requested in ((True, False), (False, True), (True, True)):
            with self.assertRaises(ValueError):
                module.validate_lock_status(dict(loginctlLocked=hint, shouldLock=requested, sessionLockSecure=False))

    def test_missing_or_malformed_evidence_cannot_be_ready(self):
        for state in ({}, None, dict(loginctlLocked='false', shouldLock=False, sessionLockSecure=False)):
            with self.assertRaises(ValueError):
                module.validate_lock_status(state)
