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
    def run_check(self, desktop_only, routing='', subject='greyward_guard_u:greyward_guard_r:greyward_guard_t:s0', api=34, expected=34):
        server = {'apiVersion': api, 'capabilities': ['dgop']}
        unsafe_lock = {'loginctlLocked': False, 'shouldLock': True, 'sessionLockSecure': False}
        with mock.patch.object(module, 'selected_api_version', return_value=expected), \
             mock.patch.dict(module.os.environ, {'DMS_SOCKET': '/run/test-shell.sock'}), \
             mock.patch.object(module.os, 'getuid', return_value=1001, create=True), \
             mock.patch.object(module.Path, 'stat', return_value=SimpleNamespace(
                 st_mode=stat.S_IFSOCK | 0o600, st_uid=1001)), \
             mock.patch.object(module.Path, 'read_text', return_value=subject), \
             mock.patch.object(module, 'request', side_effect=[server, {'network': {}}, {'pong': True}]), \
             mock.patch.object(module.subprocess, 'check_output', side_effect=[json.dumps(routing), json.dumps(unsafe_lock)]) as ipc, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            module.check(desktop_only=desktop_only)
            return json.loads(output.getvalue()), ipc.call_count

    def test_2_0_api_matches_selected_receipt_and_rejects_the_previous_backend(self):
        result, _calls = self.run_check(True, api=38, expected=38)
        self.assertEqual(result['apiVersion'], 38)
        with self.assertRaisesRegex(ValueError, 'Incompatible DMS API'):
            self.run_check(True, api=34, expected=38)

    def test_surface_ordering_never_claims_native_lock_readiness(self):
        output, calls = self.run_check(True)
        self.assertEqual(output['state'], 'SHELL_READY')
        self.assertNotIn('nativeLockSecure', output)
        self.assertEqual(calls, 1)

    def test_full_check_still_rejects_an_unsecured_requested_lock(self):
        with self.assertRaisesRegex(ValueError, 'Native lock surface'):
            self.run_check(False)

    def test_enrolled_handoff_allows_surface_ordering_without_claiming_lock_security(self):
        output,calls = self.run_check(True, routing='/usr/bin/greyward-guard lock')
        self.assertEqual(output['state'],'SHELL_READY')
        self.assertNotIn('nativeLockSecure',output)
        self.assertEqual(calls,1)
        with self.assertRaisesRegex(ValueError,'authentication owner'):
            self.run_check(False, routing='/usr/bin/greyward-guard lock')

    def test_forged_or_unrecognized_handoffs_cannot_pass_readiness(self):
        with self.assertRaisesRegex(ValueError,'outside the enrolled subject'):
            self.run_check(True, routing='/usr/bin/greyward-guard lock', subject='unconfined_u:unconfined_r:unconfined_t:s0')
        with self.assertRaisesRegex(ValueError,'routing is not ready'):
            self.run_check(True,routing='/tmp/fake-locker')

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
