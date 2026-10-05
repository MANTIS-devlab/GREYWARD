import importlib.machinery
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'environment/session/greyward-dms-runtime-check'
loader = importlib.machinery.SourceFileLoader('runtime_check', str(path))
module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(module)


class NativeLockReadinessTests(unittest.TestCase):
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
