"""Reject the real login regression: the read broker cannot admit a desktop."""
import ast
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tools/greyward-dev/desktop-compatibility-kernel-check.py'
# Exercise the actual readback function without running the separate top-level
# SELinux kernel queries on a development host that may not even run Linux.
tree = ast.parse(SOURCE.read_text())
function = next(node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == 'enrolled_broker_readback')
namespace = {'Path': Path, 're': re, 'subprocess': subprocess}
exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), 'exec'), namespace)
verify_broker = namespace['enrolled_broker_readback']


class DesktopBrokerReadbackTests(unittest.TestCase):
    def readback(self, *, workflow='active', readonly='inactive',
                 command=b'/usr/libexec/greyward-application-security\0--workflows\0',
                 owner='(uint32 123,)', interface='node / {\n      StartDesktop(out b arg_0);\n}',
                 changed=False):
        pids = iter(['123', '456' if changed else '123'])

        def run(args, **_kwargs):
            if args[0] == 'systemctl':
                if 'MainPID' in args:
                    result = next(pids)
                else:
                    result = workflow if args[2].endswith('-workflows.service') else readonly
            elif args[1] == 'call':
                result = owner
            else:
                result = interface
            return SimpleNamespace(stdout=result)

        with patch.object(subprocess, 'run', side_effect=run), patch.object(Path, 'read_bytes', return_value=command):
            return verify_broker()

    def test_live_workflow_service_owns_admission_method(self):
        self.assertTrue(self.readback())

    def test_read_only_mode_or_unbound_method_cannot_pass(self):
        for case in [
                {'workflow': 'inactive', 'readonly': 'active'},
                {'readonly': 'active'},
                {'command': b'/usr/libexec/greyward-application-security\0'},
                {'owner': '(uint32 456,)'},
                {'interface': '      GetCoverage(out s projection);'},
                {'changed': True}]:
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                self.readback(**case)


if __name__ == '__main__':
    unittest.main()
