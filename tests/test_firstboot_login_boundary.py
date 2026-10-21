"""Exercise only the first-boot readiness functions in an isolated shell.

Command fixtures emulate process/seat readbacks. No service, login, policy or
installed file is changed, and these tests do not claim graphical acceptance.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'environment/production/provision-firstboot.sh'


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'requires Linux bash')
class FirstbootLoginBoundary(unittest.TestCase):
    def run_boundary(self, function, *, processes=(), sessions='', result=None, exit_code=0, session_exit=0):
        source = SOURCE.read_text(encoding='utf-8')
        functions = source.split('greeter_is_running() {', 1)[1].split('report_enrollment_workloads() {', 1)[0]
        functions = 'greeter_is_running() {' + functions
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fixture = base / 'fixture.json'
            calls = base / 'calls.jsonl'
            fixture.write_text(json.dumps({'processes': list(processes), 'sessions': sessions,
                                          'result': result, 'exit_code': exit_code,
                                          'session_exit': session_exit}))
            stub = '''#!/usr/bin/python3
import json, os, pathlib, sys
config = json.loads(pathlib.Path(os.environ['GW_FIXTURE']).read_text())
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['GW_CALLS'], 'a') as stream:
    stream.write(json.dumps([name, args]) + '\\n')
if name == 'pgrep':
    assert args[:3] == ['-u', 'greeter', '-x'], args
    expected = args[3].split('|')
    sys.exit(0 if any(p in config['processes'] for p in expected) else 1)
if name == 'loginctl':
    assert args == ['list-sessions', '--no-legend', '--no-pager'], args
    print(config['sessions'])
    sys.exit(config['session_exit'])
elif name == 'timeout':
    assert args[:5] == ['--kill-after=1', '3', '/usr/bin/python3', '-I', '/usr/lib/greyward/application-security/desktop/verify.py'], args
    assert len(args) == 6 and args[5] == '1000', args
    print(config['result'] or '')
    sys.exit(config['exit_code'])
'''
            for name in ['pgrep', 'loginctl', 'timeout']:
                path = base / name
                path.write_text(stub)
                path.chmod(0o755)
            env = {**os.environ, 'PATH': str(base) + os.pathsep + os.environ['PATH'],
                   'GW_FIXTURE': str(fixture), 'GW_CALLS': str(calls)}
            completed = subprocess.run(['bash', '-c', 'set -eu\n' + functions + '\n' + function],
                                       env=env, capture_output=True, text=True, timeout=10)
            observed = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
            return completed, observed

    def test_exec_replaced_launcher_is_not_required(self):
        result, calls = self.run_boundary('greeter_is_running', processes=['labwc', 'qs'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)

    def test_missing_ui_or_compositor_does_not_pass(self):
        for processes in [[], ['labwc'], ['qs'], ['dms-greeter'], ['dms-greeter', 'labwc']]:
            with self.subTest(processes=processes):
                result, _ = self.run_boundary('greeter_is_running', processes=processes)
                self.assertNotEqual(result.returncode, 0)

    def test_quickshell_binary_alias_is_supported(self):
        result, _ = self.run_boundary('greeter_is_running', processes=['labwc', 'quickshell'])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_handoff_requires_actual_positive_verifier(self):
        sessions = '4 1000 user seat0 1234 user tty1 no -'
        result, calls = self.run_boundary('protected_session_is_ready', sessions=sessions,
                                          result='{"verified": true}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1][0], 'timeout')
        for output, code in [('{"verified": false}', 0), ('', 0), ('not JSON', 0),
                             ('{"verified": true}', 124), ('{"verified": true, "extra": 1}', 0)]:
            with self.subTest(output=output, code=code):
                result, _ = self.run_boundary('protected_session_is_ready', sessions=sessions,
                                              result=output, exit_code=code)
                self.assertNotEqual(result.returncode, 0)

    def test_greeter_remote_and_nonhuman_sessions_cannot_substitute_for_handoff(self):
        for sessions in ['1 983 greeter seat0 100 greeter tty1 no -',
                         '2 1000 user - 101 user pts/0 no -',
                         '3 0 root seat0 102 user tty1 no -',
                         '4 malformed user seat0 103 user tty1 no -', '']:
            with self.subTest(sessions=sessions):
                result, calls = self.run_boundary('protected_session_is_ready', sessions=sessions,
                                                  result='{"verified": true}')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([name for name, _ in calls], ['loginctl'])

    def test_failed_session_query_is_not_accepted_even_with_plausible_stdout(self):
        result, calls = self.run_boundary('protected_session_is_ready',
                                          sessions='4 1000 user seat0 1234 user tty1 no -',
                                          result='{"verified": true}', session_exit=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([name for name, _ in calls], ['loginctl'])


if __name__ == '__main__':
    unittest.main()
