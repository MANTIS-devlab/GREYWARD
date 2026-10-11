"""Exercise the shell launcher admission decision without opening a desktop."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'Linux shell routing')
class SessionAdmissionRouting(unittest.TestCase):
    def launch(self, context, helper_status=0):
        source = (ROOT / 'environment/production/greyward-start-labwc').read_text()
        admission = source.split('# Some virtual GPUs', 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            helper = Path(temporary) / 'protected-helper'
            helper.write_text('#!/bin/sh\nprintf "protected:%s\\n" "$*"\nexit ' + str(helper_status) + '\n')
            helper.chmod(0o755)
            admission = admission.replace('/usr/bin/id -Z', "printf %s '" + context + "'")
            admission = admission.replace('/usr/bin/python3', str(helper))
            return subprocess.run(['/bin/sh', '-c', admission + 'printf "ordinary\\n"\n'],
                                  capture_output=True, text=True)

    def test_enrolled_subject_uses_protected_admission(self):
        result = self.launch('greyward_guard_u:greyward_guard_r:greyward_guard_t:s0')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'protected:-I /usr/share/greyward-application-security/desktop/login.py\n')

    def test_unenrolled_subject_retains_ordinary_route(self):
        result = self.launch('unconfined_u:unconfined_r:unconfined_t:s0')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'ordinary\n')

    def test_protected_admission_failure_never_falls_back(self):
        result = self.launch('greyward_guard_u:greyward_guard_r:greyward_guard_t:s0', 77)
        self.assertEqual(result.returncode, 77)
        self.assertNotIn('ordinary', result.stdout)


if __name__ == '__main__':
    unittest.main()
