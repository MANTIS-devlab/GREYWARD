import json
import subprocess
import unittest
from unittest.mock import patch

from greyward_security_context import dms_compatibility as policy


class DesktopCompatibilityTests(unittest.TestCase):
    def test_read_only_and_update_share_fixed_selected_policy(self):
        values = {name: '1.2.3-4.fc44' for name in policy.NAMES}
        result = subprocess.CompletedProcess([], 0, json.dumps(values), '')
        with patch.object(policy.Path, 'exists', return_value=True), patch.object(policy.subprocess, 'run', return_value=result) as run:
            self.assertEqual(policy.constraints(), values)
            self.assertEqual(policy.dnf_options(), ['--exclude=dms-greeter,labwc,quickshell,uwsm'])
            self.assertEqual(run.call_args.args[0], [str(policy.VERIFIER), '--constraints'])

    def test_unavailable_or_tampered_policy_is_never_silently_ignored(self):
        with patch.object(policy.Path, 'exists', return_value=True), patch.object(policy.subprocess, 'run', side_effect=FileNotFoundError):
            with self.assertRaises(OSError): policy.dnf_options()
        result = subprocess.CompletedProcess([], 0, '{"arbitrary-package":"1"}', '')
        with patch.object(policy.Path, 'exists', return_value=True), patch.object(policy.subprocess, 'run', return_value=result):
            with self.assertRaises(ValueError): policy.dnf_options()

    def test_non_greyward_host_has_no_desktop_hold(self):
        with patch.object(policy.Path, 'exists', return_value=False):
            self.assertEqual(policy.dnf_options(), [])
