"""Keep DMS output control available without exposing higher-risk globals."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'security-center/packaging/application-security/desktop/labwc-protected-input.patch'


class ProtectedCompositorDisplayTests(unittest.TestCase):
    def test_monitor_management_is_the_only_new_ordinary_privileged_global(self):
        source = PATCH.read_text()
        start = source.index('+greyward_ordinary_protocol(')
        end = source.index('\n+}', start)
        ordinary = source[start:end]

        self.assertIn('allow_for_sandbox(NULL, iface)', ordinary)
        self.assertIn('"zwlr_output_manager_v1"', ordinary)
        for interface in (
            'zwlr_output_power_manager_v1',
            'zwlr_virtual_keyboard_manager_v1',
            'zwlr_screencopy_manager_v1',
            'ext_session_lock_manager_v1',
        ):
            self.assertNotIn(f'"{interface}"', ordinary)

    def test_enrollment_rpm_applies_the_protected_compositor_patch(self):
        spec = (ROOT / 'packaging/greyward-enrollment/greyward-enrollment.spec').read_text()
        build = (ROOT / 'packaging/greyward-enrollment/build.sh').read_text()
        relative = 'security-center/packaging/application-security/desktop/labwc-protected-input.patch'

        self.assertIn(relative, build)
        self.assertIn('patch --batch --fuzz=0 -d compositor -p1 < ' + relative, spec)

    def test_existing_enrollments_have_a_quiescent_dms_shell_migration(self):
        spec = (ROOT / 'packaging/greyward-enrollment/greyward-enrollment.spec').read_text()
        migration = ROOT / 'packaging/greyward-enrollment/migrate-dms-shell.py'

        self.assertIn('migrate-dms-shell.py', spec)
        self.assertTrue(migration.is_file())


if __name__ == '__main__':
    unittest.main()
