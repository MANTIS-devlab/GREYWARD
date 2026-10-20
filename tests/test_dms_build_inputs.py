"""Build receipt verification must reject drift before extracting upstream inputs."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dms_assembly', ROOT / 'packaging/greyward-dms/assemble.py')
ASSEMBLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSEMBLY)
IMAGE_BUILDER = ROOT / 'environment/image/build.sh'
COMPONENT_BUILDER_SPEC = importlib.util.spec_from_file_location('greyward_build_components', ROOT / 'environment/image/build-components.py')
COMPONENT_BUILDER = importlib.util.module_from_spec(COMPONENT_BUILDER_SPEC)
COMPONENT_BUILDER_SPEC.loader.exec_module(COMPONENT_BUILDER)


class BuildInputVerificationTests(unittest.TestCase):
    def attempt(self, changed_package=None, changed_version=None):
        release = json.loads((ROOT / 'environment/production/dms-release.json').read_text())

        def installed(command, **_kwargs):
            name = command[-1]
            return changed_version if name == changed_package else release['build']['requiredPackages'][name]

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            # Exact tools alone never authorize an unverified source archive.
            archive = base / 'unverified.tar.gz'
            archive.write_bytes(b'invalid upstream input')
            with patch.object(Path, 'exists', return_value=True), \
                    patch.object(ASSEMBLY.subprocess, 'check_output', side_effect=installed):
                ASSEMBLY.assemble(ROOT / 'environment/production/dms-release.json',
                                  archive, archive, base / 'patches', base / 'output')

    def test_stale_python_receipt_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'Unpinned Fedora build input: python3'):
            self.attempt('python3', '3.14.7-1.fc44.x86_64')

    def test_other_tool_drift_is_still_refused(self):
        with self.assertRaisesRegex(ValueError, 'Unpinned Fedora build input: golang'):
            self.attempt('golang', '0.0.0-1.fc44.x86_64')

    def test_matching_tools_still_require_verified_upstream_archive(self):
        with self.assertRaisesRegex(ValueError, 'source archive checksum mismatch'):
            self.attempt()

    def test_iso_builder_rejects_stale_first_party_plugin_payload(self):
        source = IMAGE_BUILDER.read_text()
        self.assertIn('plugin_source="$session/dankmaterialshell/plugins"', source)
        self.assertIn('rpm_plugin_path="./etc/xdg/quickshell/dms-plugins/$plugin_relative"', source)
        self.assertIn('normalize_plugin_text', source)
        self.assertIn('cmp -s - <(normalize_plugin_text < "$plugin_file")', source)

    def test_iso_builder_rejects_stale_virtual_display_fallback(self):
        source = IMAGE_BUILDER.read_text()
        startup = (ROOT / 'environment/production/labwc-autostart').read_text()
        session_spec = (ROOT / 'packaging/greyward-session/greyward-session.spec').read_text()
        production_packages = (ROOT / 'environment/production/packages.txt').read_text().splitlines()
        acceptance = (ROOT / 'environment/production/production-acceptance.sh').read_text()
        self.assertIn('session_autostart_path=\'./usr/share/greyward/defaults/labwc/autostart\'', source)
        self.assertIn('cmp -s - "$production/labwc-autostart"', source)
        self.assertIn('timeout 3s wlr-randr --output Virtual-1 --mode 1920x1080', startup)
        self.assertNotIn('--custom-mode', startup)
        self.assertLess(startup.index('wlr-randr --output Virtual-1 --mode 1920x1080'),
                        startup.index('systemctl --user start --no-block greyward-dms.service'))
        self.assertIn('Requires: wlr-randr', session_spec)
        self.assertIn('wlr-randr', production_packages)
        self.assertIn('policycoreutils wlr-randr wlopm', acceptance)

    def test_session_rpm_normalizes_linux_launcher_shebang(self):
        session_spec = (ROOT / 'packaging/greyward-session/greyward-session.spec').read_text()
        self.assertIn("Release: 22%{?dist}", session_spec)
        self.assertIn("sed -i 's/\\r$//' %{buildroot}/usr/local/libexec/greyward-start-labwc", session_spec)

    def test_iso_builder_rejects_stale_taskbar_default_migration(self):
        source = IMAGE_BUILDER.read_text()
        self.assertIn("session_pin_migration_path='./usr/local/libexec/greyward-dms-session-migrate'", source)
        self.assertIn('cmp -s - "$session/greyward-dms-session-migrate"', source)
        self.assertIn('io.github.lgse.Strata', (ROOT / 'environment/session/greyward-dms-session-migrate').read_text())

    def test_iso_builder_rejects_enrollment_rpm_built_for_another_dms_version(self):
        source = IMAGE_BUILDER.read_text()
        enrollment_spec = (ROOT / 'packaging/greyward-enrollment/greyward-enrollment.spec').read_text()
        self.assertIn('expected_dms_requirement="greyward-dms = $selected_dms_version"', source)
        self.assertIn('rpm_query -qp --requires "$enrollment_rpm"', source)
        self.assertIn('Requires: greyward-application-security-experimental = 0.1.0-69%{?dist}', enrollment_spec)
        self.assertIn('Requires: greyward-dms = 1.6.2-26%{?dist}', enrollment_spec)
        build = (ROOT / 'packaging/greyward-dms/build.sh').read_text()
        self.assertIn('usbguard-approval-execute.go', build)
        self.assertIn('usbguardAuthApprovalSha256', (ROOT / 'packaging/greyward-dms/greyward-dms.spec').read_text())

    def test_iso_builder_requires_exact_matched_runtime_pair_and_records_files_inputs(self):
        source = IMAGE_BUILDER.read_text()
        iso_source = (ROOT / 'environment/image/build-iso.sh').read_text()
        self.assertIn('enrollment_count != 1 || appsec_count != 1', source)
        self.assertIn('greyward-application-security-experimental = $selected_appsec_version', source)
        self.assertIn('"session_rpm": "$(basename "${session_rpm:-MISSING}")"', source)
        self.assertIn('"files_rpm": "$(basename "${files_rpm:-MISSING}")"', source)
        self.assertIn('-n "$session_rpm" && -n "$files_rpm"', source)
        self.assertIn('Provide exactly one GREYWARD Files RPM.', iso_source)

    def test_root_component_builder_drops_to_unprivileged_user_before_dms_build(self):
        command = COMPONENT_BUILDER.dms_build_command(Path('/repo'), Path('/inputs'), Path('/output'), 'stendev', True)
        self.assertEqual(command[:7], ['unshare', '--net', 'runuser', '-u', 'stendev', '--', 'bash'])
        self.assertNotIn('sudo', command)


if __name__ == '__main__':
    unittest.main()
