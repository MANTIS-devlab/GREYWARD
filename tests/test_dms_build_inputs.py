"""Build receipt verification must reject drift before extracting upstream inputs."""
import importlib.util
import json
from pathlib import Path
import re
import sys
import contextlib
import io
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
    def test_plugin_update_rejects_stale_sources_and_out_of_scope_payload(self):
        spec = importlib.util.spec_from_file_location('dms_visual_update', ROOT / 'packaging/greyward-dms/build-artwork-update.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        import hashlib
        allowed = ['greywardSecure/SecureWidget.qml', 'greywardSecure/StatusCard.qml', 'greywardSecure/plugin.json']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'source'; payload = root / 'payload'
            installed = payload / 'etc/xdg/quickshell/dms-plugins'
            names = allowed + ['greywardSecure/SecurityClient.qml']
            for name in names:
                for base in (source, installed):
                    path = base / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'before')
            old = dict.fromkeys(names, hashlib.sha256(b'before').hexdigest())
            for name in allowed: (source / name).write_bytes(b'after')
            new = {name: module.digest(source / name) for name in names}
            receipt = {'firstPartyFiles': old.copy(), 'firstPartySources': old.copy()}
            manifest = {'firstPartyDirectory': 'source', 'firstPartySources': new,
                        'build': {'pluginUpdate': {'baseFirstPartySha256': module.tree_digest(old),
                                  'changedFirstPartyFiles': allowed, 'requiresProtectedMigration': False}}}
            # A changed collector cannot slip through even when its new hash is supplied.
            collector = source / names[-1]; collector.write_bytes(b'changed collector')
            with self.assertRaisesRegex(ValueError, 'reviewed visual update'):
                module.update_plugins(payload, manifest, receipt, root)
            collector.write_bytes(b'before')
            (installed / allowed[0]).write_bytes(b'unexpected predecessor')
            with self.assertRaisesRegex(ValueError, 'Predecessor plugin payload'):
                module.update_plugins(payload, manifest, receipt, root)
            (installed / allowed[0]).write_bytes(b'before')
            module.update_plugins(payload, manifest, receipt, root)
            self.assertEqual(receipt['firstPartyFiles'], new)
            self.assertEqual((installed / names[-1]).read_bytes(), b'before')

    def test_package_only_runtime_provide_requires_exact_pinned_executables(self):
        names = ('binarySha256', 'usbguardApprovalSha256', 'usbguardAuthApprovalSha256')
        pins = dict.fromkeys(names, 'a' * 64)
        receipt = {'build': {'rpmRelease': '7.2', 'packageOnlyRuntime': pins}, **pins}
        ASSEMBLY.verify_package_only_runtime(receipt)
        for name in names:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'pinned generation'):
                ASSEMBLY.verify_package_only_runtime({**receipt, name: 'b' * 64})
        for expected in (None, {}, {**pins, 'other': 'a' * 64}, dict.fromkeys(names, 'invalid')):
            with self.assertRaisesRegex(ValueError, 'pinned generation'):
                ASSEMBLY.verify_package_only_runtime({**receipt, 'build': {'rpmRelease': '7.2', 'packageOnlyRuntime': expected}})
        ASSEMBLY.verify_package_only_runtime({'build': {}})

    def test_package_only_revision_keeps_the_runtime_selector_and_rejects_bad_suffixes(self):
        # Execute the actual build-script spec generator, not a copied parser.
        source = (ROOT / 'packaging/greyward-dms/build.sh').read_text()
        generator = source.split('"$output/SPECS/greyward-dms.spec" <<\'PY\'\n', 1)[1].split('\nPY\n', 1)[0]
        release = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
        generation = release['releaseId'].rsplit('-', 1)[1]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); manifest = base / 'input.json'; output = base / 'output.spec'
            arguments = ['spec-generator', str(manifest), str(ROOT / 'packaging/greyward-dms/greyward-dms.spec'), str(output)]
            for revision in (None, generation + '.1'):
                if revision is None: release['build'].pop('rpmRelease', None)
                else: release['build']['rpmRelease'] = revision
                manifest.write_text(json.dumps(release))
                with patch.object(sys, 'argv', arguments): exec(compile(generator, 'spec-generator', 'exec'), {})
                generated = output.read_text()
                self.assertIn('%global greyward_package_revision ' + (revision or generation) + '\n', generated)
                self.assertIn('%global greyward_runtime /usr/lib/greyward/dms/' + release['releaseId'] + '\n', generated)
                self.assertIn("printf 'v%{version}-%{greyward_revision}\\n'", generated)
                self.assertEqual('Provides: greyward-dms = 2.0.0-' + generation + '%{?dist}' in generated, revision is not None)
                self.assertEqual(COMPONENT_BUILDER.dms_package_identity(release),
                                 'greyward-dms-2.0.0-' + (revision or generation))
                enrollment = (ROOT / 'packaging/greyward-enrollment/build.sh').read_text().split("<<'PYDEP'\n", 1)[1].split('\nPYDEP', 1)[0]
                with patch.object(sys, 'argv', ['dependency', str(manifest)]), contextlib.redirect_stdout(io.StringIO()) as captured:
                    exec(compile(enrollment, 'dependency', 'exec'), {})
                self.assertEqual(captured.getvalue().strip(), '2.0.0-' + (revision or generation))
            for revision in (str(int(generation) + 1) + '.1', generation + '.0', generation + '.1\nRequires: evil', generation + '.01', 7, ''):
                release['build']['rpmRelease'] = revision; manifest.write_text(json.dumps(release))
                with patch.object(sys, 'argv', arguments), self.assertRaisesRegex(SystemExit, 'package-only revision'):
                    exec(compile(generator, 'spec-generator', 'exec'), {})
                with self.assertRaisesRegex(SystemExit, 'package-only revision'):
                    COMPONENT_BUILDER.dms_package_identity(release)

    def test_native_schema_drift_refuses_assembly(self):
        with tempfile.TemporaryDirectory() as temporary:
            shell = Path(temporary)
            (shell / 'Common').mkdir()
            source = shell / 'Common/SettingsData.qml'
            release = {'dms': {'tag': 'v2.0.0', 'settingsConfigVersion': 42}}
            source.write_text('readonly property int settingsConfigVersion: 42\n')
            ASSEMBLY.verify_settings_schema(release, shell)
            for declaration in ('readonly property int settingsConfigVersion: 43\n',
                                'property int settingsConfigVersion: 42\n',
                                'readonly property int settingsConfigVersion: 42\n' * 2):
                with self.subTest(declaration=declaration):
                    source.write_text(declaration)
                    with self.assertRaisesRegex(ValueError, 'Native settings schema'):
                        ASSEMBLY.verify_settings_schema(release, shell)
            source.write_text('readonly property int settingsConfigVersion: 42\n')
            for expected in (None, True, '42', 29):
                with self.subTest(expected=expected):
                    release['dms']['settingsConfigVersion'] = expected
                    with self.assertRaisesRegex(ValueError, 'Native settings schema'):
                        ASSEMBLY.verify_settings_schema(release, shell)

    def test_legacy_schema_pin_is_not_changed(self):
        ASSEMBLY.verify_settings_schema({'dms': {'tag': 'v1.6.2'}}, Path('/not-read'))

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
        self.assertIn('plugin_source="$repo_root/environment/session/dankmaterialshell/plugins"', source)
        self.assertIn('plugin_source="$repo_root/environment/session/dms-2.0-plugins"', source)
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
        revision = int(re.search(r'(?m)^Release:\s+(\d+)', session_spec)[1])
        self.assertGreaterEqual(revision, 22)
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
        runtime_spec = (ROOT / 'security-center/packaging/application-security/greyward-application-security-experimental.spec').read_text()
        runtime_revision = re.search(r'(?m)^Release:\s+(\d+)', runtime_spec)[1]
        self.assertIn(f'Requires: greyward-application-security-experimental = 0.1.0-{runtime_revision}%{{?dist}}', enrollment_spec)
        self.assertIn('%{!?greyward_dms_dependency:%global greyward_dms_dependency 1.6.2-26}', enrollment_spec)
        self.assertIn('Requires: greyward-dms = %{greyward_dms_dependency}%{?dist}', enrollment_spec)
        enrollment_build = (ROOT / 'packaging/greyward-enrollment/build.sh').read_text()
        self.assertIn('--define "greyward_dms_dependency $dms_dependency"', enrollment_build)
        self.assertIn('environment/production/dms-release.json', enrollment_build)
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
        self.assertEqual(command[:5], ['unshare', '--net', 'sh', '-eu', '-c'])
        self.assertEqual(command[5], 'ip link set dev lo up; exec "$@"')
        self.assertEqual(command[7:12], ['runuser', '-u', 'stendev', '--', 'bash'])
        self.assertNotIn('sudo', command)


if __name__ == '__main__':
    unittest.main()
