"""ISO input checks reject stale USB approval payloads even with matching versions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('usb_inputs', ROOT / 'environment/image/verify-usbguard-inputs.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class UsbApprovalReleaseInputs(unittest.TestCase):
    def test_candidate_receipt_is_checked_only_when_explicitly_selected(self):
        payloads = self.payloads('dms')
        legacy = next(path for path in payloads if path.endswith('/release.json'))
        manifest = ROOT / 'environment/production/dms-2.0-candidate.json'
        candidate = '/usr/lib/greyward/dms/' + json.loads(manifest.read_text())['releaseId'] + '/release.json'
        payloads[candidate] = payloads.pop(legacy)
        read = lambda rpm, path: payloads.get(path, b'{}')
        CHECK.verify(ROOT, Path('candidate.rpm'), 'dms', read, manifest=manifest)
        with self.assertRaisesRegex(ValueError, 'helper source receipt'):
            CHECK.verify(ROOT, Path('candidate.rpm'), 'dms', read)
        payloads[candidate] = b'{}'
        with self.assertRaisesRegex(ValueError, 'helper source receipt'):
            CHECK.verify(ROOT, Path('candidate.rpm'), 'dms', read, manifest=manifest)

    def payloads(self, kind):
        result = {installed: (ROOT / source).read_bytes() for source, installed in CHECK.SOURCES[kind].items()}
        if kind == 'dms':
            release = json.loads((ROOT / 'environment/production/dms-release.json').read_text())['releaseId']
            result['/usr/lib/greyward/dms/' + release + '/release.json'] = json.dumps({
                key: hashlib.sha256((ROOT / 'packaging/greyward-dms' / source).read_bytes()).hexdigest()
                for key, source in [('usbguardApprovalSourceSha256', 'usbguard-approval.go'),
                                    ('usbguardAuthApprovalSourceSha256', 'usbguard-approval-execute.go')]
            }).encode()
        return result

    def test_matched_payloads_pass_for_each_package(self):
        for kind in CHECK.SOURCES:
            with self.subTest(kind=kind):
                payloads = self.payloads(kind)
                CHECK.verify(ROOT, Path('fixture.rpm'), kind, lambda rpm, path: payloads[path])

    def test_each_stale_file_is_rejected_without_changing_package_identity(self):
        for kind, sources in CHECK.SOURCES.items():
            for installed in sources.values():
                with self.subTest(kind=kind, installed=installed):
                    payloads = self.payloads(kind)
                    payloads[installed] += b'\n# old or changed package input\n'
                    with self.assertRaisesRegex(ValueError, 'Stale or missing'):
                        CHECK.verify(ROOT, Path('same-version.rpm'), kind, lambda rpm, path: payloads[path])

    def test_missing_file_is_not_an_empty_success(self):
        for kind in CHECK.SOURCES:
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'Stale or missing'):
                    CHECK.verify(ROOT, Path('fixture.rpm'), kind, lambda rpm, path: b'')

    def test_windows_line_endings_do_not_hide_real_source_drift(self):
        payloads = self.payloads('context')
        payloads = {path: CHECK.normalized(value).replace(b'\n', b'\r\n') for path, value in payloads.items()}
        CHECK.verify(ROOT, Path('fixture.rpm'), 'context', lambda rpm, path: payloads[path])

    def test_helper_source_receipt_is_required_and_cannot_be_stale(self):
        for receipt in ({}, {'usbguardApprovalSourceSha256': '0' * 64}):
            payloads = self.payloads('dms')
            path = next(path for path in payloads if path.endswith('/release.json'))
            payloads[path] = json.dumps(receipt).encode()
            with self.assertRaisesRegex(ValueError, 'helper source receipt'):
                CHECK.verify(ROOT, Path('same-version.rpm'), 'dms', lambda rpm, path: payloads[path])

    def test_reviewed_crlf_helper_receipts_match_lf_checkout(self):
        payloads = self.payloads('dms')
        path = next(path for path in payloads if path.endswith('/release.json'))
        receipt = {}
        for key, source in [('usbguardApprovalSourceSha256', 'usbguard-approval.go'),
                            ('usbguardAuthApprovalSourceSha256', 'usbguard-approval-execute.go')]:
            content = CHECK.normalized((ROOT / 'packaging/greyward-dms' / source).read_bytes())
            receipt[key] = hashlib.sha256(content.replace(b'\n', b'\r\n')).hexdigest()
        payloads[path] = json.dumps(receipt).encode()
        CHECK.verify(ROOT, Path('reviewed-crlf.rpm'), 'dms', lambda rpm, name: payloads[name])
        receipt['usbguardApprovalSourceSha256'] = hashlib.sha256(content + b'changed').hexdigest()
        payloads[path] = json.dumps(receipt).encode()
        with self.assertRaisesRegex(ValueError, 'helper source receipt'):
            CHECK.verify(ROOT, Path('changed.rpm'), 'dms', lambda rpm, name: payloads[name])

    def test_complete_iso_staging_invokes_all_package_checks(self):
        build = (ROOT / 'environment/image/build.sh').read_text()
        for kind in CHECK.SOURCES:
            self.assertIn('--kind ' + kind + ' --rpm ', build)
        enrollment = (ROOT / 'packaging/greyward-enrollment/greyward-enrollment.spec').read_text()
        self.assertIn('install -m0444 policy/*.te policy/*.fc "$base/policy/"', enrollment)
        dms = (ROOT / 'packaging/greyward-dms/greyward-dms.spec').read_text()
        self.assertIn("m['usbguardApprovalSourceSha256']", dms)
        self.assertIn("m['usbguardAuthApprovalSourceSha256']", dms)

    def test_stale_fresh_enrollment_generator_is_rejected(self):
        payloads = self.payloads('ordinary-role')
        path = '/usr/share/greyward-application-security/desktop/ordinary-policy.py'
        payloads[path] = b'ordinary = [t for t in domains if t != "greyward_as_display_t"]\n'
        with self.assertRaisesRegex(ValueError, 'Stale or missing'):
            CHECK.verify(ROOT, Path('installed-reference.rpm'), 'ordinary-role', lambda rpm, path: payloads[path])

    def test_role_closure_check_also_runs_for_installed_imports(self):
        build = (ROOT / 'environment/image/build.sh').read_text()
        start = build.index('test -n "$usb_context_rpm"')
        role = build.index('--kind ordinary-role --rpm "$appsec_rpm"', start)
        condition = build.find('if [[ "$security_manifest_schema"', start)
        if condition >= 0:
            self.assertLess(role, condition)
        self.assertLess(role, build.index('--kind dms --rpm ', start))


if __name__ == '__main__':
    unittest.main()
