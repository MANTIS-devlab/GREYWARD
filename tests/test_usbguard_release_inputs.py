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

    def test_complete_iso_staging_invokes_all_package_checks(self):
        build = (ROOT / 'environment/image/build.sh').read_text()
        for kind in CHECK.SOURCES:
            self.assertIn('--kind ' + kind + ' --rpm ', build)
        enrollment = (ROOT / 'packaging/greyward-enrollment/greyward-enrollment.spec').read_text()
        self.assertIn('install -m0444 policy/*.te policy/*.fc "$base/policy/"', enrollment)
        dms = (ROOT / 'packaging/greyward-dms/greyward-dms.spec').read_text()
        self.assertIn("m['usbguardApprovalSourceSha256']", dms)
        self.assertIn("m['usbguardAuthApprovalSourceSha256']", dms)


if __name__ == '__main__':
    unittest.main()
