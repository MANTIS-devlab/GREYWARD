"""The public export cannot delete private originals or copy private Git refs."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('public_export', ROOT / 'tools/public-export.py')
EXPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORT)
POLICY = json.loads((ROOT / 'tools/publication-policy.json').read_text())


class PublicationBoundaryTests(unittest.TestCase):
    def test_validation_host_and_account_are_not_published_in_runtime_notes(self):
        text = 'Readback on `.150` at 192.168.1.150 for cicada.'
        cleaned = EXPORT.sanitized_text(text, 'docs/STATUS.md', set())
        self.assertNotIn('192.168.1.150', cleaned)
        self.assertNotIn('`.150`', cleaned)
        self.assertNotIn('cicada', cleaned)
        self.assertIn('<validation-host>', cleaned)

    def test_plain_host_shorthand_is_sanitized_without_changing_versions(self):
        text = 'On .150 and .149; package 1.150.2 is retained.'
        cleaned = EXPORT.sanitized_text(text, 'docs/STATUS.md', set())
        self.assertEqual(cleaned, 'On <validation-host> and <development-host>; package 1.150.2 is retained.')

    def test_extensionless_installed_scripts_keep_linux_line_endings(self):
        attributes = (ROOT / '.gitattributes').read_text()
        self.assertIn('environment/production/greyward-* text eol=lf', attributes)
        self.assertIn('security-center/security-context/bin/* text eol=lf', attributes)

    def test_private_factory_accounts_logs_and_host_controls_are_excluded(self):
        for path in ('environment/greyward.pkr.hcl', 'environment/development/provision-overlay.sh',
                     'tools/greyward-dev/common.ps1', 'tools/greyward-dev/destroy.ps1',
                     'docs/history/security-center/internal-report.md', '.secrets/id_ed25519',
                     'tests/security/exploit_priv_esc.sh',
                     'tests/security/results.md', 'output/receipt.json',
                     '.codex-attachments/request.png', 'desktop-current.png',
                     'id_rsa', 'server.key'):
            with self.subTest(path=path):
                self.assertTrue(EXPORT.excluded(path, POLICY))

    def test_generic_build_runtime_tests_and_assets_remain_public(self):
        for path in POLICY['requiredPaths'] + ['branding/source/greyward-symbol.svg',
                     'environment/production/selinux/greyward-administration.te',
                     'tools/greyward-dev/administration-kernel-check.py',
                     'security-center/crates/greyward-application-security/src/grants.rs']:
            with self.subTest(path=path):
                self.assertFalse(EXPORT.excluded(path, POLICY))

    def test_public_snapshot_does_not_modify_original_or_copy_git_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target = Path(temporary)/'private', Path(temporary)/'public'
            fixture_policy = dict(POLICY, publicTemplates={})
            files = {'tools/publication-policy.json': json.dumps(fixture_policy),
                     'docs/history/security-center/internal-report.md': 'private evidence',
                     'tools/greyward-dev/common.ps1': 'private host controls',
                     '.git/config': 'private Git configuration'}
            files.update({p: 'generic source\n' for p in POLICY['requiredPaths']})
            for p, content in files.items():
                path = source/p
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            inventory = '\0'.join(p for p in files if not p.startswith('.git/')) + '\0'
            with patch.object(EXPORT.subprocess, 'check_output', return_value=inventory.encode()), \
                    patch.object(EXPORT, 'verify_secret_scan') as scan:
                report = EXPORT.snapshot(source, target)
            scan.assert_called_once_with(target.resolve())
            self.assertFalse((target/'.git').exists())
            self.assertFalse((target/'tools/greyward-dev/common.ps1').exists())
            self.assertEqual((source/'tools/greyward-dev/common.ps1').read_text(), 'private host controls')
            self.assertFalse(report['sourceHistoryCopied'])
            self.assertTrue(all((target/p).is_file() for p in POLICY['requiredPaths']))

    def test_document_links_to_private_evidence_are_not_broken_public_links(self):
        text = '[report](history/security-center/internal-report.md)'
        result = EXPORT.sanitized_text(text, 'docs/STATUS.md', {'docs/history/security-center/internal-report.md'})
        self.assertEqual(result, 'report (private development evidence)')

    def test_internal_windows_iso_location_is_not_publication_input(self):
        text = 'Windows copy: `D:\\GREYWARD-ISO-candidates\\candidate\\installer.iso`.'
        result = EXPORT.sanitized_text(text, 'docs/STATUS.md', set())
        self.assertEqual(result, 'Windows copy: `<local workspace>`.')

    def test_forward_slash_windows_iso_location_is_also_private(self):
        text = 'ISO: `D:/GREYWARD-ISO-candidates/private/installer.iso`.'
        result = EXPORT.sanitized_text(text, 'docs/STATUS.md', set())
        self.assertEqual(result, 'ISO: `<local workspace>`.')

    def test_public_readme_does_not_embed_sensitive_desktop_captures(self):
        text = (ROOT / 'README.md').read_text(encoding='utf-8')
        result = EXPORT.sanitized_text(text, 'README.md', set())
        for name in ('greyward-desktop-browser.png', 'greyward-desktop-threat-notification.png'):
            self.assertNotIn(name, result)
        self.assertIn('greyward-desktop-security-center.png', result)
        self.assertIn('greyward-desktop-overview.gif', result)
        self.assertFalse(EXPORT.excluded('docs/assets/screenshots/greyward-desktop-overview.gif', POLICY))

    def test_destination_cannot_overwrite_private_source_or_existing_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)/'private'
            source.mkdir()
            for destination in (source, source/'export'):
                with self.assertRaises(ValueError):
                    EXPORT.snapshot(source, destination)
            target = Path(temporary)/'public'
            target.mkdir()
            (target/'existing-work').write_text('preserve')
            with self.assertRaises(ValueError):
                EXPORT.snapshot(source, target)
            self.assertEqual((target/'existing-work').read_text(), 'preserve')

    def test_secret_scanner_failure_refuses_publication(self):
        with patch.dict(EXPORT.os.environ, {'GREYWARD_GITLEAKS_BINARY': 'gitleaks'}), \
                patch.object(EXPORT.subprocess, 'run') as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(ValueError, 'Secret scan rejected'):
                EXPORT.verify_secret_scan(Path('/candidate'))
            command = run.call_args.args[0]
            self.assertIn('--redact', command)
            self.assertIn('--config', command)


if __name__ == '__main__':
    unittest.main()
