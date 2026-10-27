"""Source drift, incomplete RPM sets and payload forgery must block Office staging."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('office_inputs', ROOT / 'packaging/greyward-office/verify-inputs.py')
office = importlib.util.module_from_spec(spec)
spec.loader.exec_module(office)


class OfficeInputTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.sha = office.validate_sources(ROOT)
        self.apps = self.manifest['applications']
        self.mime_fixture = (b'<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">'
                             b'<mime-type type="application/x-deckcraft"><glob pattern="*.deckcraft"/>'
                             b'<icon name="old-application-icon"/></mime-type></mime-info>')
        # Small synthetic resource payloads exercise closure without downloading OCR weights.
        for app in self.apps:
            app['noticeSha256'] = hashlib.sha256(b'upstream-notice-fixture').hexdigest()
            if app.get('mimeSource'):
                app['mimeSha256'] = hashlib.sha256(self.mime_fixture).hexdigest()
            for resource in app.get('runtimeResources', []):
                resource['sha256'] = hashlib.sha256(b'resource-fixture').hexdigest()
                resource['licence_sha256'] = hashlib.sha256(b'license-fixture').hexdigest()
        self.payloads = {}
        self.receipts = {}
        self.rpms = []
        self.identities = {}
        self.scriptlets = {}
        self.capabilities = {'greyward-writer.rpm': '/usr/bin/greyward-writer\t\n'}
        self.header_extra = {}
        for app in self.apps:
            filename = Path(app['package'] + '.rpm')
            self.rpms.append(filename)
            self.identities[str(filename)] = '|'.join((app['package'], app['version'], str(self.manifest['rpmRelease']) + '.fc44', 'x86_64'))
            files = {
                'usr/share/licenses/' + app['package'] + '/NOTICE': b'upstream-notice-fixture',
                'usr/bin/greyward-' + app['slug']: b'launcher',
                'usr/libexec/greyward-office/' + app['upstream']: b'ELF-test-binary',
                'usr/share/applications/' + app['appId'] + '.desktop': b'desktop',
                'usr/share/icons/hicolor/scalable/apps/' + app['appId'] + '.svg':
                    (ROOT / 'branding/source' / ('greyward-' + app['slug'] + '.svg')).read_bytes(),
                'usr/share/icons/hicolor/scalable/mimetypes/' + office.artwork.document_icon_name(app) + '.svg':
                    (ROOT / 'branding/source' / ('greyward-' + app['slug'] + '-document.svg')).read_bytes(),
                'usr/share/icons/Greyward/scalable/mimetypes/' + office.artwork.document_icon_name(app) + '.svg':
                    (ROOT / 'branding/source' / ('greyward-' + app['slug'] + '-document.svg')).read_bytes(),
                'usr/share/mime/packages/' + app['appId'] + '.xml':
                    office.artwork.document_mime(app, self.mime_fixture if app.get('mimeSource') else None),
            }
            for size in (16, 24, 32, 48, 64, 128, 256, 512):
                files['usr/share/icons/hicolor/' + str(size) + 'x' + str(size) + '/apps/' + app['appId'] + '.png'] = b'PNG-fixture'
            if app.get('mimeSource'):
                files['usr/share/greyward/office/' + app['slug'] + '/upstream-mime.xml'] = self.mime_fixture
            self.payloads[str(filename)] = files
            self.receipts[str(filename)] = {
                'schema': 'greyward.office-build/v1',
                'application': app, 'sourceManifestSha256': self.sha,
                'integrationSources': self.manifest['integrationSources'],
                'fonts': next(f for f in self.manifest['fonts'] if f['commit'] == app['fontsCommit']),
                'brandSources': self.manifest['brandSources'],
                'toolchain': self.manifest['toolchain'], 'vendoredInputs': {'crate': 'locked'},
                'payloadFiles': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
            }
            for resource in app.get('runtimeResources', []):
                name = 'usr/share/greyward/office/' + app['slug'] + '/models/' + resource['file']
                self.payloads[str(filename)][name] = b'resource-fixture'
                self.payloads[str(filename)][name + '.LICENCE.txt'] = b'license-fixture'
                self.receipts[str(filename)]['payloadFiles'][name] = resource['sha256']
                self.receipts[str(filename)]['payloadFiles'][name + '.LICENCE.txt'] = resource['licence_sha256']

    def read(self, rpm, name):
        if name.endswith('/provenance.json'):
            return json.dumps(self.receipts[str(rpm)]).encode()
        if name not in self.payloads[str(rpm)]:
            raise ValueError('Missing payload: ' + name)
        return self.payloads[str(rpm)][name]

    def query(self, args, **kwargs):
        name = args[-1]
        if '--filecaps' in args:
            return self.capabilities.get(name, '')
        if '--scripts' in args:
            return self.scriptlets.get(name, '')
        if any('FILEMODES' in value for value in args):
            return ''.join('/' + path + '|100644|root|root\n' for path in self.payloads[name]) + self.header_extra.get(name, '')
        return self.identities[name]

    def verify(self, rpms=None):
        with patch.object(office, 'validate_sources', return_value=(self.manifest, self.sha)), \
             patch.object(office, 'read_payload', side_effect=self.read), \
             patch.object(office.subprocess, 'check_output', side_effect=self.query):
            office.verify_rpms(ROOT, self.rpms if rpms is None else rpms)

    def test_matched_family_is_accepted(self):
        self.verify()

    def test_missing_application_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete Office RPM set'):
            self.verify(self.rpms[:-1])

    def test_duplicate_application_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.verify(self.rpms + self.rpms[:1])

    def test_privileged_scriptlet_is_refused(self):
        self.scriptlets[str(self.rpms[0])] = 'postinstall scriptlet: unexpected command'
        with self.assertRaisesRegex(ValueError, 'privileged scriptlets'):
            self.verify()

    def test_file_capability_is_refused(self):
        self.capabilities[str(self.rpms[0])] = '/usr/bin/greyward-writer\tcap_sys_admin=ep\n'
        with self.assertRaisesRegex(ValueError, 'file capabilities'):
            self.verify()

    def test_unexpected_autostart_payload_is_refused(self):
        self.header_extra[str(self.rpms[0])] = '/etc/systemd/system/unexpected.service|100644|root|root\n'
        with self.assertRaisesRegex(ValueError, 'Unexpected Office RPM install path'):
            self.verify()

    def test_setuid_launcher_is_refused(self):
        self.header_extra[str(self.rpms[0])] = '/usr/bin/greyward-writer|104755|root|root\n'
        with self.assertRaisesRegex(ValueError, 'Unsafe Office RPM ownership or mode'):
            self.verify()

    def test_wrong_revision_is_refused(self):
        first = str(self.rpms[0])
        self.identities[first] = self.identities[first].replace('.fc44', '.fc43')
        with self.assertRaisesRegex(ValueError, 'revision mismatch'):
            self.verify()

    def test_replaced_binary_is_refused(self):
        first = str(self.rpms[0])
        path = 'usr/libexec/greyward-office/' + self.apps[0]['upstream']
        self.payloads[first][path] = b'old-binary'
        with self.assertRaisesRegex(ValueError, 'payload drift'):
            self.verify()

    def test_receipt_from_old_manifest_is_refused(self):
        self.receipts[str(self.rpms[0])]['sourceManifestSha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'provenance mismatch'):
            self.verify()

    def test_recomputed_receipt_cannot_replace_canonical_icon(self):
        first = str(self.rpms[0])
        icon = 'usr/share/icons/hicolor/scalable/apps/' + self.apps[0]['appId'] + '.svg'
        self.payloads[first][icon] = b'old-artwork'
        self.receipts[first]['payloadFiles'][icon] = hashlib.sha256(b'old-artwork').hexdigest()
        with self.assertRaisesRegex(ValueError, 'icon does not match'):
            self.verify()

    def test_document_artwork_is_distinct_and_retains_accepted_revision_five_bytes(self):
        accepted = {
            'writer': 'f9dbbb6d310485b72213b69c0411d0de5857e9c2132c432444e95d0515a1ad9d',
            'sheets': '1cadb11395d3461f855180e7004cb58a896e384ceb26413b2fac54af48d52794',
            'pdf': 'f15b53a789886de48e4fe9857fb8e50d8478ca2873bf0fef3a65d286f45944bf',
            'slides': '1d224eaf5e43524967d364701b3dcd348e9342cc1a85afed679af20a5745b33c',
        }
        for app in self.apps:
            self.assertEqual(app['documentIconSha256'], accepted[app['slug']])
            self.assertNotEqual(app['iconSha256'], app['documentIconSha256'])

    def test_recomputed_receipt_cannot_replace_document_icon(self):
        first = str(self.rpms[0])
        icon = 'usr/share/icons/hicolor/scalable/mimetypes/greyward-writer-document.svg'
        self.payloads[first][icon] = b'changed-document-artwork'
        self.receipts[first]['payloadFiles'][icon] = hashlib.sha256(self.payloads[first][icon]).hexdigest()
        with self.assertRaisesRegex(ValueError, 'document icon does not match'):
            self.verify()

    def test_file_type_icons_cannot_silently_revert_to_application_icons(self):
        first = str(self.rpms[0])
        path = 'usr/share/mime/packages/' + self.apps[0]['appId'] + '.xml'
        changed = self.payloads[first][path].replace(b'greyward-writer-document', self.apps[0]['appId'].encode())
        self.payloads[first][path] = changed
        self.receipts[first]['payloadFiles'][path] = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(ValueError, 'MIME icon metadata'):
            self.verify()

    def test_document_metadata_preserves_detection_rules_and_excludes_unsupported_formats(self):
        app = next(app for app in self.apps if app['slug'] == 'slides')
        root = ET.fromstring(office.artwork.document_mime(app, self.mime_fixture))
        ns = '{' + office.artwork.NAMESPACE + '}'
        deck = next(entry for entry in root if entry.get('type') == 'application/x-deckcraft')
        self.assertEqual(deck.find(ns + 'glob').get('pattern'), '*.deckcraft')
        self.assertEqual(deck.find(ns + 'icon').get('name'), 'greyward-slides-document')
        self.assertNotIn('application/vnd.ms-powerpoint', [entry.get('type') for entry in root])
        self.assertNotIn('application/vnd.oasis.opendocument.presentation', [entry.get('type') for entry in root])
        for entry in root:
            if entry is not deck:
                self.assertEqual([child.tag for child in entry], [ns + 'icon'])

    def test_missing_ocr_resource_is_refused(self):
        key = str(self.rpms[2])
        missing = next(name for name in self.receipts[key]['payloadFiles'] if name.endswith('.rten'))
        del self.receipts[key]['payloadFiles'][missing]
        with self.assertRaisesRegex(ValueError, 'Incomplete Office payload'):
            self.verify()

    def test_missing_window_icon_is_refused(self):
        key = str(self.rpms[0])
        missing = next(name for name in self.receipts[key]['payloadFiles'] if '/256x256/' in name)
        del self.receipts[key]['payloadFiles'][missing]
        with self.assertRaisesRegex(ValueError, 'Incomplete Office payload'):
            self.verify()

    def test_upstream_notice_cannot_be_omitted(self):
        key = str(self.rpms[0])
        missing = 'usr/share/licenses/' + self.apps[0]['package'] + '/NOTICE'
        del self.payloads[key][missing]
        del self.receipts[key]['payloadFiles'][missing]
        with self.assertRaisesRegex(ValueError, 'Missing payload'):
            self.verify()

    def test_receipt_tracks_runtime_payload_without_separate_debug_packages(self):
        import subprocess
        import sys
        recipe = (ROOT / 'packaging/greyward-office/office.spec.in').read_text()
        script = recipe.split("<<'RECEIPT'\n", 1)[1].split('\nRECEIPT', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / 'usr/share/greyward/office/writer/provenance.json'
            receipt.parent.mkdir(parents=True)
            receipt.write_text('{}')
            for name in ('usr/libexec/greyward-office/wordcraft',
                         'usr/lib/debug/usr/libexec/greyward-office/wordcraft.debug',
                         'usr/src/debug/greyward-writer/source.rs'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'content')
            subprocess.run([sys.executable, '-c', script, str(root), 'writer'], check=True)
            files = json.loads(receipt.read_text())['payloadFiles']
            self.assertEqual(set(files), {'usr/libexec/greyward-office/wordcraft'})
            self.assertEqual(files['usr/libexec/greyward-office/wordcraft'], hashlib.sha256(b'content').hexdigest())

    def test_recipe_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            shutil.copytree(ROOT / 'packaging/greyward-office', repo / 'packaging/greyward-office')
            (repo / 'branding/source').mkdir(parents=True)
            for path in (ROOT / 'branding/source').glob('greyward-*.svg'):
                shutil.copyfile(path, repo / 'branding/source' / path.name)
            script = repo / 'packaging/greyward-office/office.spec.in'
            script.write_bytes(script.read_bytes() + b'\n# changed\n')
            with self.assertRaisesRegex(ValueError, 'integration drift'):
                office.validate_sources(repo)

    def test_associations_preserve_other_default_applications(self):
        source = (ROOT / 'environment/flatpak/mimeapps.list').read_text()
        self.assertIn('inode/directory=io.github.lgse.Strata.desktop;', source)
        self.assertIn('text/plain=org.gnome.TextEditor.desktop;', source)
        self.assertIn('text/html=com.brave.Browser.desktop;', source)
        self.assertIn('image/png=org.gnome.Loupe.desktop;', source)
        self.assertNotIn('application/vnd.ms-powerpoint=', source)
        self.assertNotIn('application/vnd.oasis.opendocument.presentation=', source)
        self.assertNotIn('collabora', source)

    def test_adaptations_do_not_change_engines(self):
        for app in self.apps:
            self.assertTrue(all(name.startswith(('apps/' + app['upstream'] + '/src/', 'crates/ui-egui/src/'))
                                or name == 'packaging/linux/ai.storyteller.deckcraft.mime.xml'
                                for name in app['adaptedInputs']))


class OfficeUpdateCandidateTests(unittest.TestCase):
    def module(self):
        import sys
        directory = str(ROOT / 'packaging/greyward-office')
        sys.path.insert(0, directory)
        try:
            spec = importlib.util.spec_from_file_location('office_candidate', ROOT / 'packaging/greyward-office/prepare-update.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            sys.path.remove(directory)

    def fixture(self, temporary, version):
        from types import SimpleNamespace
        repo = Path(temporary) / 'repo'
        directory = repo / 'packaging/greyward-office'
        directory.mkdir(parents=True)
        font = 'a' * 40
        manifest = {'rpmRelease': 5, 'applications': [
            {'slug': 'writer', 'upstream': 'wordcraft', 'version': '0.10.0',
             'fontsCommit': font, 'adaptedInputs': {'ui.rs': hashlib.sha256(b'unchanged').hexdigest()},
             'patch': 'writer.patch'},
            {'slug': 'sheets', 'version': '0.11.1'}, {'slug': 'pdf', 'version': '0.13.0'},
            {'slug': 'slides', 'version': '0.10.0'}]}
        (directory / 'source.json').write_text(json.dumps(manifest))
        tree = Path(temporary) / 'tree'
        (tree / '.github/workflows').mkdir(parents=True)
        (tree / '.github/workflows/release.yml').write_text('fonts: ' + font)
        (tree / 'ui.rs').write_bytes(b'unchanged')
        (tree / 'Cargo.lock').write_bytes(b'locked-candidate-dependencies')
        return SimpleNamespace(repo=repo, application='writer', version=version,
                               output=Path(temporary) / 'candidate.json'), tree, manifest

    def test_updating_one_app_never_rolls_back_sibling_rpm_revisions(self):
        import io
        module = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            args, tree, original = self.fixture(temporary, '0.10.1')
            release = {'tag_name': 'v0.10.1', 'prerelease': False, 'draft': False}
            commit = 'b' * 40
            replies = [io.BytesIO(json.dumps(release).encode()), io.BytesIO(b'candidate-archive')]
            with patch.object(module.urllib.request, 'urlopen', side_effect=replies), \
                 patch.object(module.subprocess, 'check_output', return_value=commit + '\trefs/tags/v0.10.1\n'), \
                 patch.object(module.subprocess, 'run'), patch.object(module, 'extract', return_value=tree):
                module.candidate(args)
            candidate = json.loads(args.output.read_text())
            self.assertTrue(candidate['candidateOnly'])
            self.assertGreater(candidate['rpmRelease'], original['rpmRelease'])
            self.assertEqual(candidate['applications'][1:], original['applications'][1:])
            self.assertEqual(candidate['applications'][0]['version'], '0.10.1')
            self.assertEqual(candidate['applications'][0]['cargoLockSha256'],
                             hashlib.sha256(b'locked-candidate-dependencies').hexdigest())
            self.assertEqual(json.loads((args.repo / 'packaging/greyward-office/source.json').read_text()), original)

    def test_equal_or_older_versions_are_rejected_before_network_access(self):
        module = self.module()
        for version in ('0.10.0', '0.9.9'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                args, _, _ = self.fixture(temporary, version)
                with patch.object(module.urllib.request, 'urlopen') as network:
                    with self.assertRaisesRegex(ValueError, 'newer stable'):
                        module.candidate(args)
                    network.assert_not_called()
                    self.assertFalse(args.output.exists())


class OfficeAssociationMigrationTests(unittest.TestCase):
    def test_user_browser_and_custom_choices_survive_retired_handler_cleanup(self):
        spec = importlib.util.spec_from_file_location('office_mimes', ROOT / 'packaging/greyward-office/migrate-associations.py')
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        current = ('[Default Applications]\ntext/html=custom.browser.desktop;\n'
                   'application/pdf=custom.pdf.desktop;org.gnome.Papers.desktop;\n'
                   'application/vnd.ms-powerpoint=com.collaboraoffice.Office.desktop;\n'
                   '[Added Associations]\nimage/png=custom.image.desktop;\n'
                   '[Removed Associations]\napplication/pdf=org.gnome.Papers.desktop;\n')
        output = migration.migrate(current, (ROOT / 'environment/flatpak/mimeapps.list').read_text())
        parsed = migration.parser()
        parsed.read_string(output)
        self.assertEqual(parsed['Default Applications']['text/html'], 'custom.browser.desktop;')
        self.assertEqual(parsed['Default Applications']['application/pdf'],
                         'custom.pdf.desktop;systems.mantis.greyward.PDF.desktop;')
        self.assertNotIn('application/vnd.ms-powerpoint', parsed['Default Applications'])
        self.assertNotIn('application/pdf', parsed['Removed Associations'])
        self.assertEqual(parsed['Added Associations']['image/png'], 'custom.image.desktop;')


if __name__ == '__main__':
    unittest.main()
