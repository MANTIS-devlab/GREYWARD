"""Shared vector catalog and scoped launch boundaries, no desktop mutations."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('file_icon_family',ROOT/'tools/generate-file-icons.py')
icons=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(icons)
CATALOG=ROOT/'branding/source/greyward-icon-family.json'


class FileIconFamily(unittest.TestCase):
    def test_extension_resources_and_native_mime_icons_use_identical_artwork(self):
        model=json.loads(CATALOG.read_text())
        with tempfile.TemporaryDirectory() as directory:
            upstream=Path(directory)/'upstream'
            actions=upstream/'data/icons/scalable/actions'
            actions.mkdir(parents=True)
            # Non-original geometry makes any old-extension carryover visible.
            simple=icons.svg('<path d="M1 1h2"/>')
            required={x for x in model['folderBadges'].values() if x}
            required.update(x[0] for x in model['mimeTypes'].values())
            required.update(x[0] for x in model['objects'].values())
            required.add('folder')
            required.update(('arrow-down','arrow-up','plus'))
            for name in required:
                (actions/f'strata-{name}.svg').write_text(simple)
            extensions=upstream/'data/icons/catppuccin'
            extensions.mkdir()
            names=('python','rust','markdown','readme','config','bash','database','unfamiliar-language')
            for name in names:
                (extensions/f'strata-ctp-{name}.svg').write_text(icons.svg('<circle cx="2" cy="2" r="1" fill="#ff00ff"/>'))
            licenses=upstream/'data/licenses'
            licenses.mkdir()
            for name in ('Lucide-ISC.txt','Catppuccin-VSCode-Icons-MIT.txt'):
                (licenses/name).write_text('Synthetic test notice')
            destination=Path(directory)/'generated'
            icons.generate(CATALOG,upstream,destination)
            for name in names:
                kind=model['strataFileKinds']['overrides'].get(name,model['strataFileKinds']['default'])
                native=destination/'theme/Greyward/scalable/mimetypes'/f'{kind}.svg'
                resource=destination/'strata/icons/catppuccin'/f'strata-ctp-{name}.svg'
                self.assertEqual(native.read_bytes(),resource.read_bytes(),name)
                self.assertNotIn(b'#ff00ff',resource.read_bytes())
            original=(ROOT/'branding/source/greyward-files.svg').read_bytes()
            self.assertEqual(original,(destination/'strata/icons/scalable/apps/io.github.lgse.Strata.svg').read_bytes())
            self.assertEqual(original,(destination/'theme/Greyward/scalable/apps/io.github.lgse.Strata.svg').read_bytes())

    def test_shared_folder_and_document_frames_are_bounded_valid_vectors(self):
        model=json.loads(CATALOG.read_text())
        palette=model['palette']
        for content in (icons.folder(palette),icons.document(palette,'',palette['blue']),icons.tile(palette,'',palette['muted'])):
            root=ET.fromstring(content)
            self.assertEqual(root.attrib['viewBox'],'0 0 24 24')
            self.assertLess(len(content),65536)
            self.assertNotIn('filter=',content)
            self.assertNotIn('<image',content)
        self.assertNotEqual(icons.folder(palette),icons.document(palette,'',palette['blue']))

    def test_catalog_covers_common_objects_without_reusing_unrelated_marks(self):
        model=json.loads(CATALOG.read_text())
        self.assertEqual(model['folderBadges']['folder'],None)
        self.assertEqual(model['folderBadges']['inode-directory'],None)
        self.assertEqual(model['folderBadges']['user-home'],'house')
        self.assertNotEqual(model['mimeTypes']['application-pdf'],model['mimeTypes']['text-x-generic'])
        self.assertNotEqual(model['mimeTypes']['application-zip'],model['mimeTypes']['image-png'])
        self.assertIn('application-vnd.oasis.opendocument.text',model['mimeTypes'])
        self.assertIn('drive-removable-media-usb',model['objects'])

    def test_resource_overlay_is_icon_only_and_source_patch_closure_is_pinned(self):
        launcher=(ROOT/'environment/session/desktop/strata-launcher').read_text()
        self.assertIn('export G_RESOURCE_OVERLAYS=/io/github/lgse/Strata/icons=/usr/share/greyward/files/strata-resources/icons',launcher)
        self.assertNotIn('/io/github/lgse/Strata=',launcher)
        spec=(ROOT/'packaging/greyward-files/greyward-files.spec').read_text()
        self.assertIn('Built executable changed during packaging',spec)
        self.assertIn('cargo build --release --frozen --offline',spec)
        self.assertIn('--test greyward_native_icons',spec)
        source=json.loads((ROOT/'packaging/greyward-files/source.json').read_text())
        self.assertEqual(set(source['sourcePatches']),{'strata-preview-mode.patch','strata-native-icons.patch'})
        for name,digest in source['sourcePatches'].items():
            patch=(ROOT/'packaging/greyward-files'/name).read_bytes().replace(b'\r\n',b'\n')
            self.assertEqual(hashlib.sha256(patch).hexdigest(),digest,name)
        for name,digest in source['inputs']['desktop']['patches'].items():
            data=(ROOT/'packaging/greyward-files'/name).read_bytes().replace(b'\r\n',b'\n')
            self.assertEqual(hashlib.sha256(data).hexdigest(),digest,name)
        for name,digest in source['inputs']['desktop']['integrationInputs'].items():
            data=(ROOT/name).read_bytes().replace(b'\r\n',b'\n')
            self.assertEqual(hashlib.sha256(data).hexdigest(),digest,name)
        self.assertEqual(len(source['inputs']['vendor']['sha256']),64)
        self.assertIn('/usr/share/icons/Greyward',spec)
        self.assertIn('icons-build/LICENSES',spec)

    def test_external_or_active_icon_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.svg'
            for content in ('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>',
                            '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.invalid/image"/></svg>',
                            '<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>'):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    icons.svg_body(path)

    def test_native_desktop_theme_selection_is_scoped_and_uses_supported_setting(self):
        settings=(ROOT/'environment/session/desktop/settings.conf').read_text().splitlines()
        self.assertIn('FallbackIconThemeName=Greyward',settings)
        self.assertFalse(any(line.startswith('IconThemeName=') for line in settings))
        style=(ROOT/'environment/session/desktop/style/obsidian.cpp').read_text()
        self.assertIn('QIcon::setThemeName(QStringLiteral("Greyward"))',style)
        launcher=(ROOT/'environment/session/greyward-desktop-icons').read_text()
        self.assertIn('QT_STYLE_OVERRIDE=GreywardDesktop',launcher)


if __name__=='__main__':
    unittest.main()
