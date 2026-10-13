"""Shared vector catalog and scoped launch boundaries, no desktop mutations."""
import importlib.util
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

    def test_resource_overlay_is_icon_only_and_attested_elf_is_still_packaged(self):
        launcher=(ROOT/'environment/session/desktop/strata-launcher').read_text()
        self.assertIn('export G_RESOURCE_OVERLAYS=/io/github/lgse/Strata/icons=/usr/share/greyward/files/strata-resources/icons',launcher)
        self.assertNotIn('/io/github/lgse/Strata=',launcher)
        spec=(ROOT/'packaging/greyward-files/greyward-files.spec').read_text()
        self.assertIn('Attested executable changed during packaging',spec)
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
