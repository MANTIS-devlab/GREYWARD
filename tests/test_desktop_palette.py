"""Shared adapters must stay closed and text must remain readable in both modes."""
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('desktop_palette', ROOT / 'tools/generate-desktop-theme.py')
palette = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(palette)


def luminance(color):
    channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in channels]
    return sum(v * weight for v, weight in zip(linear, (.2126, .7152, .0722)))


class DesktopPalette(unittest.TestCase):
    def test_shell_uses_reference_dark_surfaces_without_recoloring_applications(self):
        generated = palette.outputs(palette.load())
        shell = json.loads(generated[ROOT / 'environment/session/dankmaterialshell/greyward-obsidian.json'])
        self.assertEqual(shell['dark']['surface'], '#050607')
        self.assertEqual(shell['dark']['surfaceVariant'], '#101214')
        self.assertEqual(shell['dark']['surfaceContainer'], '#16191C')
        self.assertEqual(shell['dark']['matugen_type'], 'scheme-monochrome')
        self.assertIn(b'--graphite: #171A1D;', generated[ROOT / 'security-center/tauri/frontend/theme-tokens.css'])
        for mode in ('dark', 'light'):
            colors = shell[mode]
            for foreground, background in (('surfaceText', 'surface'), ('surfaceVariantText', 'surfaceVariant'),
                                           ('onPrimary', 'primary'), ('onPrimaryContainer', 'primaryContainer')):
                low, high = sorted((luminance(colors[foreground]), luminance(colors[background])))
                self.assertGreaterEqual((high+.05)/(low+.05), 4.5, (mode, foreground, background))

    def test_dashboard_status_text_remains_readable_on_its_tinted_surface(self):
        for mode in ('dark', 'light'):
            colors = palette.load()[mode]
            weight = .035 if mode == 'light' else .065
            for role in ('positive', 'warning', 'error'):
                tint = '#' + ''.join(f'{round(int(colors["soft"][i:i+2],16)*(1-weight)+int(colors[role][i:i+2],16)*weight):02x}' for i in (1,3,5))
                low, high = sorted((luminance(colors[role]), luminance(tint)))
                self.assertGreaterEqual((high+.05)/(low+.05), 4.5, (mode, role, tint))

    def test_generated_adapters_are_current_and_palette_has_one_owner(self):
        for path, expected in palette.outputs(palette.load()).items():
            self.assertEqual(path.read_bytes(), expected, str(path))
        frontend = ROOT / 'security-center/tauri/frontend'
        tokens = (frontend / 'theme-tokens.css').read_text(encoding='utf-8')
        materials = (frontend / 'materials.css').read_text(encoding='utf-8')
        for name in re.findall(r'  (--[a-z-]+):', tokens):
            self.assertNotRegex(materials, re.escape(name) + r'\s*:')
        index = (frontend / 'index.html').read_text(encoding='utf-8')
        self.assertLess(index.index('./theme-tokens.css'), index.index('./materials.css'))

    def test_body_labels_and_semantic_text_have_accessible_contrast(self):
        for mode in ('dark', 'light'):
            colors = palette.load()[mode]
            for foreground, background in (('text', 'surface'), ('muted', 'surface'),
                                           ('text', 'raised'), ('onPrimary', 'primary'),
                                           ('positive', 'surface'), ('warning', 'surface'),
                                           ('error', 'surface'), ('uncertain', 'surface')):
                light, dark = sorted((luminance(colors[foreground]), luminance(colors[background])))
                self.assertGreaterEqual((dark + .05) / (light + .05), 4.5,
                                        (mode, foreground, background))


if __name__ == '__main__':
    unittest.main()
