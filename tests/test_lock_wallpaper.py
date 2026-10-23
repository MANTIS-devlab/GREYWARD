"""Pinned native lock rendering on a private display, never an installed lock."""
import importlib.util
import json
import os
from pathlib import Path
import unittest

import test_authentication_input_focus as focus

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lock_profile', ROOT /
    'security-center/packaging/application-security/desktop/materialize.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)

HARNESS = '''import QtQuick
import Quickshell
import qs.Common
import qs.Services
import qs.Modules.Lock
import qs.DCommon.Common as DC
ShellRoot {
 id: root
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 function loadedImage(item) {
  if (item.source !== undefined && String(item.source) === "file://" + @@WALLPAPER@@)
   return item.status === Image.Ready;
  for (const child of item.children ?? []) { if (loadedImage(child)) return true; }
  return false;
 }
 function directSoftwareImage(item) {
  if (item.wallpaperSource !== undefined && String(item.wallpaperSource) === "file://" + @@WALLPAPER@@)
   return item.layer.enabled === false;
  for (const child of item.children ?? []) { if (directSoftwareImage(child)) return true; }
  return false;
 }
 FloatingWindow {
  implicitWidth: 1280; implicitHeight: 720; visible: true
  LockScreenContent { id: content; anchors.fill: parent; screenName: Quickshell.screens[0]?.name ?? "" }
  Timer { interval: 1800; running: true; onTriggered: {
   const loaded = SettingsData._hasLoaded && SettingsData.lockScreenWallpaperPath === @@WALLPAPER@@;
   const rendered = root.loadedImage(content.backgroundItem);
   const direct = root.directSoftwareImage(content.backgroundItem);
   const themed = Theme.currentTheme === "custom" && String(Theme.surface) === "#050607";
   const clock = SettingsData.lockWidgetInstance("desktopClock")?.config;
   const auth = SettingsData.lockWidgetInstance("lockAuth")?.config;
   console.info("LOCK_APPEARANCE", "loaded="+loaded, "imageReady="+rendered, "themed="+themed);
   if (!loaded || !rendered || !direct || !themed || clock?.twoTone !== false || clock?.style !== "digital"
       || auth?.style !== "pill" || auth?.profileVisibility !== "never") { Qt.exit(3); return; }
   if (@@PREVIEW@@ !== "") {
    content.grabToImage(result => { result.saveToFile(@@PREVIEW@@); Qt.exit(0); });
   } else Qt.exit(0);
  } }
 }
 Timer { interval: 6000; running: true; onTriggered: Qt.exit(2) }
}
'''


@unittest.skipUnless(os.name == 'posix' and os.environ.get('GREYWARD_LOCK_SHELL'),
                     'explicit native protected-shell wallpaper test')
class LockWallpaper(unittest.TestCase):
    def test_real_settings_theme_and_decoded_wallpaper_without_config_folder_worker(self):
        settings = profile.authentication_settings({'currentThemeName': 'custom',
            'customThemeFile': '/usr/share/greyward/dms/greyward-obsidian.json'}, 42)
        wallpaper = settings['lockScreenWallpaperPath']
        self.assertTrue(Path(wallpaper).is_file(), 'Installed canonical wallpaper fixture required')
        harness = HARNESS.replace('@@WALLPAPER@@', json.dumps(wallpaper))
        harness = harness.replace('@@PREVIEW@@', json.dumps(os.environ.get('GREYWARD_LOCK_PREVIEW', '')))
        baseline = os.environ.get('GREYWARD_LOCK_BASELINE')
        if baseline:
            old = focus.AuthenticationInputFocus.run_shell(self, baseline, harness,
                settings=settings, stalled_discovery=True)
            self.assertEqual(old.returncode, 3, old.stdout)
            self.assertIn('loaded=false', old.stdout)
        result = focus.AuthenticationInputFocus.run_shell(self, os.environ['GREYWARD_LOCK_SHELL'],
            harness, settings=settings, stalled_discovery=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('loaded=true imageReady=true themed=true', result.stdout)
        self.assertNotIn('ReferenceError:', result.stdout)


if __name__ == '__main__':
    unittest.main()
