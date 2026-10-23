"""Explicit Linux candidate UI checks in a private headless display, no live bus."""
import os
import importlib.util
import json
from pathlib import Path
import re
import unittest
import test_authentication_input_focus as focus

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('GREYWARD_DMS20_SHELL'), 'explicit pinned DMS 2.0 shell')
class Dms20Schema(unittest.TestCase):
    def test_protected_profile_matches_actual_native_settings_schema(self):
        source = (Path(os.environ['GREYWARD_DMS20_SHELL']) / 'Common/SettingsData.qml').read_text()
        versions = re.findall(r'\breadonly\s+property\s+int\s+settingsConfigVersion\s*:\s*(\d+)\b', source)
        self.assertEqual(len(versions), 1, 'Upstream settings schema declaration changed')
        manifest = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
        spec = importlib.util.spec_from_file_location('native_profile_schema',
            ROOT / 'security-center/packaging/application-security/desktop/materialize.py')
        profile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profile)
        self.assertEqual(profile.authentication_profile(manifest['releaseId'])[2], int(versions[0]))
        self.assertEqual(manifest['dms']['settingsConfigVersion'], int(versions[0]))

HARNESS = '''import QtQuick
import Quickshell
import qs.Common
import qs.DCommon.Common as DC
import qs.Modals.Settings
import qs.Modules.Settings
ShellRoot {
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 FloatingWindow {
  implicitWidth:900; implicitHeight:650; visible:true
  SettingsContent { id: registry; visible:false }
  GreywardManagedTab { id: managed; anchors.fill:parent; managedPage:"updater" }
 }
 Timer { interval:700; running:true; onTriggered: {
  const pages=["users","user_create","lock_screen","greeter","greeter_auth","updater"];
  for (const page of pages) {
   if (registry.pageFiles[page] !== "GreywardManagedTab.qml") { Qt.exit(4); return; }
   const properties=registry._propertiesFor(page);
   if (properties.managedPage !== page) { Qt.exit(5); return; }
  }
  if (!managed.isUpdates || managed.isAccounts) { Qt.exit(6); return; }
  managed.managedPage="user_create";
  if (managed.isUpdates || !managed.isAccounts) { Qt.exit(7); return; }
  managed.managedPage="greeter_auth";
  if (managed.isUpdates || managed.isAccounts) { Qt.exit(8); return; }
  console.info("MANAGED_SETTINGS_ROUTING_PASSED");
  Qt.exit(0);
 } }
 Timer { interval:5000; running:true; onTriggered:Qt.exit(2) }
}
'''

@unittest.skipUnless(os.name == 'posix' and os.environ.get('GREYWARD_DMS20_SHELL'),
                     'explicit Linux assembled DMS 2.0 shell')
class Dms20Shell(unittest.TestCase):
    def test_managed_pages_load_and_direct_routes_do_not_open_upstream_mutators(self):
        result = focus.AuthenticationInputFocus.run_shell(self, os.environ['GREYWARD_DMS20_SHELL'], HARNESS)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('MANAGED_SETTINGS_ROUTING_PASSED', result.stdout)

    @unittest.skipUnless(os.environ.get('GREYWARD_DMS20_AUTH_SHELL'), 'explicit protected 2.0 derivative')
    def test_complete_native_lock_component_loads_without_an_authorization_request(self):
        harness = '''import QtQuick
import Quickshell
import qs.Common
import qs.DCommon.Common as DC
import qs.Modules.Lock
import qs.Services
ShellRoot {
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 Lock { id: protectedLock }
 Timer { interval:700; running:true; onTriggered: {
  if (protectedLock.authorizationActive || protectedLock.shouldLock || protectedLock.sharedPasswordBuffer !== "") {
   Qt.exit(3); return;
  }
  if (Object.keys(PluginService.loadedPlugins).length || PluginService.pluginDirectory !== "" || PluginService.systemPluginDirectory !== "") {
   Qt.exit(4); return;
  }
  console.info("PROTECTED_LOCK_COMPONENT_LOADED");
  Qt.exit(0);
 } }
 Timer { interval:5000; running:true; onTriggered:Qt.exit(2) }
}
'''
        result = focus.AuthenticationInputFocus.run_shell(self, os.environ['GREYWARD_DMS20_AUTH_SHELL'], harness)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('PROTECTED_LOCK_COMPONENT_LOADED', result.stdout)


if __name__ == '__main__':
    unittest.main()
