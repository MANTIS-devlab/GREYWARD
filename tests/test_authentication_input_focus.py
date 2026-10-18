"""Explicit Fedora offscreen gate; never joins the installed graphical session.

Set GREYWARD_AUTH_FOCUS_SHELL to an assembled authentication shell. Optionally
set GREYWARD_AUTH_FOCUS_BASELINE to its previous generation to verify the
negative control. Requires root for a child-only network namespace, QtTest and
Quickshell. No real Polkit flow, password or USBGuard mutation is involved.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HARNESS = '''import QtQuick
import QtQuick.Window
import QtTest
import Quickshell
import qs.Modals
import qs.Common
import qs.DankCommon.Common as DC
ShellRoot {
 id: root
 property bool authorizationActive: true
 QtObject { id: sessionLock; property bool secure: true }
 QtObject {
  id: fakeFlow
  property bool isResponseRequired: true
  property bool responseVisible: false
  property string inputPrompt: "Synthetic"
  property string message: "Offscreen only"
  signal authenticationSucceeded()
  signal authenticationFailed()
  signal authenticationRequestCancelled()
 }
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 FloatingWindow { id: otherWindow; implicitWidth:100; implicitHeight:100; visible:false }
 FloatingWindow {
  id: lockSurface; implicitWidth:800; implicitHeight:500; visible:true
  Item { id: alternate; focus:false }
  @@GENERATED_AUTHORIZATION@@
  TestEvent { id: events }
  Timer { interval:150; running:true; onTriggered:alternate.forceActiveFocus() }
  Timer { interval:220; running:true; onTriggered: {
   console.info("BUTTON_FOCUS_PRESERVED",alternate.activeFocus);
   otherWindow.visible=true;
   otherWindow.contentItem.Window.window.requestActivate();
  } }
  Timer { interval:300; running:true; onTriggered:lockSurface.contentItem.Window.window.requestActivate() }
  Timer { interval:650; running:true; onTriggered: {
   const delivered=events.keyClickChar("s",Qt.NoModifier,0);
   const accepted=authorizationContent.item.passwordInput==="s";
   console.info("LATE_ENTRY_PROOF", "acceptedSyntheticInput="+accepted, "delivered="+delivered);
   Qt.exit(accepted?0:3);
  } }
 }
 Timer { interval:5000; running:true; onTriggered:Qt.exit(2) }
}
'''


@unittest.skipUnless(os.name == 'posix' and os.environ.get('GREYWARD_AUTH_FOCUS_SHELL'),
                     'explicit Fedora assembled-shell focus gate')
class AuthenticationInputFocus(unittest.TestCase):
    def run_shell(self, source):
        self.assertEqual(os.geteuid(), 0, 'child-only network isolation requires root')
        with tempfile.TemporaryDirectory(prefix='greyward-focus-') as temporary:
            base = Path(temporary)
            tree = base / 'shell'
            shutil.copytree(source, tree)
            lock = (tree / 'Modules/Lock/Lock.qml').read_text()
            start = lock.index('            Loader {\n                id: authorizationContent')
            end = lock.index('            Loader {\n                anchors.fill: parent\n                active: !root.authorizationActive', start)
            generated = lock[start:end].replace('sourceComponent: PolkitAuthContent {',
                                               'sourceComponent: PolkitAuthContent {\n currentFlow: fakeFlow')
            harness = tree / 'focus-proof.qml'
            harness.write_text(HARNESS.replace('@@GENERATED_AUTHORIZATION@@', generated))
            for name in ('home', 'runtime'):
                (base / name).mkdir(mode=0o700)
            env = dict(os.environ, HOME=str(base / 'home'), XDG_RUNTIME_DIR=str(base / 'runtime'),
                       XDG_CONFIG_HOME=str(base / 'home/config'), XDG_CACHE_HOME=str(base / 'home/cache'),
                       XDG_STATE_HOME=str(base / 'home/state'), QT_QPA_PLATFORM='offscreen',
                       QT_QUICK_BACKEND='software', DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent',
                       DMS_DISABLE_POLKIT='1')
            return subprocess.run(['unshare', '-n', 'qs', '-p', str(harness)], env=env,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)

    def test_late_window_entry_restores_input_without_stealing_button_focus(self):
        baseline = os.environ.get('GREYWARD_AUTH_FOCUS_BASELINE')
        if baseline:
            old = self.run_shell(baseline)
            self.assertEqual(old.returncode, 3, old.stdout)
            self.assertIn('acceptedSyntheticInput=false delivered=true', old.stdout)
        result = self.run_shell(os.environ['GREYWARD_AUTH_FOCUS_SHELL'])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('BUTTON_FOCUS_PRESERVED true', result.stdout)
        self.assertIn('acceptedSyntheticInput=true delivered=true', result.stdout)


if __name__ == '__main__':
    unittest.main()
