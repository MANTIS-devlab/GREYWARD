"""Explicit Fedora offscreen gate; never joins the installed graphical session.

Set GREYWARD_AUTH_FOCUS_SHELL to an assembled authentication shell. Optionally
set GREYWARD_AUTH_FOCUS_BASELINE to its previous generation to verify the
negative control. Requires root for a child-only network namespace, QtTest and
Quickshell. No real Polkit flow, password or USBGuard mutation is involved.
"""
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


HARNESS = '''import QtQuick
import QtQuick.Window
import QtQuick.Shapes
import QtTest
import Quickshell
import qs.Modals
import qs.Common
import qs.Services
import qs.DankCommon.Common as DC
ShellRoot {
 id: root
 property bool authorizationActive: true
 property string authorizationScreenName: Quickshell.screens[0]?.name ?? ""
 property int authorizationPasswordLength: 0
 property var authorizationController: null
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
    def run_shell(self, source, harness_source=None, settings=None, stalled_discovery=False):
        self.assertEqual(os.geteuid(), 0, 'child-only network isolation requires root')
        with tempfile.TemporaryDirectory(prefix='greyward-focus-') as temporary:
            base = Path(temporary)
            tree = base / 'shell'
            shutil.copytree(source, tree)
            if stalled_discovery:
                # Reproduce an unavailable folder worker in this disposable
                # tree. The protected single-file adapter never waits for it.
                path = tree / 'Common/SettingsData.qml'
                path.write_text(path.read_text().replace(
                    'id: settingsFolderLoader\n        active: !isGreeterMode',
                    'id: settingsFolderLoader\n        active: false'))
            harness = tree / 'focus-proof.qml'
            if harness_source is None:
                lock = (tree / 'Modules/Lock/Lock.qml').read_text()
                start = lock.index('            Loader {\n                id: authorizationContent')
                end = lock.index('            Loader {\n                anchors.fill: parent\n                active: !root.authorizationActive', start)
                generated = lock[start:end].replace('sourceComponent: PolkitAuthContent {',
                                                   'sourceComponent: PolkitAuthContent {\n currentFlow: fakeFlow')
                template = HARNESS.replace('qs.DankCommon.Common', 'qs.DCommon.Common').replace('import qs.Common\n', 'import qs.Common\nimport qs.DCommon.Widgets\n') if (tree / 'DCommon').is_dir() else HARNESS
                if (tree / 'DCommon').is_dir():
                    # Wayland ignores arbitrary requestActivate() calls. Closing
                    # the temporary child produces a real keyboard-enter handoff.
                    template = template.replace('onTriggered:lockSurface.contentItem.Window.window.requestActivate()',
                        'onTriggered: { otherWindow.visible=false; lockSurface.contentItem.Window.window.requestActivate(); }')
                template = template.replace('@@GENERATED_AUTHORIZATION@@', generated)
            else:
                template = harness_source
            harness.write_text(template, encoding='utf-8')
            for name in ('home', 'runtime'):
                (base / name).mkdir(mode=0o700)
            if settings is not None:
                profile = base / 'home/config/dms'
                profile.mkdir(parents=True)
                (profile / 'settings.json').write_text(json.dumps(settings))
            env = dict(os.environ, HOME=str(base / 'home'), XDG_RUNTIME_DIR=str(base / 'runtime'),
                       XDG_CONFIG_HOME=str(base / 'home/config'), XDG_CACHE_HOME=str(base / 'home/cache'),
                       XDG_STATE_HOME=str(base / 'home/state'), QT_QPA_PLATFORM='offscreen',
                       QT_QUICK_BACKEND='software', DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent',
                       DMS_DISABLE_POLKIT='1')
            if not (tree / 'DCommon').is_dir():
                return subprocess.run(['unshare', '-n', 'qs', '-p', str(harness)], env=env,
                                      text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
            # 2.0's type registry includes PanelWindow-backed controls, which
            # cannot compile under Qt's offscreen platform. Use a new private
            # headless compositor; never connect to the installed user display.
            config = base / 'labwc'
            config.mkdir()
            (config / 'rc.xml').write_text('<labwc_config/>')
            (config / 'autostart').write_text('')
            env.update(QT_QPA_PLATFORM='wayland', WAYLAND_DISPLAY='wayland-0',
                       WLR_BACKENDS='headless', WLR_HEADLESS_OUTPUTS='1', WLR_RENDERER='pixman',
                       LIBGL_ALWAYS_SOFTWARE='1', XDG_CURRENT_DESKTOP='GREYWARD:labwc',
                       DBUS_SYSTEM_BUS_ADDRESS='unix:path=/nonexistent')
            with (base / 'compositor.log').open('w+') as log:
                display = subprocess.Popen(['unshare', '-n', 'labwc', '-C', str(config)],
                                           env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 5
                    while not (base / 'runtime/wayland-0').exists() and time.monotonic() < deadline:
                        if display.poll() is not None:
                            break
                        time.sleep(0.05)
                    if not (base / 'runtime/wayland-0').exists():
                        log.seek(0)
                        self.fail('Private headless compositor failed: ' + log.read())
                    return subprocess.run(['unshare', '-n', 'qs', '-p', str(harness)], env=env,
                                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
                finally:
                    display.terminate()
                    try:
                        display.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        display.kill()
                        display.wait(timeout=5)

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
