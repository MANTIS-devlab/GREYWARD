"""Real protected QML on a private display; no real credentials or Polkit.

GREYWARD_AUTH_FOCUS_SHELL selects an exact assembled shell. Optional
GREYWARD_AUTH_PREVIEW_DIR exports synthetic renders for visual inspection.
"""
import importlib.util
import json
import os
from pathlib import Path
import unittest

import test_authentication_input_focus as focus

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('presentation_assembly', ROOT /
    'security-center/packaging/application-security/authentication/assemble.py')
assembly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembly)

HARNESS = '''import QtQuick
import QtQuick.Window
import QtQuick.Shapes
import QtTest
import Quickshell
import qs.Common
import qs.Services
import qs.Modals
import qs.DCommon.Widgets
import qs.DCommon.Common as DC
ShellRoot {
 id: root
 property bool authorizationActive: true
 property string authorizationScreenName: "synthetic-owner"
 property int authorizationPasswordLength: 0
 property var authorizationController: content
 property int cancelled: 0
 property int submitted: 0
 QtObject { id: sessionLock; property bool secure: true }
 QtObject {
  id: fakeFlow
  property bool isResponseRequired: true
  property bool responseVisible: false
  property string inputPrompt: "Password"
  property string message: "Authentication is required to approve this USB device."
  property string supplementaryMessage: ""
  property bool supplementaryIsError: false
  function submit(value) { if (value === "synthetic") root.submitted++; }
  function cancelAuthenticationRequest() { root.cancelled++; }
  signal authenticationSucceeded()
  signal authenticationFailed()
  signal authenticationRequestCancelled()
 }
 function find(item, name) {
  if (item.objectName === name) return item;
  for (const child of item.children ?? []) {
   const result = find(child, name); if (result) return result;
  }
  return null;
 }
 function check(ok, message) { if (!ok) { console.error(message); Qt.exit(3); } }
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 FloatingWindow {
  id: lockSurface
  implicitWidth: 900; implicitHeight: 680; visible: true; color: "#090B0D"
  Item {
   id: page; anchors.fill: parent
   PolkitAuthContent {
    id: content; anchors.fill: parent; currentFlow: fakeFlow
   }
   Item { id: mirror; anchors.fill: parent; visible: false
    @@MIRROR@@
   }
  }
  TestEvent { id: events }
  property int phase: 0
  Timer { interval: 180; running: true; repeat: true; onTriggered: {
   const card = root.find(content, "greywardAuthorizationCard");
   const viewport = root.find(content, "greywardAuthorizationViewport");
   const approve = root.find(content, "greywardAuthorizationSubmit");
   const cancel = root.find(content, "greywardAuthorizationCancel");
   root.check(card && viewport && approve && cancel, "Missing protected controls");
   switch (lockSurface.phase++) {
    case 0:
     root.check(card.width <= 640 && card.height <= page.height && card.y >= 0, "Card outside viewport");
     if (@@EXPORT@@ !== "") page.grabToImage(result => result.saveToFile(@@EXPORT@@ + "/polkit-normal.png"));
     break;
    case 1:
     content.passwordInput = "synthetic";
     content.isLoading = true;
     break;
    case 2:
     root.check(!approve.enabled && !cancel.enabled, "Busy actions remained enabled");
     content.isLoading = false;
     approve.forceActiveFocus();
     events.keyClick(Qt.Key_Return, Qt.NoModifier, 0);
     root.check(root.submitted === 1, "Keyboard submit failed");
     content.reset();
     events.mouseClick(cancel, cancel.width / 2, cancel.height / 2, Qt.LeftButton, Qt.NoModifier, 0);
     root.check(root.cancelled === 1, "Mouse cancel did not reach the flow");
     cancel.forceActiveFocus();
     events.keyClick(Qt.Key_Space, Qt.NoModifier, 0);
     root.check(root.cancelled === 2, "Keyboard cancel failed");
     events.keyClick(Qt.Key_Escape, Qt.NoModifier, 0);
     root.check(root.cancelled === 3, "Escape cancel failed");
     fakeFlow.message = "<b>Literal request</b> " + "Long authorization details. ".repeat(30);
     content.anchors.leftMargin = 270; content.anchors.rightMargin = 270;
     content.anchors.topMargin = 170; content.anchors.bottomMargin = 170;
     break;
    case 3:
     root.check(viewport.contentHeight > viewport.height && card.width <= content.width, "Small viewport cannot scroll");
     root.check(root.find(content, "greywardAuthorizationMessage").textFormat === Text.PlainText, "Request interpreted markup");
     approve.forceActiveFocus();
     break;
    case 4:
     root.check(viewport.contentY > 0, "Keyboard focus did not reveal actions");
     if (@@EXPORT@@ !== "") page.grabToImage(result => result.saveToFile(@@EXPORT@@ + "/polkit-narrow.png"));
     break;
    case 5:
     content.anchors.margins = 0;
     fakeFlow.message = "Authentication is required to approve this USB device.";
     root.authorizationPasswordLength = 4;
     content.visible = false; mirror.visible = true;
     break;
    case 6:
     const remoteApprove = root.find(mirror, "greywardAuthorizationSubmit");
     root.check(remoteApprove && remoteApprove.enabled, "Mirror controls did not load");
     if (@@EXPORT@@ !== "") page.grabToImage(result => result.saveToFile(@@EXPORT@@ + "/polkit-mirror.png"));
     content.isLoading = true;
     break;
    case 7:
     root.check(!root.find(mirror, "greywardAuthorizationSubmit").enabled, "Mirror ignored busy state");
     console.info("AUTHORIZATION_PRESENTATION_PASSED"); Qt.exit(0); break;
   }
  } }
 }
 Timer { interval: 7000; running: true; onTriggered: Qt.exit(2) }
}
'''


@unittest.skipUnless(os.name == 'posix' and os.environ.get('GREYWARD_AUTH_FOCUS_SHELL'),
                     'explicit assembled DMS 2.0 private-display presentation gate')
class AuthenticationPresentation(unittest.TestCase):
    def test_external_screen_actions_and_cancel_without_input_controller(self):
        shell = Path(os.environ['GREYWARD_AUTH_FOCUS_SHELL'])
        lock = (shell / 'Modules/Lock/Lock.qml').read_text()
        start = lock.index('    onAuthorizationActiveChanged: {')
        end = lock.index('    Connections {\n        target: Quickshell', start)
        lifecycle = lock[start:end]
        start = lock.index('            Loader {\n                id: authorizationContent')
        end = lock.index('            Loader {\n                anchors.fill: parent\n                active: !root.authorizationActive', start)
        # Keep the real Loader/focus controller, but omit the second native lock
        # form and replace only the read-only flow binding with a synthetic one.
        loader = lock[start:end]
        remote = loader.index('            Rectangle {\n                id: remoteAuthorizationCard')
        loader = loader[:remote].replace('sourceComponent: PolkitAuthContent {',
            'sourceComponent: PolkitAuthContent {\n currentFlow: fakeFlow')
        start = lock.index('            Rectangle {\n                id: remoteAuthorizationCard')
        end = lock.index('\n            Connections {\n                target: sessionLock', start)
        mirror = lock[start:end]
        mirror = mirror.replace('PolkitService.agent?.flow', 'fakeFlow')
        mirror = mirror.replace('lockSurface.screen?.name !== root.authorizationScreenName',
                                '"synthetic-external" !== root.authorizationScreenName')
        harness = '''import QtQuick
import QtQuick.Window
import QtQuick.Shapes
import QtTest
import Quickshell
import qs.Common
import qs.Services
import qs.Modals
import qs.DCommon.Widgets
import qs.DCommon.Common as DC
ShellRoot {
 id: root
 property bool authorizationActive: false
 property string authorizationScreenName: ""
 property int authorizationPasswordLength: 0
 property var authorizationController: null
 property bool authorizationWasLocked: false
 property bool authorizationPending: false
 property bool shouldLock: false
 property string sharedPasswordBuffer: ""
 property int cancelled: 0
 property int submitted: 0
 QtObject { id: sessionLock; property bool secure: true }
 QtObject {
  id: fakeFlow
  property bool isResponseRequired: true
  property bool responseVisible: false
  property string inputPrompt: "Password"
  property string message: "Synthetic external-screen cancellation"
  property string supplementaryMessage: ""
  property bool supplementaryIsError: false
  function cancelAuthenticationRequest() { root.cancelled++; }
  function submit(value) { if (value === "synthetic") root.submitted++; }
  signal authenticationSucceeded()
  signal authenticationFailed()
  signal authenticationRequestCancelled()
 }
 @@LIFECYCLE@@
 function find(item, name) {
  if (item.objectName === name) return item;
  for (const child of item.children ?? []) { const found=find(child,name); if (found) return found; }
  return null;
 }
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 FloatingWindow {
  id: lockSurface; implicitWidth: 900; implicitHeight: 680; visible: true
  @@LOADER@@
  Item { id: external; anchors.fill: parent
   @@MIRROR@@
  }
  TestEvent { id: events }
  Timer { interval: 180; running: true; onTriggered: root.authorizationActive=true }
  Timer { interval: 650; running: true; onTriggered: {
   const owner=root.authorizationController;
   if (!owner) { console.error("Input owner missing after request start"); Qt.exit(3); return; }
   owner.passwordInput="synthetic";
   const approve=root.find(external,"greywardAuthorizationSubmit");
   events.mouseClick(approve,approve.width/2,approve.height/2,Qt.LeftButton,Qt.NoModifier,0);
   if (root.submitted !== 1) { console.error("External submit did not reach the input owner"); Qt.exit(3); return; }
   owner.reset();
   const cancel=root.find(external,"greywardAuthorizationCancel");
   // Model a missing Loader proxy on another output. Cancel must reach the
   // shared flow even when no password-bearing controller can be consulted.
   root.authorizationController = null;
   const delivered=events.mouseClick(cancel,cancel.width/2,cancel.height/2,Qt.LeftButton,Qt.NoModifier,0);
   console.info("EXTERNAL_CANCEL", "controller="+(root.authorizationController !== null),
                "delivered="+delivered, "cancelled="+root.cancelled);
   Qt.exit(root.cancelled === 1 ? 0 : 3);
  } }
 }
 Timer { interval: 5000; running: true; onTriggered: Qt.exit(2) }
}
'''
        harness = harness.replace('@@LIFECYCLE@@', lifecycle).replace('@@LOADER@@', loader).replace('@@MIRROR@@', mirror)
        result = focus.AuthenticationInputFocus.run_shell(self, shell, harness)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('controller=false delivered=true cancelled=1', result.stdout)

    def test_keyboard_busy_mirror_and_constrained_layout(self):
        output = os.environ.get('GREYWARD_AUTH_PREVIEW_DIR', '')
        if output:
            Path(output).mkdir(parents=True, exist_ok=True)
        harness = HARNESS.replace('@@MIRROR@@', assembly.authorization_card(native=True, mirror=True))
        harness = harness.replace('PolkitService.agent?.flow', 'fakeFlow')
        harness = harness.replace('@@EXPORT@@', json.dumps(output))
        result = focus.AuthenticationInputFocus.run_shell(self, os.environ['GREYWARD_AUTH_FOCUS_SHELL'], harness)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('AUTHORIZATION_PRESENTATION_PASSED', result.stdout)
        self.assertNotIn('ReferenceError:', result.stdout)
        self.assertNotIn('TypeError:', result.stdout)


if __name__ == '__main__':
    unittest.main()
