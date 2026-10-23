"""Explicit native DMS 2.0 plugin fixture; no installed bus or personal data."""
import json
import os
import shutil
from pathlib import Path
import tempfile
import unittest
import test_authentication_input_focus as focus

ROOT = Path(__file__).resolve().parents[1]
HARNESS = '''import QtQuick
import Quickshell
import qs.Common
import qs.Services
import qs.DCommon.Common as DC
import "PLUGINS/GreywardCandidate/greywardSecure" as Security
import "PLUGINS/GreywardCandidate/greywardNetwork" as Network
import "PLUGINS/GreywardCandidate/greywardPublicIp" as Identity
import "PLUGINS/GreywardCandidate/greywardNetworkTraffic" as Traffic
import "PLUGINS/GreywardCandidate/greywardSoftware" as Software
ShellRoot {
 id: root
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 Security.SecurityClient { id: client }
 QtObject {
  id: facade
  property var pluginDaemonInstances: ({greywardSecure:client})
  property var globalVars: ({})
  signal pluginDataChanged(string id)
  signal pluginStateChanged(string id)
  signal globalVarChanged(string id,string key)
  function loadPluginState(id,key,fallback) { return fallback; }
  function removePluginStateKey(id,key) {}
  function getGlobalVar(id,key,fallback) { return globalVars[id]?.[key] ?? fallback; }
  function setGlobalVar(id,key,value) {
   const updated=Object.assign({},globalVars); updated[id]=Object.assign({},updated[id]??{}); updated[id][key]=value;
   globalVars=updated; globalVarChanged(id,key);
  }
  function loadPluginData(id,key,fallback) { return fallback; }
  function getPluginVariants(id) { return []; }
 }
 Security.SecurityLauncher { id: search; pluginService:facade }
 FloatingWindow {
  implicitWidth:1000; implicitHeight:800; visible:true
  Security.SecureWidget { id: first; pluginId:"greywardSecure"; pluginService:facade; width:100; height:40 }
  Security.SecureWidget { id: second; pluginId:"greywardSecure"; pluginService:facade; x:150; width:100; height:40 }
  Identity.PublicIpWidget { id: identity; pluginId:"greywardPublicIp"; pluginService:facade; x:300; width:100; height:40 }
  Traffic.NetworkTrafficWidget { pluginId:"greywardNetworkTraffic"; pluginService:facade; x:420; width:100; height:40 }
  Software.SoftwareWidget { pluginId:"greywardSoftware"; pluginService:facade; x:540; width:100; height:40 }
  Network.Card { id: card; pluginService:facade; y:60; width:280; height:230 }
  Security.SecurityTab { id: tab; pluginService:facade; y:300; width:950; height:450 }
 }
 Timer { interval:550; running:true; onTriggered: {
  client.requestPending=true; client.clockNow=Date.now(); client.initialized=true;
  client.presentation={schema:"greyward.security.experience/v1",label:"Synthetic only",fresh_until:new Date(Date.now()+10000).toISOString(),details:[],activity:[],notification_items:[{id:"synthetic",title:"Synthetic device",detail:"Fixture only",severity:"WARNING",route:"devices",actions:[{id:"open",label:"Review"}]}]};
 } }
 Timer { interval:900; running:true; onTriggered: {
  if (first.provider !== client || second.provider !== client || card.provider !== client || tab.provider !== client) { Qt.exit(4); return; }
  if (!first.fresh || !second.fresh || !card.fresh) { Qt.exit(7); return; }
  if (identity.publicLookupEnabled || identity.publicState !== "OFF" || identity.requestInFlight) { Qt.exit(8); return; }
  // Native host Background toggles must reach both pill orientations.
  const pills=first.children.filter(child=>"widgetBackground" in child);
  if (pills.length!==2) { Qt.exit(47);return; }
  first.widgetBackground=false;
  if (pills.some(pill=>pill.widgetBackground)) { Qt.exit(48);return; }
  first.widgetBackground=true;
  if (pills.some(pill=>!pill.widgetBackground)) { Qt.exit(49);return; }
  identity.publicLookupEnabled=true; identity.runtimeOwner=true;
  identity.publicState="CHECKING";
  if (identity.publicDisplay!=="Checking…") { Qt.exit(50);return; }
  identity.publicIp="203.0.113.42"; identity.countryCode="FR";
  identity.publicState="AVAILABLE";
  identity.scheduleNetworkRefresh();
  if (identity.publicDisplay!=="203.0.113.42" || identity.countryCode!=="FR") { Qt.exit(51);return; }
  identity.fetchPublicIdentity();
  if (identity.publicDisplay!=="203.0.113.42" || identity.countryCode!=="FR") { Qt.exit(52);return; }
  identity.publicLookupEnabled=false;
  client.requestPending=true;
  client.clockNow=Date.now();
  client.initialized=true;
  client.presentation={schema:"greyward.security.experience/v1",label:"Synthetic only",fresh_until:new Date(Date.now()-1000).toISOString(),notification_items:[],activity:[],details:[]};
  client.runAction({connection_ref:"synthetic"},{id:"trust_always"});
  if (client.actionPending || client.usbActionGeneration !== 0) { Qt.exit(5); return; }
  if (search.getItems("network").length !== 1 || search.getItems("zzzzzz").length !== 0) { Qt.exit(6); return; }
  console.info("SHARED_SECURITY_CLIENT_PASSED");
  Qt.exit(0);
 } }
 Timer { interval:6000; running:true; onTriggered:Qt.exit(2) }
}
'''


REGISTERED_HARNESS = '''import QtQuick
import Quickshell
import qs.Common
import qs.Services
import qs.Modules.DDash
import qs.DCommon.Common as DC
ShellRoot {
 id: root
 property var created: []
 property var originalProvider: null
 Component.onCompleted: {
  DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n;
  PluginService.systemPluginDirectory=Quickshell.shellDir+"/PLUGINS/GreywardCandidate";
 }
 FloatingWindow { id: surface; implicitWidth:1020; implicitHeight:680; visible:true; color:Theme.surface }
 Timer { interval:400; running:true; onTriggered: {
  for (const manifest of @@MANIFESTS@@) {
   PluginService._onManifestParsed(Quickshell.shellDir+"/PLUGINS/GreywardCandidate/"+manifest.id+"/plugin.json",manifest,"system",Date.now());
   if (!PluginService.loadPlugin(manifest.id)) { Qt.exit(10); return; }
  }
  SettingsData.dashTabs=@@PRESET@@.dashTabs;
  SettingsData.dashCards=@@PRESET@@.dashCards;
 } }
 Timer { interval:1400; running:true; onTriggered: {
  const client=PluginService.pluginDaemonInstances.greywardSecure;
  if (!client || Object.keys(PluginService.pluginDaemonInstances).length !== 1) { Qt.exit(11); return; }
  root.originalProvider=client;
  const tabId=@@PRESET@@.dashTabs.find(tab=>tab.id.startsWith("plugin_")).id;
  if (!DashRegistry.isSelectable(tabId) || !DashRegistry.tabComponentFor(tabId)) { Qt.exit(12); return; }
  // An invalid old-style ID must never pass the actual native registry.
  if (DashRegistry.entry("plugin:greywardSecure")) { Qt.exit(13); return; }
  for (const preset of @@PRESET@@.dashCards.filter(card=>card.id.startsWith("plugin_"))) {
   if (!DashRegistry.isCardAvailable(preset.id)) { Qt.exit(14); return; }
   const card=DashRegistry.cardComponentFor(preset.id).createObject(surface.contentItem,{pluginService:PluginService, width:310,height:210});
   if (!card || card.provider !== client) { Qt.exit(15); return; }
   root.created.push(card);
  }
  for (let i=0; i<2; i++) {
   const widget=PluginService.pluginWidgetComponents.greywardSecure.createObject(surface.contentItem,{pluginService:PluginService,pluginId:"greywardSecure",width:160,height:40});
   if (!widget || widget.provider !== client) { Qt.exit(16); return; }
   root.created.push(widget);
  }
  const tab=DashRegistry.tabComponentFor(tabId).createObject(surface.contentItem,{pluginService:PluginService,width:960,height:500});
  if (!tab || tab.provider !== client) { Qt.exit(17); return; }
  root.created.push(tab);
  const search=PluginService.ensureLauncherInstance("greywardSecure");
  if (!search || search.getItems("network").length !== 1) { Qt.exit(18); return; }
  if (!PluginService.unloadPlugin("greywardSecure")) { Qt.exit(19); return; }
  if (PluginService.pluginDaemonInstances.greywardSecure || !PluginService.loadPlugin("greywardSecure")) { Qt.exit(20); return; }
 } }
 Timer { interval:2200; running:true; onTriggered: {
  const client=PluginService.pluginDaemonInstances.greywardSecure;
  if (!client || client === root.originalProvider || Object.keys(PluginService.pluginDaemonInstances).length !== 1) { Qt.exit(21); return; }
  for (const item of root.created) if (item.provider !== client) { Qt.exit(22); return; }
  console.info("NATIVE_PLUGIN_REGISTRATION_PRESET_RELOAD_PASSED");Qt.exit(0);
 } }
 Timer { interval:6000; running:true; onTriggered:Qt.exit(2) }
}
'''

@unittest.skipUnless(os.name == 'posix' and os.environ.get('GREYWARD_DMS20_SHELL'), 'explicit Linux DMS 2.0 candidate')
class Dms20Plugins(unittest.TestCase):
    def test_card_colors_require_fresh_scoped_evidence_and_fit_compact_sizes(self):
        harness = '''import QtQuick
import Quickshell
import qs.Common
import qs.DCommon.Common as DC
import "PLUGINS/GreywardCandidate/greywardSecure" as Security
ShellRoot {
 id: root
 property int phase: 0
 property var healthy: ({posture:"PROTECTED",severity:"INFO",label:"Protected",reason:"Synthetic protection is operating.",details:[{label:"Firewall",value:"Secure"},{label:"Network protection",value:"Healthy"},{label:"Secure DNS",value:"Encrypted"},{label:"Device protection",value:"Secure"}],activity:[],notification_items:[]})
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 QtObject { id:client; property bool freshnessLeaseValid:true; property var presentation:root.healthy }
 QtObject { id:facade; property var pluginDaemonInstances:({greywardSecure:client}); signal pluginDataChanged(string id) }
 FloatingWindow {
  implicitWidth:1000; implicitHeight:350; visible:true
  Security.StatusCard { id:protection; pluginService:facade; width:310; height:260 }
  Security.StatusCard { id:network; section:"network"; pluginService:facade; x:330; width:310; height:260 }
  Security.StatusCard { id:updates; section:"updates"; pluginService:facade; x:660; width:310; height:260 }
 }
 Timer { interval:220; running:true; repeat:true; onTriggered: {
  phase++;
  if (phase===1) {
   if (protection.stateTone!=="positive" || network.stateTone!=="positive" || updates.stateTone!=="warning") { Qt.exit(30); return; }
   if (!protection.activeFocusOnTab || protection.rows.length<2 || network.rows.length!==3) { Qt.exit(31); return; }
   client.presentation=Object.assign({},root.healthy,{severity:"CRITICAL",notification_items:[{route:"devices",severity:"CRITICAL"}]});
  } else if (phase===2) {
   if (protection.stateTone!=="critical" || network.stateTone!=="positive") { Qt.exit(32); return; }
   client.presentation=Object.assign({},root.healthy,{details:[{label:"Firewall",value:"Secure"},{label:"Network protection",value:"Operating"},{label:"Secure DNS",value:"Vpnowned"}],notification_items:[{route:"network",severity:"INFO",detail:"Synthetic VPN information"}]});
  } else if (phase===3) {
   if (network.stateTone!=="positive" || network.value!=="Protection active" || network.detail!=="VPN active" || network.rows[2].label!=="VPN") { Qt.exit(37); return; }
   client.freshnessLeaseValid=false;
  } else if (phase===4) {
   if ([protection,network,updates].some(card=>card.stateTone!=="warning" || card.rows.length!==0)) { Qt.exit(33); return; }
   client.freshnessLeaseValid=true;
   client.presentation=Object.assign({},root.healthy,{details:[{label:"Firewall",value:"Disabled"}]});
  } else if (phase===5) {
   if (network.stateTone!=="critical") { Qt.exit(34); return; }
   Theme.isLightMode=true;
   for (const card of [protection,network,updates]) { card.width=220;card.height=170; }
  } else {
   if (protection.stateColor.toString()!=="#2e6b53") { Qt.exit(35); return; }
   for (const card of [protection,network,updates]) {
    const body=Array.from(card.content ?? []).find(item=>item.objectName==="greywardStatusContent");
    if (!body || body.implicitHeight>body.height+1) { console.info("CARD_OVERFLOW",body?.implicitHeight,body?.height);Qt.exit(36);return; }
   }
   console.info("STATUS_COLORS_FRESHNESS_RELAYOUT_PASSED");Qt.exit(0);
  }
 } }
 Timer { interval:6000; running:true; onTriggered:Qt.exit(2) }
}
'''
        with tempfile.TemporaryDirectory(prefix='gw-status-cards-') as temporary:
            tree = Path(temporary) / 'shell'
            shutil.copytree(os.environ['GREYWARD_DMS20_SHELL'], tree)
            shutil.copytree(ROOT / 'environment/session/dms-2.0-plugins', tree / 'PLUGINS/GreywardCandidate')
            result = focus.AuthenticationInputFocus.run_shell(self, tree, harness)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('STATUS_COLORS_FRESHNESS_RELAYOUT_PASSED', result.stdout)
            self.assertNotRegex(result.stdout, r'ReferenceError|TypeError|Cannot assign|Binding loop|Cannot override|recursive rearrange')

    def test_shared_client_native_views_search_and_stale_usb_refusal(self):
        with tempfile.TemporaryDirectory(prefix='gw-plugin-source-') as temporary:
            tree = Path(temporary) / 'shell'
            shutil.copytree(os.environ['GREYWARD_DMS20_SHELL'], tree)
            shutil.copytree(ROOT / 'environment/session/dms-2.0-plugins', tree / 'PLUGINS/GreywardCandidate')
            result = focus.AuthenticationInputFocus.run_shell(self, tree, HARNESS)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('SHARED_SECURITY_CLIENT_PASSED', result.stdout)
            self.assertNotRegex(result.stdout, r'ReferenceError|TypeError|Cannot assign|Binding loop|Cannot override')

    def test_positive_aggregate_fallback_preserves_only_original_fresh_details(self):
        harness = '''import QtQuick
import Quickshell
import qs.Common
import qs.DCommon.Common as DC
import "PLUGINS/GreywardCandidate/greywardSecure" as Security
ShellRoot {
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 Security.SecurityClient { id: client }
 QtObject { id: facade; property var pluginDaemonInstances: ({greywardSecure:client}); signal pluginDataChanged(string id) }
 FloatingWindow { visible:true; implicitWidth:300; implicitHeight:250
  Security.StatusCard { id: card; section:"network"; pluginService:facade; width:280;height:230 }
 }
 Timer { interval:500; running:true; onTriggered: {
  ++client.requestGeneration; client.requestPending=true; client.initialized=true;
  const deadline=new Date(Date.now()+10000).toISOString();
  const healthy={schema:"greyward.security.experience/v1",posture:"PROTECTED",label:"Protected",severity:"INFO",
   fresh_until:deadline,display_fresh_until:deadline,
   details:[{label:"Firewall",value:"Secure"},{label:"Network protection",value:"Operating"}],notification_items:[]};
  client.presentation=healthy;
  client.applyProtectedDesktopPosture({state:"PROTECTED",fresh_for_ms:5000,display_for_ms:17000});
  if (client.presentation.fresh_until!==deadline || client.presentation.details.length!==2) { Qt.exit(40);return; }
  // Aggregate success cannot clear a still-fresh pending action either.
  client.presentation=Object.assign({},healthy,{posture:"REVIEW NEEDED",severity:"WARNING",notification_items:[{id:"pending",severity:"ACTION"}]});
  client.applyProtectedDesktopPosture({state:"PROTECTED",fresh_for_ms:5000});
  if (client.presentation.notification_items.length!==1 || client.presentation.posture!=="REVIEW NEEDED") { Qt.exit(41);return; }
  // A fresh negative aggregate wins immediately; no blanket debounce.
  client.presentation=healthy;
  client.applyProtectedDesktopPosture({state:"REVIEW NEEDED",fresh_for_ms:5000});
  if (client.presentation.posture!=="REVIEW NEEDED" || client.presentation.details.length!==0) { Qt.exit(42);return; }
  // Neither expired detailed evidence nor stale positive fallback can be green.
  client.presentation=Object.assign({},healthy,{fresh_until:new Date(Date.now()-1).toISOString()});
  client.applyProtectedDesktopPosture({state:"PROTECTED",fresh_for_ms:5000});
  if (client.presentation.details.length!==0) { Qt.exit(43);return; }
  client.presentation=healthy;
  client.applyProtectedDesktopPosture({state:"PROTECTED",fresh_for_ms:0});
  if (client.presentation.details.length!==0 || client.freshnessLeaseValid) { Qt.exit(44);return; }
  // Force a fresh aggregate-only reply: missing details mean unavailable,
  // rather than claiming there is a finding to review.
  client.applyProtectedDesktopPosture({state:"PROTECTED",fresh_for_ms:5000});
 } }
 Timer { interval:900; running:true; onTriggered: {
  if (card.stateTone!=="warning" || card.value!=="Status unavailable") { Qt.exit(45);return; }
  console.info("BOUNDED_AGGREGATE_FALLBACK_PASSED");Qt.exit(0);
 } }
 Timer { interval:6000; running:true; onTriggered:Qt.exit(2) }
}
'''
        with tempfile.TemporaryDirectory(prefix='gw-fallback-') as temporary:
            tree = Path(temporary) / 'shell'
            shutil.copytree(os.environ['GREYWARD_DMS20_SHELL'], tree)
            shutil.copytree(ROOT / 'environment/session/dms-2.0-plugins', tree / 'PLUGINS/GreywardCandidate')
            result = focus.AuthenticationInputFocus.run_shell(self, tree, harness)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('BOUNDED_AGGREGATE_FALLBACK_PASSED', result.stdout)
            self.assertNotRegex(result.stdout, r'ReferenceError|TypeError|Cannot assign|Binding loop|Cannot override')

    def test_native_theme_loader_reads_reference_dark_shell_roles(self):
        harness = '''import QtQuick
import Quickshell
import qs.Common
import qs.DCommon.Common as DC
ShellRoot {
 Component.onCompleted: { DC.Style.theme=Theme; DC.Style.settings=SettingsData; DC.I18n.backend=I18n; }
 FloatingWindow { visible:true; implicitWidth:300; implicitHeight:200; color:Theme.surface }
 Timer { interval:500; running:true; onTriggered: {
  Theme.isLightMode=false;
  SettingsData.customThemeFile=Quickshell.shellDir+"/reference-theme.json";
  Theme.switchTheme("custom",false,false);
 } }
 Timer { interval:1300; running:true; onTriggered: {
  if (Theme.surface.toString()!=="#050607" || Theme.surfaceVariant.toString()!=="#101214"
      || Theme.surfaceContainer.toString()!=="#16191c" || Theme.surfaceContainerHigh.toString()!=="#202429") {
   console.info("OBSERVED_NATIVE_THEME",Theme.surface,Theme.surfaceVariant,Theme.surfaceContainer,Theme.surfaceContainerHigh);
   Qt.exit(46);return;
  }
  console.info("REFERENCE_DARK_SHELL_THEME_PASSED");Qt.exit(0);
 } }
 Timer { interval:6000; running:true; onTriggered:Qt.exit(2) }
}
'''
        with tempfile.TemporaryDirectory(prefix='gw-shell-theme-') as temporary:
            tree = Path(temporary) / 'shell'
            shutil.copytree(os.environ['GREYWARD_DMS20_SHELL'], tree)
            shutil.copyfile(ROOT / 'environment/session/dankmaterialshell/greyward-obsidian.json', tree / 'reference-theme.json')
            result = focus.AuthenticationInputFocus.run_shell(self, tree, harness)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('REFERENCE_DARK_SHELL_THEME_PASSED', result.stdout)
            self.assertNotRegex(result.stdout, r'ReferenceError|TypeError|Cannot assign|Binding loop|Cannot override')

    def test_actual_loader_resolves_preset_cards_tab_launcher_and_single_daemon_after_reload(self):
        plugins = ROOT / 'environment/session/dms-2.0-plugins'
        manifests = [json.loads(p.read_text(encoding='utf-8')) for p in sorted(plugins.glob('*/plugin.json'))]
        preset = json.loads((ROOT / 'environment/session/dms-2.0-defaults/experience.json').read_text(encoding='utf-8'))
        harness = REGISTERED_HARNESS.replace('@@MANIFESTS@@', json.dumps(manifests)).replace('@@PRESET@@', json.dumps(preset))
        with tempfile.TemporaryDirectory(prefix='gw-native-plugins-') as temporary:
            tree = Path(temporary) / 'shell'
            shutil.copytree(os.environ['GREYWARD_DMS20_SHELL'], tree)
            shutil.copytree(plugins, tree / 'PLUGINS/GreywardCandidate')
            result = focus.AuthenticationInputFocus.run_shell(self, tree, harness)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('NATIVE_PLUGIN_REGISTRATION_PRESET_RELOAD_PASSED', result.stdout)
            self.assertNotRegex(result.stdout, r'ReferenceError|TypeError|Cannot assign|Binding loop|Cannot override|failed to instantiate')

if __name__ == '__main__':
    unittest.main()
