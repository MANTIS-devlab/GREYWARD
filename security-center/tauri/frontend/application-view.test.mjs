import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";
import test from "node:test";
const context={window:{}};
vm.runInNewContext(readFileSync(new URL("./application-view.js",import.meta.url),"utf8"),context);
const api=context.window.GREYWARD_APPLICATION_VIEW;
const coverage=Object.fromEntries(["graphical_session","user_manager","direct_exec","services_and_scheduled_jobs","enrolled_remote_sessions","protected_resource_labels","deputies_and_portals"].map(key=>[key,true]));
const snapshot=()=>({health:"AVAILABLE",requested_profile:"PROTECTED",effective_profile:"PROTECTED",coverage:{...coverage},policy_revision:4,evidence_age_ms:0});
const esc=value=>String(value).replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
const ref=kind=>kind+"_"+"a".repeat(64);
function view(language="en") {
  const translations={window:{},localStorage:{getItem:()=>language,setItem:()=>{}},navigator:{language},document:{documentElement:{lang:language}}};
  vm.runInNewContext(readFileSync(new URL("./i18n.js",import.meta.url),"utf8"),translations);
  return api.create({esc,copy:translations.GREYWARD_I18N.t,icon:()=>"",live:envelope=>envelope?.projection||null,time:()=>"Today"});
}
test("session badges require complete current enforcement, never provenance or registration",()=>{
  assert.equal(api.protection(snapshot()).verified,true);
  for(const change of [{coverage:{...coverage,direct_exec:false}}, {health:"UNKNOWN"}, {evidence_age_ms:30001},
    {policy_revision:0}, {requested_profile:"TRUSTED"}, {coverage:null}, {effective_profile:"arbitrary"}]) {
    const value=api.protection({...snapshot(),...change});
    assert.equal(value.verified,false);assert.notEqual(value.state,"PROTECTED");
  }
  assert.equal(api.protection({provenance:{state:"VERIFIED"}}).verified,false);
  assert.equal(api.protection({...snapshot(),requested_profile:"ISOLATED",effective_profile:"ISOLATED",isolation:{}}).verified,false);
  assert.equal(api.protection({...snapshot(),requested_profile:"TRUSTED",effective_profile:"TRUSTED",reviewed_exception:false}).verified,false);
});
test("Overview cannot claim complete protection from system checks alone",()=>{
  const renderer=view(), posture={state:"PROTECTED",tone:"positive"};
  for(const protection of [null,{...snapshot(),health:"UNAVAILABLE",effective_profile:null},
      {...snapshot(),coverage:{...coverage,direct_exec:false}}]) {
    const result=renderer.overviewPosture(posture,{coverage:{projection:{protection}}});
    assert.equal(result.state,"REVIEW NEEDED"); assert.equal(posture.state,"PROTECTED");
  }
  assert.equal(renderer.overviewPosture(posture,{coverage:{projection:{protection:snapshot()}}}),posture);
  const critical={state:"ACTION REQUIRED",tone:"critical"};
  assert.equal(renderer.overviewPosture(critical,{}),critical);
  const domains=[{name_key:"evidence.domain.applications",state:"SECURE"}, {name_key:"evidence.domain.network",state:"SECURE"}];
  const restricted=renderer.overviewDomains(domains,{});
  assert.equal(restricted[0].state,"UNKNOWN"); assert.equal(restricted[1],domains[1]);
  assert.equal(domains[0].state,"SECURE");
  assert.equal(renderer.overviewDomains(domains,{coverage:{projection:{protection:snapshot()}}})[0],domains[0]);
});
test("English and French empty, unavailable, populated and detail views have complete product copy",()=>{
  for(const language of ["en","fr"]) {
    const renderer=view(language);
    const app={record:{identity:{installation_ref:ref("installation"),display_name:"Test application",provider:"RPM",provenance:{state:"VERIFIED"}}},protection:{...snapshot(),health:"UNKNOWN",effective_profile:null}};
    const resource={resource_ref:ref("resource"),label:"SSH keys",category:"CREDENTIALS",coverage:"UNKNOWN"};
    for(const html of [renderer.inventory({},"applications"),renderer.inventory({envelope:{projection:{applications:[app]}}},"applications"),
      renderer.inventory({envelope:{projection:{resources:[resource]}},grants:{grants:[]}},"resources"),
      renderer.detail(resource,"resources",[],true),renderer.detail(app,"applications",[],false),renderer.events({events:[{event_type:"SENSITIVE_ACCESS_BLOCKED",outcome:"DENIED"}]})]) {
      assert.doesNotMatch(html,/guard\.[a-zA-Z]|route\.apps|ui\.close/);
    }
  }
});
test("unavailable read exposes no mutation; stored grants are not presented as current enforcement",()=>{
  const renderer=view();
  const html=renderer.inventory({grants:{grants:[]}},"resources");
  assert.doesNotMatch(html,/guard-register-form|data-guard-grant|is-verified/);
  const detail=renderer.detail({resource_ref:ref("resource"),category:"CREDENTIALS",label:'<img src=x onerror="run()">',coverage:"UNKNOWN"},"resources",[{grant_ref:ref("grant"),resources:[ref("resource")]}],false);
  assert.match(detail,/&lt;img/);assert.doesNotMatch(detail,/<img|is-verified|data-guard-grant/);
  assert.match(detail,/current enforcement checked at launch/);
});
test("sensitive denial has no Allow action; unknown outcomes remain unconfirmed",()=>{
  const html=view().events({events:[{event_type:"SENSITIVE_ACCESS_BLOCKED",outcome:"untrusted",details:{text:"<script>"}}]});
  assert.match(html,/Outcome not confirmed/);assert.doesNotMatch(html,/Sensitive access blocked|Access denied|data-.*allow|<script>|untrusted/);
  const evidence={event_type:"SENSITIVE_ACCESS_BLOCKED",source:"root-kernel-selinux-audit",outcome:"DENIED",decision:"DENIED",quality:{source_state:"PARTIAL",confidence:"KERNEL_DECISION"}};
  assert.match(view().events({events:[evidence]}),/Sensitive access blocked/);
  for(const changed of [{source:"application-error"},{decision:null},{quality:{source_state:"UNAVAILABLE",confidence:"KERNEL_DECISION"}}]) {
    assert.doesNotMatch(view().events({events:[{...evidence,...changed}]}),/Sensitive access blocked|Access denied/);
  }
});
test("managed isolation can be offered without enabling unenrolled resource or grant changes",()=>{
  const renderer=view();
  const data={envelope:{projection:{applications:[],resources:[]}},grants:{grants:[],capabilities:{isolation:true,policy_changes:false}}};
  assert.match(renderer.inventory(data,"applications"),/data-guard-run/);
  assert.doesNotMatch(renderer.inventory(data,"resources"),/guard-register-form|data-guard-grant/);
  for(const capabilities of [undefined,{isolation:"true",policy_changes:"true"},{isolation:false,policy_changes:false}]) {
    const unavailable={...data,grants:{grants:[],capabilities}};
    assert.doesNotMatch(renderer.inventory(unavailable,"applications"),/data-guard-run/);
    assert.doesNotMatch(renderer.inventory(unavailable,"resources"),/guard-register-form/);
  }
});

test("connected UNKNOWN state explains unavailable enrollment controls without pretending protection",()=>{
  for(const language of ['en','fr']) {
    const renderer=view(language);
    const data={coverage:{projection:{protection:{health:'UNKNOWN',effective_profile:null}}},
      envelope:{projection:{resources:[]}},grants:{grants:[],capabilities:{isolation:true,policy_changes:false}}};
    const html=renderer.inventory(data,'resources');
    assert.match(html,/data-guard-connection="connected"/);
    assert.match(html,/guard-setup/); assert.match(html,/data-page="applications"/);
    assert.doesNotMatch(html,/guard\.[a-zA-Z]|guard-register-form|is-verified/);
    const unavailable=renderer.inventory({coverage:{source_state:{state:'UNAVAILABLE'}}},'resources');
    assert.match(unavailable,/data-guard-connection="unavailable"/);
    assert.doesNotMatch(unavailable,/guard-setup|data-guard-run/);
  }
});

test("resource and provider marks express supplied records without implying verified protection",()=>{
  const renderer=api.create({esc,copy:key=>key,icon:name=>`<svg data-kind="${name}"></svg>`,live:envelope=>envelope?.projection||null,time:()=>"Today"});
  for(const [provider,glyph] of Object.entries({RPM:"package",FLATPAK:"applications",APP_IMAGE:"package",SCRIPT:"script",MANUAL:"file",UNKNOWN:"applications"})) {
    const app={record:{identity:{installation_ref:ref("installation"),display_name:"Tool",provider,provenance:{state:"UNKNOWN"}}},protection:{health:"UNKNOWN"}};
    const html=renderer.inventory({envelope:{projection:{applications:[app]}}},"applications");
    assert.match(html,new RegExp(`data-kind="${glyph}"`));assert.doesNotMatch(html,/is-verified/);
  }
  for(const [category,glyph] of Object.entries({CREDENTIALS:"key",CLOUD:"cloud",DEVELOPMENT:"script",BROWSER_SESSION:"browser",CUSTOM:"folder"})) {
    const resource={resource_ref:ref("resource"),label:"Data",category,coverage:"UNKNOWN"};
    const html=renderer.inventory({envelope:{projection:{resources:[resource]}}},"resources");
    assert.match(html,new RegExp(`data-kind="${glyph}"`));assert.doesNotMatch(html,/is-verified/);
  }
});

test("optional portal coverage is explicitly unverified without erasing baseline", () => {
  const protection = {...snapshot(), coverage:{...coverage,deputies_and_portals:false}};
  assert.equal(api.protection(protection).verified,true);
  const html=view().inventory({coverage:{projection:{protection}},envelope:{projection:{resources:[]}},grants:{grants:[]}},"resources");
  assert.match(html,/Portal attribution and complete deputy isolation are not verified/);
  const detail=view().detail({resource_ref:ref("resource"),label:"Keys",category:"CREDENTIALS",coverage:"PROTECTED"},"resources",[],true);
  assert.match(detail,/Review SSH key inspection/);
  assert.match(detail,/Script and IDE raw-key access is not yet available/);
  assert.doesNotMatch(detail,/Always allow|Allow once|Allow application/);
});
