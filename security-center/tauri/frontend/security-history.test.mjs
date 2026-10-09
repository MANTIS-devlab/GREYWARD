import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";
function history(request = async () => ({}), options = {}) {
  const context = {};
  vm.runInNewContext(readFileSync(new URL("./security-history.js", import.meta.url), "utf8"), context);
  return context.GREYWARD_SECURITY_HISTORY.create({request, copy: key => key, esc: value => String(value).replaceAll("<", "&lt;"), icon: () => "", time: String, ...options});
}
test("security history requests an independent bounded scope, with cursor reset on filter change", async () => {
  const calls = [], api = history(async (...args) => calls.push(args));
  api.older("cursor-1"); await api.read();
  assert.equal(calls[0][0], "query_telemetry");
  assert.equal(calls[0][1].filters.scope, "SECURITY");
  assert.equal(calls[0][1].filters.limit, 60);
  api.select("RECOVERY"); await api.read();
  assert.equal(calls[1][1].filters.category, "RECOVERY");
  assert.equal(calls[1][1].filters.cursor, undefined);
  api.select("NETWORK"); assert.equal(api.filters().category, undefined);
});

test("historical executable and current resource labels explain a denial without claiming application identity", () => {
  const event = {category:"APPLICATION_SECURITY", event_type:"SENSITIVE_ACCESS_BLOCKED", action:"READ", outcome:"DENIED", decision:"DENIED",
    source:"root-kernel-selinux-audit", quality:{confidence:"KERNEL_DECISION",source_state:"AVAILABLE"},
    details:{observed_process:{pid:42,executable_name:"python3",source:"KERNEL_AUDIT"},resource_refs:["resource_"+"a".repeat(64)],policy_revision:6}};
  const api=history(), labels={resources:{[event.details.resource_refs[0]]:"SSH credentials"}};
  const html=api.row(event,labels);
  assert.match(html,/python3/); assert.match(html,/SSH credentials/);
  assert.match(html,/history.action.READ/); assert.match(html,/history.reason.denied/);
  assert.match(html,/PID 42/); assert.match(html,/history.process.limit/);
  assert.doesNotMatch(html,/history.actor.application|Allow|PROTECTED/);
  assert.match(api.row({...event,details:{resource_refs:event.details.resource_refs}},labels),/history.actor.unknown/);
  for (const process of [{pid:42,executable_name:"<img>",source:"KERNEL_AUDIT"},{pid:42,executable_name:"brave",source:"USER_CLAIM"}]) {
    assert.match(api.row({...event,details:{...event.details,observed_process:process}}),/history.actor.unknown/);
  }
});

test("optional label failure never hides history; completing a grant is not an allowed data access", async () => {
  const event={category:"APPLICATION_SECURITY",event_type:"POLICY_GRANT",outcome:"COMPLETED",source:"root-broker-operation-readback",details:{verified_readback:true}};
  const api=history(async()=>({source_state:{state:"AVAILABLE"},events:[event]}),{context:async()=>{throw Error("Unavailable");}});
  const data=await api.read(),html=api.markup(data);
  assert.match(html,/guard.outcome.completed/); assert.match(html,/history.reason.policyVerified/);
  assert.doesNotMatch(html,/Allowed|guard.outcome.blocked/);
});

test("presentation labels and local activity are escaped, with private references in disclosure", () => {
  const api=history();
  const event={category:"LOCAL_ACTIVITY",event_type:"LOCAL_ACTION",source:"security-center/presentation",details:{local:{title:"<script>alert(1)</script>",detail_parts:["Recorded <img>"]}}};
  const html=api.row(event);
  assert.doesNotMatch(html,/<script>|<img>/); assert.match(html,/&lt;script>/);
});
test("empty, unavailable and network-only histories never establish protection", () => {
  const api = history();
  assert.match(api.markup({source_state:{state:"AVAILABLE"}, events:[]}), /history.empty.copy/);
  assert.match(api.markup({source_state:{state:"UNAVAILABLE"}, events:[{event_type:"POLICY_GRANT"}]}), /history.unavailable.copy/);
  assert.doesNotMatch(api.markup({source_state:{state:"AVAILABLE"}, events:[{category:"NETWORK",event_type:"CONNECTION_ATTEMPT"}]}), /CONNECTION_ATTEMPT/);
});
test("sensitive block presentation requires the existing kernel evidence contract", () => {
  const api = history(), record = {category:"APPLICATION_SECURITY",event_type:"SENSITIVE_ACCESS_BLOCKED",outcome:"DENIED",decision:"DENIED",source:"root-kernel-selinux-audit",quality:{confidence:"KERNEL_DECISION",source_state:"AVAILABLE"}};
  const render = event => api.markup({source_state:{state:"AVAILABLE"},events:[event]});
  assert.match(render(record), /guard.outcome.blocked/);
  for (const change of [{source:"application-error"}, {quality:{}}, {decision:"UNKNOWN"}]) {
    assert.match(render({...record,...change}), /guard.event.sensitiveUnconfirmed/);
    assert.doesNotMatch(render({...record,...change}), /guard.outcome.blocked/);
  }
});
test("network activity renders its own full workspace without unrelated events", () => {
  const source = readFileSync(new URL("./app.js", import.meta.url), "utf8");
  const ctx={normalizePage:x=>x, networkActivityMarkup:()=>"NETWORK_WORKSPACE", contextNavigation:()=>"", currentPage:"activity"};
  const start=source.indexOf("function renderContent("), end=source.indexOf("function ",start+10);
  vm.runInNewContext(source.slice(start,end),ctx);
  assert.match(ctx.renderContent("activity",{}), /NETWORK_WORKSPACE/);
  assert.doesNotMatch(ctx.renderContent("activity",{}), /guard|history/i);
});
test("devices and recovery have distinct content owners", () => {
  const source = readFileSync(new URL("./app.js", import.meta.url), "utf8");
  const devices = source.slice(source.indexOf("function devicesMarkup("),source.indexOf("function evidenceMarkup("));
  assert.doesNotMatch(devices, /recoveryMarkup/);
  const context={pageHeader:()=>"HEADER",copy:String,actionButton:()=>"",recoveryMarkup:()=>"REAL_RECOVERY"};
  vm.runInNewContext(source.slice(source.indexOf("function recoveryProductMarkup("),source.indexOf("function applicationAccessLabel(")),context);
  assert.equal(context.recoveryProductMarkup({}),"HEADERREAL_RECOVERY");
});

test("identity references remain in evidence disclosure rather than primary history copy", () => {
  const reference="installation_"+"a".repeat(64);
  const html=history().markup({source_state:{state:"AVAILABLE"},events:[{category:"APPLICATION_SECURITY",event_type:"POLICY_GRANT",outcome:"COMPLETED",application:reference}]});
  assert.doesNotMatch(html, new RegExp(`<p>[^<]*${reference}`));
  assert.match(html, new RegExp(`<dd>${reference}</dd>`));
});
