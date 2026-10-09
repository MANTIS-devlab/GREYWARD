import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";
const source = readFileSync(new URL("./application-security.js", import.meta.url), "utf8");
const operationRef = "operation_" + "a".repeat(64);
const value = {kind: "GRANT", preview: {grant_ref: "grant_" + "b".repeat(64), tool_profile:"openssh-key-inspection/v1", review: {operation_ref: operationRef, expires_after_ms: 10000}}};
const outcome = (state, extra = {}) => ({operation_ref: operationRef, outcome: state, verified_readback: false, committed_revision: null, failure: null, ...extra});
function fixture(request) {
  let clock = 0;
  const context = {window: {}}; vm.runInNewContext(source, context);
  return {controller: context.window.GREYWARD_APPLICATION_SECURITY.create({request, now: () => clock, pause: async ms => {clock += ms;}}), advance: ms => {clock += ms;}};
}

test("visible Guard reads renew from the provider and stop after route departure", async () => {
  let clock=10000, visible=true, reads=0, next, cancelled;
  const context={window:{}}; vm.runInNewContext(source,context);
  const controller=context.window.GREYWARD_APPLICATION_SECURITY.create({
    now:()=>clock, schedule:(callback,ms)=>{assert.ok(ms>=250 && ms<=3000);next=callback;return callback;},
    unschedule:timer=>{cancelled=timer;}, request:async command=>{
      reads++;
      if(command==='list_application_security_grants') return {capabilities:{isolation:true,policy_changes:false},grants:[]};
      return {schema:'greyward.application-security/v1',source_state:{state:'AVAILABLE'},
        observed_at:new Date(clock).toISOString(),fresh_until:new Date(clock+5000).toISOString(),projection:{resources:[]}};
    }});
  const changed=[];
  const stop=controller.watch('resources',value=>changed.push(value),()=>visible);
  await next(); assert.equal(reads,3); assert.ok(controller.live(changed[0].envelope));
  clock+=6000; assert.equal(controller.live(changed[0].envelope),null);
  await next(); assert.equal(reads,6); assert.ok(controller.live(changed[1].envelope));
  assert.notEqual(changed[0].envelope.observed_at,changed[1].envelope.observed_at);
  visible=false; await next(); assert.equal(reads,6);
  stop(); assert.equal(cancelled,next); await next(); assert.equal(reads,6);
});

test("fast reads back off while keeping the actual provider deadline", async () => {
  let clock=10000,next,delay;
  const context={window:{}};vm.runInNewContext(source,context);
  const controller=context.window.GREYWARD_APPLICATION_SECURITY.create({
    now:()=>clock,schedule:(callback,ms)=>{next=callback;delay=ms;return callback;},unschedule:()=>{},
    request:async()=>({schema:'greyward.application-security/v1',source_state:{state:'AVAILABLE'},
      observed_at:new Date(clock).toISOString(),fresh_until:new Date(clock+5000).toISOString(),projection:{}})});
  let value;const stop=controller.watch('coverage',result=>{value=result;});
  await next();assert.equal(delay,3000);const deadline=value.coverage.fresh_until;
  clock+=delay;assert.ok(controller.live(value.coverage));assert.equal(value.coverage.fresh_until,deadline);
  clock=Date.parse(deadline)+1;assert.equal(controller.live(value.coverage),null);stop();
});

test("slow complete reads renew before the earliest provider lease without extending it", async () => {
  let clock=10000,next,delay;
  const context={window:{}};vm.runInNewContext(source,context);
  const controller=context.window.GREYWARD_APPLICATION_SECURITY.create({
    now:()=>clock,schedule:(callback,ms)=>{next=callback;delay=ms;return callback;},unschedule:()=>{},
    request:async command=>{
      if(command==='list_application_security_grants'){clock+=1400;return {grants:[]};}
      return {schema:'greyward.application-security/v1',source_state:{state:'AVAILABLE'},
        observed_at:new Date(clock).toISOString(),fresh_until:new Date(clock+5000).toISOString(),projection:{resources:[]}};
    }});
  let value;const stop=controller.watch('resources',result=>{value=result;});
  await next();assert.equal(delay,1200);
  const expires=value.coverage.fresh_until;
  clock+=delay+1400;
  assert.ok(controller.live(value.coverage));assert.equal(value.coverage.fresh_until,expires);
  clock=Date.parse(expires)+1;assert.equal(controller.live(value.coverage),null);
  stop();
});

test("age-only renewal keeps the presentation key, while stale, changed and failed evidence changes it", () => {
  let clock=10000;
  const context={window:{}};vm.runInNewContext(source,context);
  const controller=context.window.GREYWARD_APPLICATION_SECURITY.create({now:()=>clock,request:async()=>null});
  const envelope=age=>({schema:'greyward.application-security/v1',source_state:{state:'AVAILABLE'},
    observed_at:new Date(clock).toISOString(),fresh_until:new Date(clock+5000).toISOString(),
    projection:{protection:{health:'AVAILABLE',effective_profile:'PROTECTED',policy_revision:6,evidence_age_ms:age}}});
  const a={coverage:envelope(20),envelope:envelope(20),grants:{grants:[]}};
  const key=controller.presentationKey(a);
  const b={...a,coverage:envelope(900),envelope:envelope(900)};
  assert.equal(controller.presentationKey(b),key);
  b.coverage.projection.protection.health='DEGRADED';assert.notEqual(controller.presentationKey(b),key);
  assert.notEqual(controller.presentationKey({...a,coverage:envelope(30001)}),key);
  assert.notEqual(controller.presentationKey({...a,coverage:{source_state:{state:'UNAVAILABLE'}}}),key);
  clock+=5001;assert.notEqual(controller.presentationKey(a),key);
});

test("a stopped Guard watcher ignores an in-flight read and never repeats a mutation", async () => {
  let next, complete;
  const calls=[],changed=[];
  const context={window:{}}; vm.runInNewContext(source,context);
  const controller=context.window.GREYWARD_APPLICATION_SECURITY.create({
    schedule:callback=>{next=callback;return callback;},unschedule:()=>{},
    request:command=>{calls.push(command);return new Promise(resolve=>{complete=resolve;});}});
  const stop=controller.watch('coverage',value=>changed.push(value));
  const pending=next(); stop(); complete({source_state:{state:'UNAVAILABLE'},projection:null});
  await pending; assert.equal(changed.length,0);
  assert.deepEqual(calls,['get_application_security_coverage']);
});
test("GUI submission waits for the actual verified operation", async () => {
  const calls = [], progress = [];
  const {controller} = fixture(async (command) => {
    calls.push(command);
    if (command.startsWith("pick_")) return structuredClone(value);
    if (command.startsWith("apply_")) return outcome("PENDING");
    return outcome("COMPLETED", {verified_readback: true, committed_revision: 3});
  });
  const review = await controller.review("grant", {revision: 2});
  const result = await controller.apply(review, r => progress.push(r.outcome));
  assert.equal(result.outcome, "COMPLETED");
  assert.deepEqual(progress, ["PENDING", "COMPLETED"]);
  assert.deepEqual(calls, ["pick_application_security_grant", "apply_application_security_policy", "get_application_security_operation"]);
  await assert.rejects(controller.apply(review), /review again/);
});

test("background renewal does not crowd out authentication or operation readback", async () => {
  let next, release;
  const calls=[];
  const context={window:{}}; vm.runInNewContext(source,context);
  const controller=context.window.GREYWARD_APPLICATION_SECURITY.create({
    now:()=>0,schedule:callback=>{next=callback;return callback;},unschedule:()=>{},
    request:async command=>{
      calls.push(command);
      if(command.startsWith('pick_')) return structuredClone(value);
      if(command.startsWith('apply_')) return new Promise(resolve=>{release=resolve;});
      return outcome('CANCELLED');
    }});
  const stop=controller.watch('resources',()=>{throw new Error('Unexpected background read');});
  const ticket=await controller.review('grant',{revision:2});
  await next(); assert.equal(calls.length,1);
  const pending=controller.apply(ticket);
  await next(); assert.equal(calls.length,2);
  release(outcome('COMPLETED',{verified_readback:true,committed_revision:3}));
  assert.equal((await pending).outcome,'COMPLETED');
  stop();
});
test("expired reviews never reach apply and unverified completion is refused", async () => {
  let writes = 0;
  const {controller, advance} = fixture(async command => {
    if (command.startsWith("pick_")) return structuredClone(value);
    writes++; return outcome("COMPLETED", {committed_revision: 3});
  });
  const stale = await controller.review("grant", {}); advance(10000);
  await assert.rejects(controller.apply(stale), /review again/); assert.equal(writes, 0);
  const fresh = await controller.review("grant", {});
  await assert.rejects(controller.apply(fresh), /Invalid operation readback/);
});
test("missing or unknown tested restrictions cannot become a grant review", async () => {
  for (const tool_profile of [undefined, "arbitrary", "openssh-key-inspection/v2"]) {
    const {controller} = fixture(async () => ({...value, preview: {...value.preview, tool_profile}}));
    await assert.rejects(controller.review("grant", {}), /Invalid or expired review/);
  }
});
test("cancel requires confirmed cancellation and a foreign handle is refused", async () => {
  const {controller} = fixture(async command => command.startsWith("pick_") ? structuredClone(value) : outcome("RUNNING"));
  const review = await controller.review("grant", {});
  await assert.rejects(controller.cancel({...review}), /owner changed/);
  await assert.rejects(controller.cancel(review), /not confirmed/);
});
test("private launch review is one-shot, expires and cannot claim session protection", async () => {
  const launch_ref="launch_"+"c".repeat(64), schema="greyward.application-security/v1";
  let writes=0;
  const {controller,advance}=fixture(async command=>{
    if(command.startsWith("pick_"))return {schema,launch_ref,requested_profile:"ISOLATED",enforcement_health:"UNKNOWN",private_display_requested:true,expires_after_ms:90000};
    writes++;return {schema,launch_ref,state:"LAUNCHED",enforcement_health:"UNKNOWN",isolation_established:true,private_display:true};
  });
  const expired=await controller.prepareLaunch();advance(90000);
  await assert.rejects(controller.startLaunch(expired),/expired/);assert.equal(writes,0);
  const ticket=await controller.prepareLaunch();
  await assert.rejects(controller.startLaunch({...ticket}),/expired/);
  assert.equal((await controller.startLaunch(ticket)).enforcement_health,"UNKNOWN");
  await assert.rejects(controller.startLaunch(ticket),/expired/);assert.equal(writes,1);
});
test("application history uses the existing bounded telemetry store", async()=>{
  const calls=[];const {controller}=fixture(async(...args)=>{calls.push(args);return {events:[]};});
  const application="installation_"+"a".repeat(64);
  await controller.events(application);
  assert.deepEqual(JSON.parse(JSON.stringify(calls)),[["query_telemetry",{filters:{category:"APPLICATION_SECURITY",limit:100,application}},8000]]);
  await assert.rejects(controller.events("/home/user/.ssh"),/Invalid/);
});

test("blocked-resource navigation opens the exact resource once and never approves", async () => {
  const appSource=readFileSync(new URL("./app.js",import.meta.url),"utf8");
  const fragment=appSource.slice(appSource.indexOf("let navigationInFlight = null;"),appSource.indexOf("async function consumeNavigationRequest()"));
  const reference="resource_"+"a".repeat(64), calls=[];
  const control={dataset:{guardDetail:reference}};
  const context={pages:["protected-data","history"],currentPage:"overview",focusedThreatEventId:"",normalizePage:value=>value,
    loadPage:async page=>{calls.push(["page",page]);context.currentPage=page;},
    app:{querySelectorAll:()=>[control]},showGuardDetail:async item=>calls.push(["detail",item.dataset.guardDetail]),
    copy:key=>key,setStatus:(target,value)=>calls.push(["status",value])};
  vm.runInNewContext(fragment,context);
  await Promise.all([context.followSecurityNavigation("protected-data|"+reference),context.followSecurityNavigation("protected-data|"+reference)]);
  assert.deepEqual(calls,[["page","protected-data"],["detail",reference]]);
  calls.length=0;
  await context.followSecurityNavigation("protected-data|resource_../../secret");
  assert.equal(calls.length,0);
  context.app.querySelectorAll=()=>[];
  await context.followSecurityNavigation("protected-data|"+reference);
  assert.deepEqual(calls,[["page","protected-data"],["status","guard.block.resourceMissing"]]);
});


test("security widget Review forwards only the resource route without a mutation", () => {
  const qml=readFileSync(new URL("../../../environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml",import.meta.url),"utf8");
  const fragment=qml.slice(qml.indexOf("    function openRoute("),qml.indexOf("    function setPrivacyProfile("));
  const commands=[],reference="resource_"+"a".repeat(64);
  const context={activateSecurityCenterWindow:()=>{},Quickshell:{execDetached:args=>commands.push(Array.from(args))},freshnessLeaseValid:true,actionPending:false};
  vm.runInNewContext(fragment,context);
  context.runAction({route:"protected-data",resource_ref:reference},{id:"open"});
  assert.deepEqual(commands,[["/usr/bin/greyward-security-center-route","protected-data",reference]]);
  assert.equal(context.actionPending,false);
  context.freshnessLeaseValid=false;
  context.runAction({route:"protected-data",resource_ref:reference},{id:"open"});
  assert.equal(commands.length,1);
});
