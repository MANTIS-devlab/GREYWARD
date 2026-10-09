// Fixed private WebKit/Tauri smoke test, not a package/performance release gate.
import assert from "node:assert/strict";
import {readFileSync, statSync, writeFileSync} from "node:fs";

const endpoint = "http://127.0.0.1:49940";
const application = "/usr/local/libexec/greyward-application-security-center-probe";
const liveWorkflow = process.env.GREYWARD_UI_WORKFLOW === "true";
assert.equal(process.getuid(), 1002);
const actualDomain = readFileSync("/proc/self/attr/current", "utf8").split(":")[2];
assert.equal(actualDomain, process.env.GREYWARD_UI_EXPECTED_DOMAIN);
let session;
async function request(method, path, body) {
  const response = await fetch(endpoint + path, {
    method, headers: {"Content-Type": "application/json"},
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    signal: AbortSignal.timeout(25000),
  });
  const result = await response.json();
  assert.ok(response.ok && !result.value?.error, `WebDriver command failed: ${result.value?.error || response.status}; ${String(result.value?.message || "").slice(0, 1000)}`);
  return result.value;
}
async function captureReadyView(path, page) {
  const ready = () => request("POST", `/session/${session}/execute/sync`, {
    script: "return document.querySelector('.nav-item.active')?.dataset.page === arguments[0] && !!document.querySelector('.guard-hero') && !document.querySelector('.loading-panel');", args: [page],
  });
  for (let attempt = 0; attempt < 60; attempt++) {
    if (await ready()) {
      // Startup navigation and live refresh may replace the view after an
      // initial paint. Require consecutive ready frames around the capture.
      await new Promise(resolve => setTimeout(resolve, 100));
      if (await ready()) {
        const image = await request("GET", `/session/${session}/screenshot`);
        if (await ready()) {
          writeFileSync(path, Buffer.from(image, "base64"), {mode: 0o600});
          return;
        }
      }
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error("The actual application view did not stabilize for capture");
}
try {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try { await request("GET", "/status"); break; }
    catch (error) { if (attempt === 39) throw error; await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  const created = await request("POST", "/session", {capabilities: {alwaysMatch: {"tauri:options": {application}}}});
  session = created.sessionId;
  assert.equal(typeof session, "string");
  await request("POST", `/session/${session}/timeouts`, {script: 10000});
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    ready = await request("POST", `/session/${session}/execute/sync`, {
      script: "return typeof window.__TAURI_INTERNALS__?.invoke === 'function' && document.querySelectorAll('[data-page]').length >= 5 && (window.__greywardStartupMarks || []).some(mark => mark.name === 'app_script_start');", args: [],
    });
    if (ready) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(ready, true, "Bundled app/startup scripts and navigation did not become ready");
  const cgroup = readFileSync("/proc/self/cgroup", "utf8").trim();
  assert.equal(cgroup, "0::/system.slice/greyward-application-security-ui-check.service");
  const executable = statSync(application);
  const domains = [];
  for (const pid of readFileSync("/sys/fs/cgroup/system.slice/greyward-application-security-ui-check.service/cgroup.procs", "utf8").trim().split(/\s+/)) {
    try {
      const held = statSync(`/proc/${pid}/exe`);
      if (held.dev === executable.dev && held.ino === executable.ino) domains.push(readFileSync(`/proc/${pid}/attr/current`, "utf8").split(":")[2]);
    } catch (error) {
      // Unrelated collector helpers can enter Fedora domains whose executable
      // metadata is hidden from the driver. They are not identity evidence.
      // A positively matched, readable root-owned Tauri process is required.
      if (error.code !== "ENOENT" && error.code !== "EACCES") throw error;
    }
  }
  assert.ok(domains.length >= 1, "A live root-owned Tauri executable was not found in the workload");
  assert.ok(domains.every((domain) => domain === process.env.GREYWARD_UI_APPLICATION_DOMAIN), "The Tauri application did not enter its required subject");
  const ipc = await request("POST", `/session/${session}/execute/async`, {
    script: "const done = arguments[arguments.length - 1]; window.__TAURI_INTERNALS__.invoke('consume_navigation_request').then(() => done({ok:true}), () => done({ok:false}));", args: [],
  });
  assert.equal(ipc.ok, true, "Existing allowlisted native IPC did not work");
  const reads = await request("POST", `/session/${session}/execute/async`, {
    script: "const done=arguments[arguments.length-1]; Promise.all([window.__TAURI_INTERNALS__.invoke('get_application_security_coverage'),window.__TAURI_INTERNALS__.invoke('list_application_security_applications',{query:{limit:10,revision:null,after:null}}),window.__TAURI_INTERNALS__.invoke('get_application_security_application',{installationRef:'installation_'+ 'a'.repeat(64)}),window.__TAURI_INTERNALS__.invoke('list_application_security_resources',{query:{limit:10,revision:null,after:null}}),window.__TAURI_INTERNALS__.invoke('get_application_security_resource',{resourceRef:'resource_'+ 'a'.repeat(64)})]).then(values=>done({ok:true,values}),()=>done({ok:false}));", args: [],
  });
  assert.equal(reads.ok, true, "Typed Context/facade reads did not complete");
  for (const value of reads.values) {
    assert.equal(value.schema, "greyward.application-security/v1");
    assert.equal(value.source_state.state, liveWorkflow ? "AVAILABLE" : "UNAVAILABLE");
    if (liveWorkflow) assert.notEqual(value.projection, null);
    else {
      assert.equal(value.projection, null, "Missing broker became a protected/empty projection");
      assert.equal(value.fresh_until, value.observed_at);
    }
  }
  if (liveWorkflow) {
    assert.equal(reads.values[0].projection.protection.health, "UNKNOWN");
    assert.equal(reads.values[0].projection.protection.effective_profile, null);
    assert.equal(reads.values[3].projection.resources.length, 1);
    assert.equal(reads.values[3].projection.resources[0].coverage, "UNKNOWN");
  }
  const refused = await request("POST", `/session/${session}/execute/async`, {
    script: "const done=arguments[arguments.length-1]; Promise.allSettled([window.__TAURI_INTERNALS__.invoke('list_application_security_applications',{query:{limit:101,revision:null,after:null}}),window.__TAURI_INTERNALS__.invoke('get_application_security_application',{installationRef:'../secret'})]).then(values=>done(values.map(value=>value.status)));", args: [],
  });
  assert.deepEqual(refused, ["rejected", "rejected"], "Invalid selectors reached a successful projection");
  const workflows = await request("POST", `/session/${session}/execute/async`, {
    script: "const done=arguments[arguments.length-1]; Promise.allSettled([window.__TAURI_INTERNALS__.invoke('list_application_security_grants'),window.__TAURI_INTERNALS__.invoke('pick_application_security_revocation',{grantRef:'grant_'+ 'a'.repeat(64),revision:1}),window.__TAURI_INTERNALS__.invoke('apply_application_security_policy',{operationRef:'operation_'+ 'a'.repeat(64)})]).then(values=>done(values.map(value=>value.status)));", args: [],
  });
  assert.deepEqual(workflows, [liveWorkflow ? "fulfilled" : "rejected", "rejected", "rejected"], "An unavailable provider or foreign review became a successful grant workflow");
  // Capture only the no-broker read path, before any authentication or review.
  // No synthetic UI data or native bridge replacement is installed.
  if (!liveWorkflow) {
    await request("POST", `/session/${session}/execute/sync`, {
      script: "document.querySelector('.nav-item[data-page=\"applications\"]').click();", args: [],
    });
    for (let attempt = 0; attempt < 80; attempt++) {
      const ready = await request("POST", `/session/${session}/execute/sync`, {
        script: "return !!document.querySelector('.guard-hero') && !!document.querySelector('.guard-provider-permissions');", args: [],
      });
      if (ready) break;
      if (attempt === 79) throw new Error("Unified Applications view did not become ready");
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    await captureReadyView("/run/greyward-application-security-ui/applications.png", "applications");
  }
  await request("POST", `/session/${session}/execute/sync`, {
    script: "document.querySelector('.nav-item[data-page=\"protected-data\"]').click();", args: [],
  });
  let resourceView=false;
  for(let attempt=0;attempt<80;attempt+=1){
    resourceView=await request("POST", `/session/${session}/execute/sync`,{
      script:"return !!document.querySelector('#guard-action-status') && document.querySelector('.content-frame').textContent.includes(arguments[0]);",args:[liveWorkflow ? "Synthetic descriptor registration" : "Protection provider unavailable"],
    });
    if(resourceView)break;
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.equal(resourceView,true,"Resource route did not present provider unavailability");
  if (!liveWorkflow) {
    await captureReadyView("/run/greyward-application-security-ui/protected-data.png", "protected-data");
  }
  if (liveWorkflow) {
    await request("POST", `/session/${session}/execute/sync`, {
      script:"document.querySelector('[data-guard-revoke]').click();", args:[],
    });
    let review = false;
    for (let attempt=0;attempt<80;attempt++) {
      review = await request("POST", `/session/${session}/execute/sync`, {
        script:"return !!document.querySelector('dialog[open]') && document.querySelector('dialog[open]').textContent.toLowerCase().includes('restart');", args:[],
      });
      if(review) break;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.equal(review, true, "The actual native revocation preview did not reach GUI review");
    await request("POST", `/session/${session}/execute/sync`, {
      script:"document.querySelector('dialog[open] button[value=cancel]').click();", args:[],
    });
    const retained = await request("POST", `/session/${session}/execute/async`, {
      script:"const done=arguments[arguments.length-1]; window.__TAURI_INTERNALS__.invoke('list_application_security_grants').then(value=>done(value.grants.length),()=>done(-1));", args:[],
    });
    assert.equal(retained, 1, "GUI cancellation changed actual grant policy");
  }
  // Keep each real operation within its own bounded WebDriver deadline. The
  // export and privacy reads also collect existing posture/backend facts;
  // timing this fixture is not a policy-lookup or performance acceptance test.
  await request("POST", `/session/${session}/timeouts`, {script: 20000});
  const invoke = async (command) => {
    const result = await request("POST", `/session/${session}/execute/async`, {
      script: "const command=arguments[0],done=arguments[arguments.length-1]; window.__TAURI_INTERNALS__.invoke(command).then(value=>done({ok:true,value}),()=>done({ok:false}));", args: [command],
    });
    assert.equal(result.ok, true, `Private typed operation failed: ${command}`);
    return result.value;
  };
  assert.equal((await invoke("export_posture")).ok, true, "Private posture export failed");
  const recorded = await invoke("get_privacy");
  assert.equal(recorded.activity_state, "AVAILABLE");
  assert.ok(recorded.activity.some(item => item.title === "Safe posture exported"), "Tauri/backend/Context did not share local history");
  assert.equal((await invoke("clear_history")).ok, true, "Local clear/readback failed");
  const empty = await invoke("get_privacy");
  assert.equal(empty.activity_state, "AVAILABLE");
  assert.equal(empty.activity.length, 0, "Cleared local history was resurrected");
  const csp = await request("POST", `/session/${session}/execute/async`, {
    script: "const done=arguments[arguments.length-1]; let violation=false; const listener=(event)=>{if(event.effectiveDirective==='script-src-elem'||event.effectiveDirective==='script-src')violation=true;}; document.addEventListener('securitypolicyviolation',listener); const injected=document.createElement('script'); injected.textContent='window.__greywardForbiddenInlineProbe=true'; document.head.append(injected); setTimeout(()=>{injected.remove();document.removeEventListener('securitypolicyviolation',listener);done({blocked:window.__greywardForbiddenInlineProbe!==true,violation});},100);", args: [],
  });
  assert.equal(csp.blocked, true, "Inline scripting was not refused");
  assert.equal(csp.violation, true, "No authoritative browser CSP violation was observed");
  console.log(JSON.stringify({schema: "greyward.application-security.ui-probe/v1", bundled_scripts: true,
    native_ipc: true, typed_context_reads: true, shared_local_history: true, missing_broker_unavailable: !liveWorkflow,
    actual_grant_review_cancel: liveWorkflow,
    invalid_selectors_refused: true, inline_script_blocked: true, private_session: true,
    application_domain: process.env.GREYWARD_UI_APPLICATION_DOMAIN, automation_domain: actualDomain,
    package_or_performance_claimed: false}));
} finally {
  if (session) await request("DELETE", `/session/${session}`);
}
