import assert from "node:assert/strict";
import {execFile} from "node:child_process";
import {promisify} from "node:util";
import test from "node:test";
import {createTauriCapabilities} from "@wdio/tauri-service";
import {remote} from "webdriverio";

const execFileAsync = promisify(execFile);
const endpoint = process.env.GREYWARD_TAURI_WEBDRIVER_URL;
const application = process.env.GREYWARD_TAURI_APPLICATION;
const sshConfig = process.env.GREYWARD_INTERACTION_SSH_CONFIG;
const sshAlias = process.env.GREYWARD_INTERACTION_SSH_ALIAS || "greyward-dev";
const localExecution = process.env.GREYWARD_INTERACTION_LOCAL === "1";
const privacyWatchdog = process.env.GREYWARD_PRIVACY_WATCHDOG || "/usr/local/libexec/greyward-privacy-network-watchdog";

async function remoteCommand(command) {
  if (localExecution) {
    const result = await execFileAsync("/bin/bash", ["-lc", command], {timeout: 30000, maxBuffer: 1024 * 1024});
    return result.stdout.trim();
  }
  const result = await execFileAsync(
    process.env.GREYWARD_INTERACTION_SSH_BIN || "ssh",
    ["-F", sshConfig, "-o", "BatchMode=yes", sshAlias, command],
    {timeout: 30000, maxBuffer: 1024 * 1024},
  );
  return result.stdout.trim();
}

async function armPrivacyWatchdog() {
  await remoteCommand(`${privacyWatchdog} arm STANDARD`);
}

async function cancelPrivacyWatchdog() {
  await remoteCommand(`${privacyWatchdog} cancel`);
}

async function waitFor(browser, selector, timeout = 30000) {
  await browser.waitUntil(
    async () => (await browser.$(selector)).isExisting(),
    {timeout, interval: 250, timeoutMsg: `Timed out waiting for ${selector}`},
  );
  return browser.$(selector);
}

async function elementText(browser, selector) {
  return (await browser.$(selector)).getText();
}

async function clickSelector(browser, selector) {
  await browser.execute((value) => {
    const element = document.querySelector(value);
    if (!element) throw new Error(`Missing semantic UI target: ${value}`);
    element.click();
  }, selector);
}

async function setField(browser, selector, value) {
  await browser.execute((target, nextValue) => {
    const element = document.querySelector(target);
    if (!element) throw new Error(`Missing semantic field: ${target}`);
    const setter = Object.getOwnPropertyDescriptor(element.constructor.prototype, "value")?.set;
    if (setter) setter.call(element, nextValue);
    else element.value = nextValue;
    element.dispatchEvent(new Event("input", {bubbles: true}));
    element.dispatchEvent(new Event("change", {bubbles: true}));
  }, selector, value);
}

async function selectValue(browser, selector, value) {
  await setField(browser, selector, value);
}

async function eventIds(browser) {
  const rows = await browser.$$('[data-activity-event]');
  const ids = [];
  for (let index = 0; index < Math.min(rows.length, 12); index += 1) {
    ids.push(await rows[index].getAttribute("data-activity-event"));
  }
  return ids;
}

async function eventRows(browser) {
  return browser.$$('[data-activity-event]');
}

async function waitForNewEvents(browser, beforeIds, timeout = 20000) {
  await browser.waitUntil(
    async () => {
      const current = await eventIds(browser);
      return current.some((id) => !beforeIds.includes(id));
    },
    {timeout, interval: 500, timeoutMsg: "No newly observed Network Activity event appeared"},
  );
  return eventIds(browser);
}

async function generateTraffic() {
  const marker = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  await remoteCommand(`curl --silent --show-error --max-time 10 --output /dev/null 'https://example.com/?greyward=${marker}'`);
}

async function listPolicyRules() {
  const output = await remoteCommand(
    "gdbus call --system --dest systems.mantis.greyward.OpenSnitchPolicy1 --object-path /systems/mantis/greyward/OpenSnitchPolicy1 --method systems.mantis.greyward.OpenSnitchPolicy1.ListRules",
  );
  const match = output.match(/^\('((?:[^'\\]|\\.)*)',\)$/s);
  assert.ok(match, `unexpected ListRules response: ${output}`);
  return JSON.parse(match[1]);
}

function ruleMatches(rule, action) {
  return rule.action === action
    && rule.scope?.application === "/usr/bin/curl"
    && rule.scope?.destination?.host === "example.com";
}

async function waitForPolicyRule(action, browser) {
  let result;
  await browser.waitUntil(
    async () => {
      result = await listPolicyRules();
      return result.ok && result.rules.some((rule) => ruleMatches(rule, action));
    },
    {timeout: 15000, interval: 500, timeoutMsg: `Authoritative ${action} policy readback did not appear`},
  );
  return result.rules.find((rule) => ruleMatches(rule, action));
}

async function waitForNoPolicyRule(browser) {
  let result;
  await browser.waitUntil(
    async () => {
      result = await listPolicyRules();
      return result.ok && !result.rules.some((rule) => rule.scope?.application === "/usr/bin/curl" && rule.scope?.destination?.host === "example.com");
    },
    {timeout: 15000, interval: 500, timeoutMsg: "Removed Network Activity rule remained in authoritative policy readback"},
  );
  return result;
}

async function findExpandableRule(browser) {
  const rows = await eventRows(browser);
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const eventId = await row.getAttribute("data-activity-event");
    const rowSelector = `[data-activity-event="${eventId}"]`;
    await clickSelector(browser, `${rowSelector} [data-activity-toggle]`);
    await browser.pause(150);
    const actions = await browser.$$(`${rowSelector} [data-network-set]`);
    if (actions.length >= 2) return eventId;
    await clickSelector(browser, `${rowSelector} [data-activity-toggle]`);
  }
  throw new Error("No live Network Activity event exposed typed Always Allow/Always Block actions");
}

async function chooseProtocol(browser) {
  const options = await (await browser.$("[data-activity-protocol]")).$$('option');
  for (let index = 0; index < options.length; index += 1) {
    const value = await options[index].getAttribute("value");
    if (value && value !== "ALL") return value;
  }
  throw new Error("Network Activity did not expose a concrete protocol option");
}

async function clearFilters(browser) {
  const clear = await browser.$("[data-activity-clear]");
  if ((await clear.getAttribute("disabled")) === null) await clickSelector(browser, "[data-activity-clear]");
  await browser.waitUntil(
    async () => (await (await browser.$("[data-activity-search]")).getValue()) === "",
    {timeout: 10000, interval: 250, timeoutMsg: "Clear Filters did not reset search"},
  );
}

async function waitForPendingEvents(browser, timeout = 15000) {
  const deadline = Date.now() + timeout;
  let status = "";
  while (Date.now() < deadline) {
    status = await elementText(browser, "[data-activity-status]");
    if (/new/i.test(status)) return status;
    await browser.pause(500);
  }
  throw new Error(`Paused live activity did not expose a pending-event count (status=${status})`);
}

async function updateState(browser) {
  return browser.execute(() => {
    const surface = document.querySelector("[data-update-state]");
    return surface ? {
      state: surface.dataset.updateState,
      available: Number(surface.dataset.updateAvailableCount || 0),
      progress: document.querySelectorAll(".transaction-field .progress-block").length,
      text: surface.textContent || "",
    } : null;
  });
}

async function privacyUiState(browser) {
  return browser.execute(() => {
    const surface = document.querySelector("[data-privacy-profile-state]");
    return surface ? {
      current: surface.dataset.profileCurrent,
      pending: surface.dataset.profilePending || "",
      busy: surface.getAttribute("aria-busy"),
      text: surface.textContent || "",
    } : null;
  });
}

async function tauriPrivacyProfile(browser) {
  return browser.execute(async () => {
    const payload = await window.__TAURI_INTERNALS__.invoke("get_privacy");
    return String(payload?.profile?.value || "").toUpperCase();
  });
}

async function waitForPrivacyProfile(browser, target) {
  let state;
  await browser.waitUntil(
    async () => {
      state = await privacyUiState(browser);
      return state && state.current === target && state.pending === "" && await tauriPrivacyProfile(browser) === target;
    },
    {timeout: 30000, interval: 500, timeoutMsg: `Privacy profile did not converge to ${target}`},
  );
  return state;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

async function inspectExport(path) {
  const output = await remoteCommand(`test -f ${shellQuote(path)} && stat -c '%a' -- ${shellQuote(path)} && python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8")); print("valid")' ${shellQuote(path)}`);
  const lines = output.split(/\r?\n/).filter(Boolean);
  assert.equal(lines[0], "600", `export permissions were not restrictive: ${output}`);
  assert.equal(lines[1], "valid", `export did not satisfy the JSON contract: ${output}`);
}

test("real Tauri Network Activity workflow is interactive through WebDriver", async (t) => {
  if (!(endpoint && application && (localExecution || sshConfig))) {
    t.skip("GREYWARD_TAURI_WEBDRIVER_URL and GREYWARD_TAURI_APPLICATION plus either local guest execution or GREYWARD_INTERACTION_SSH_CONFIG are required for a real Fedora interaction run");
    return;
  }

  const capabilities = createTauriCapabilities(application, {
    driverProvider: "external",
    appBinaryPath: application,
    tauriDriverPort: 4444,
    startTimeout: 60000,
  });
  delete capabilities["wdio:tauriServiceOptions"];

  const driverUrl = new URL(endpoint);
  const openBrowser = () => remote({
    protocol: driverUrl.protocol.replace(":", ""),
    hostname: driverUrl.hostname,
    port: Number(driverUrl.port || 80),
    path: driverUrl.pathname || "/",
    logLevel: "warn",
    connectionRetryTimeout: 60000,
    connectionRetryCount: 5,
    capabilities,
  });
  let browser = await openBrowser();
  t.after(async () => browser.deleteSession());

  await clickSelector(browser, 'button[data-page="privacy"]');
  await waitFor(browser, "[data-privacy-profile-state]");
  await clickSelector(browser, '[data-action="export"]');
  await browser.waitUntil(
    async () => /Export complete:/i.test(await elementText(browser, "[data-privacy-action-status]")),
    {timeout: 30000, interval: 250, timeoutMsg: "Privacy export did not retain a completion destination"},
  );
  const exportStatus = await elementText(browser, "[data-privacy-action-status]");
  const exportPathMatch = exportStatus.match(/(\/[^\s]+posture-latest\.json)/);
  assert.ok(exportPathMatch, `Privacy export status did not expose the backend destination: ${exportStatus}`);
  const exportPath = exportPathMatch[1];
  await inspectExport(exportPath);
  assert.match(exportPath, /\/\.local\/state\/greyward\/security-center\/exports\/posture-latest\.json$/);
  await remoteCommand(`rm -- ${shellQuote(exportPath)}`);
  console.log(`RUNTIME_EVIDENCE privacy_export=pass destination=${exportPath} permissions=600 contract=valid cleaned=true`);

  const initialPrivacyProfile = await tauriPrivacyProfile(browser);
  assert.equal(initialPrivacyProfile, "STANDARD", `runtime Privacy workflow must start from the recovered STANDARD baseline, got ${initialPrivacyProfile}`);
  await armPrivacyWatchdog();
  for (const target of ["PRIVATE", "TRAVEL", "STANDARD"]) {
    const label = target.charAt(0) + target.slice(1).toLowerCase();
    await clickSelector(browser, `[data-profile="${label}"]`);
    await browser.waitUntil(
      async () => {
        const state = await privacyUiState(browser);
        return state && state.pending === target;
      },
      {timeout: 10000, interval: 100, timeoutMsg: `Privacy ${target} transition did not expose a semantic pending state`},
    );
    const confirmed = await waitForPrivacyProfile(browser, target);
    assert.equal(confirmed.current, target, `Privacy UI did not render the confirmed ${target} profile`);
    assert.equal(await tauriPrivacyProfile(browser), target, `authoritative Tauri Privacy state did not confirm ${target}`);
  }
  await cancelPrivacyWatchdog();
  console.log(`RUNTIME_EVIDENCE privacy_profiles=pass transitions=STANDARD>PRIVATE>TRAVEL>STANDARD initial=${initialPrivacyProfile}`);

  await browser.deleteSession();
  browser = await openBrowser();
  await clickSelector(browser, 'button[data-page="privacy"]');
  await waitFor(browser, "[data-privacy-profile-state]");
  const restartedPrivacy = await waitForPrivacyProfile(browser, "STANDARD");
  assert.equal(restartedPrivacy.current, "STANDARD", "application restart did not render the effective Privacy profile");
  console.log("RUNTIME_EVIDENCE privacy_restart=pass effective=STANDARD");

  await clickSelector(browser, 'button[data-page="updates"]');
  await waitFor(browser, "[data-update-state]");
  await waitFor(browser, "[data-update-resolve]", 60000);
  await clickSelector(browser, "[data-update-resolve]");
  let busyObserved = false;
  await browser.waitUntil(
    async () => {
      const state = await updateState(browser);
      if (state && ["CHECKING", "AUTHENTICATING", "RESOLVING", "DOWNLOADING", "INSTALLING", "VERIFYING", "CHECKPOINTING", "PREPARING_RESTART", "UPDATING_APPLICATIONS", "UPDATING_FIRMWARE", "UPDATING_SECURITY", "RESTARTING"].includes(state.state)) busyObserved = true;
      return busyObserved;
    },
    {timeout: 15000, interval: 250, timeoutMsg: "Updates Check did not expose a semantic busy phase"},
  );
  await browser.waitUntil(
    async () => {
      const state = await updateState(browser);
      return state && !["CHECKING", "AUTHENTICATING", "RESOLVING", "DOWNLOADING", "INSTALLING", "VERIFYING", "CHECKPOINTING", "PREPARING_RESTART", "UPDATING_APPLICATIONS", "UPDATING_FIRMWARE", "UPDATING_SECURITY", "RESTARTING"].includes(state.state) && state.progress === 0;
    },
    {timeout: 120000, interval: 500, timeoutMsg: "Updates Check did not reach a terminal or review state"},
  );
  const terminalUpdate = await updateState(browser);
  assert.ok(busyObserved, "Updates Check never exposed a busy phase");
  assert.equal(terminalUpdate.progress, 0, "terminal Updates state retained a progress indicator");
  assert.doesNotMatch(terminalUpdate.text, /Applying the update|Checking for updates…/i, "terminal Updates state retained stale progress text");
  if (terminalUpdate.available > 0) {
    assert.notEqual(terminalUpdate.state, "COMPLETE", "historical completion outranked currently available updates");
    assert.ok((await browser.$$(".update-row")).length > 0, "available update count had no rendered update rows");
  }
  assert.ok(await (await browser.$(".journal-section h2")).isExisting(), "Update history surface was not rendered");
  const historyRows = await browser.$$('[data-update-history-row]');
  if (historyRows.length > 0) assert.doesNotMatch(await historyRows[0].getText(), /undefined|null/i, "history row contained fabricated placeholder text");
  console.log(`RUNTIME_EVIDENCE updates=pass busy=${busyObserved} terminal=${terminalUpdate.state} available=${terminalUpdate.available} progress_reset=${terminalUpdate.progress === 0} history_rows=${historyRows.length}`);

  await clickSelector(browser, 'button[data-page="network"]');
  await clickSelector(browser, '.context-navigation button[data-page="activity"]');
  await waitFor(browser, 'h1');
  await waitFor(browser, '[data-activity-pause]');

  await clearFilters(browser);
  let before = await eventIds(browser);
  await clickSelector(browser, "[data-activity-pause]");
  assert.match(await elementText(browser, "[data-activity-pause]"), /Resume/i);
  assert.match(await elementText(browser, "[data-activity-status]"), /Updates paused/i);
  await generateTraffic();
  await browser.pause(3000);
  await clickSelector(browser, "[data-refresh]");
  await waitForPendingEvents(browser);
  assert.deepEqual(await eventIds(browser), before, "paused live rows changed before Resume");
  await clickSelector(browser, "[data-activity-pause]");
  await browser.waitUntil(
    async () => !/new/i.test(await elementText(browser, "[data-activity-status]")),
    {timeout: 10000, interval: 250, timeoutMsg: "Resume did not clear the pending-event indicator"},
  );
  before = await eventIds(browser);
  assert.ok(before.length, "Resume produced no live activity rows");

  await clickSelector(browser, "[data-activity-pause]");
  await generateTraffic();
  await browser.pause(3000);
  await clickSelector(browser, "[data-refresh]");
  await waitForPendingEvents(browser);
  await clickSelector(browser, "[data-activity-pause]");
  const afterResume = await waitForNewEvents(browser, before);
  assert.equal(new Set(afterResume).size, afterResume.length, "Resume produced duplicate event IDs");

  const search = await browser.$("[data-activity-search]");
  await setField(browser, "[data-activity-search]", "example.com");
  await browser.waitUntil(async () => (await eventRows(browser)).length > 0, {timeout: 10000, interval: 250, timeoutMsg: "search filter hid the observed example.com event"});
  const decision = await browser.$("[data-activity-decision]");
  await selectValue(browser, "[data-activity-decision]", "ALLOWED");
  assert.equal(await decision.getValue(), "ALLOWED");
  const protocol = await chooseProtocol(browser);
  await selectValue(browser, "[data-activity-protocol]", protocol);
  assert.equal(await (await browser.$("[data-activity-protocol]")).getValue(), protocol);
  const port = await browser.$("[data-activity-port]");
  await setField(browser, "[data-activity-port]", "443");
  assert.equal(await port.getValue(), "443");
  await generateTraffic();
  await browser.pause(2500);
  assert.equal(await search.getValue(), "example.com", "live polling lost search filter");
  assert.equal(await port.getValue(), "443", "live polling lost port filter");
  await clearFilters(browser);
  assert.equal(await (await browser.$("[data-activity-decision]")).getValue(), "ALL");
  assert.equal(await (await browser.$("[data-activity-protocol]")).getValue(), "ALL");
  assert.equal(await (await browser.$("[data-activity-port]")).getValue(), "");

  await clickSelector(browser, '[data-activity-mode="history"]');
  await waitFor(browser, "[data-activity-window]");
  for (const range of ["6h", "24h"]) {
    await selectValue(browser, "[data-activity-window]", range);
    await browser.waitUntil(async () => (await (await browser.$("[data-activity-window]")).getValue()) === range, {timeout: 10000, interval: 250, timeoutMsg: `history range ${range} was not retained`});
  }
  assert.ok((await eventRows(browser)).length > 0, "history range was not populated by the generated activity");
  await setField(browser, "[data-activity-search]", "__greyward_no_such_activity__");
  await browser.pause(600);
  assert.match(await elementText(browser, "[data-network-activity-list]"), /No matching|No activity|unavailable/i, "empty filtered history was not rendered");
  await clearFilters(browser);
  await browser.waitUntil(async () => (await (await browser.$("[data-activity-window]")).getValue()) === "30m", {timeout: 10000, interval: 250, timeoutMsg: "Clear Filters did not reset history range"});
  const loadMore = await browser.$("[data-activity-load-more]");
  console.log(`RUNTIME_EVIDENCE pagination=${await loadMore.isExisting() ? "available" : "not-needed"}`);
  await clickSelector(browser, '[data-activity-mode="live"]');
  await waitFor(browser, "[data-activity-pause]");
  assert.equal(await (await browser.$('[data-activity-mode="live"]')).getAttribute("aria-pressed"), "true");

  await generateTraffic();
  await browser.pause(3000);
  const ruleEventId = await findExpandableRule(browser);
  await clickSelector(browser, `[data-activity-event="${ruleEventId}"] [data-network-set][data-network-action="allow"]`);
  await browser.waitUntil(async () => /saved|allow/i.test(await elementText(browser, "#network-action-status")), {timeout: 10000, interval: 200, timeoutMsg: "Always Allow did not expose UI feedback"});
  await waitFor(browser, 'h1');
  await browser.waitUntil(async () => (await browser.$$('[data-network-remove]')).length > 0, {timeout: 15000, interval: 500, timeoutMsg: "Always Allow did not render the saved rule"});
  const allowRule = await waitForPolicyRule("ALLOW", browser);
  assert.ok(allowRule.id, "Always Allow readback did not provide a mutable rule ID");
  await clickSelector(browser, `[data-network-remove][data-rule-id="${allowRule.id}"]`);
  await browser.waitUntil(async () => /removed/i.test(await elementText(browser, "#network-action-status")), {timeout: 10000, interval: 200, timeoutMsg: "Allow rule removal did not expose UI feedback"});
  await waitForNoPolicyRule(browser);
  await browser.pause(1200);

  await clickSelector(browser, '.context-navigation button[data-page="activity"]');
  await waitFor(browser, "[data-activity-pause]");
  await generateTraffic();
  await browser.pause(3000);
  await clickSelector(browser, "[data-refresh]");
  await browser.pause(2500);
  const blockEventId = await findExpandableRule(browser);
  await clickSelector(browser, `[data-activity-event="${blockEventId}"] [data-network-set][data-network-action="deny"]`);
  await browser.waitUntil(async () => /saved|block/i.test(await elementText(browser, "#network-action-status")), {timeout: 10000, interval: 200, timeoutMsg: "Always Block did not expose UI feedback"});
  await waitFor(browser, 'h1');
  await browser.waitUntil(async () => (await browser.$$('[data-network-remove]')).length > 0, {timeout: 15000, interval: 500, timeoutMsg: "Always Block did not render the saved rule"});
  const blockRule = await waitForPolicyRule("DENY", browser);
  assert.ok(blockRule.id, "Always Block readback did not provide a mutable rule ID");
  await clickSelector(browser, `[data-network-remove][data-rule-id="${blockRule.id}"]`);
  await browser.waitUntil(async () => /removed/i.test(await elementText(browser, "#network-action-status")), {timeout: 10000, interval: 200, timeoutMsg: "Block rule removal did not expose UI feedback"});
  await waitForNoPolicyRule(browser);
  console.log("RUNTIME_EVIDENCE network_activity=pass pause_resume=pass filters=pass history=pass rule_allow_block_cleanup=pass");
});
