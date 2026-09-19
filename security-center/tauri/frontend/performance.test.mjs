import assert from "node:assert/strict";
import {execFile} from "node:child_process";
import test from "node:test";
import {promisify} from "node:util";
import {createTauriCapabilities} from "@wdio/tauri-service";
import {remote} from "webdriverio";

const endpoint = process.env.GREYWARD_TAURI_WEBDRIVER_URL;
const application = process.env.GREYWARD_TAURI_APPLICATION;
const execFileAsync = promisify(execFile);

const routes = [
  ["overview", ".overview-brief"],
  ["system", ".evidence-resolution"],
  ["files", ".file-security-hero"],
  ["updates", "[data-update-state]"],
  ["applications", ".inventory-section"],
  ["devices", ".device-history-section"],
];

async function waitFor(browser, selector, timeout = 8000) {
  await browser.waitUntil(
    async () => {
      const failure = await browser.$(".error-state");
      if (await failure.isExisting()) return true;
      const marker = await browser.$(selector);
      return await marker.isExisting() && await browser.execute(() => document.querySelector(".app-shell")?.getAttribute("aria-busy") !== "true");
    },
    {timeout, interval: 100, timeoutMsg: `Timed out waiting for ${selector}`},
  );
  if (!(await browser.$(selector)).isExisting()) {
    throw new Error(`Page failed while waiting for ${selector}: ${await browser.$(".error-state").getText()}`);
  }
}

async function navigate(browser, route, marker) {
  const started = performance.now();
  const startedEpoch = Date.now();
  console.log(`RUNTIME_TRACE start route=${route}`);
  const direct = await browser.execute((page) => {
    let element = document.querySelector(`button.nav-item[data-page="${page}"]`);
    if (!element) element = document.querySelector(`button[data-page="${page}"]`);
    if (!element && page !== "system") {
      const system = document.querySelector('button.nav-item[data-page="system"]');
      if (system) system.click();
      return false;
    }
    if (!element) throw new Error(`Missing primary navigation target: ${page}`);
    element.click();
    return true;
  }, route);
  console.log(`RUNTIME_TRACE primary_click route=${route} active=${await browser.execute(() => document.querySelector(".context-navigation .active")?.getAttribute("data-page") || document.querySelector(".nav-item.active")?.getAttribute("data-page") || "none")}`);
  if (!direct) {
    await waitFor(browser, `.context-navigation button[data-page="${route}"]`);
    await browser.execute((page) => {
      const element = document.querySelector(`.context-navigation button[data-page="${page}"]`);
      if (!element) throw new Error(`Missing contextual navigation target: ${page}`);
      element.click();
    }, route);
    console.log(`RUNTIME_TRACE contextual_click route=${route} active=${await browser.execute(() => document.querySelector(".context-navigation .active")?.getAttribute("data-page") || "none")}`);
  }
  try {
    await waitFor(browser, marker);
  } catch (error) {
    const state = await browser.execute(() => ({
      busy: document.querySelector(".app-shell")?.getAttribute("aria-busy"),
      text: document.querySelector(".content-frame")?.textContent?.slice(0, 500),
      html: document.querySelector(".content-frame")?.innerHTML?.slice(0, 500),
    }));
    throw new Error(`${error.message}; route=${route} state=${JSON.stringify(state)}`);
  }
  const latency = Math.round((performance.now() - started) * 100) / 100;
  console.log(`RUNTIME_TRACE ready route=${route} latency_ms=${latency}`);
  return latency;
}

async function clearCalls(browser) {
  await browser.execute(() => {
    if (window.__greywardPerformanceCalls) window.__greywardPerformanceCalls.length = 0;
  });
}

async function readCalls(browser) {
  return browser.execute(() => [...(window.__greywardPerformanceCalls || [])]);
}

test("measures real Tauri cold pages, revisits, IPC calls, and idle CPU", async (t) => {
  if (!(endpoint && application)) {
    t.skip("GREYWARD_TAURI_WEBDRIVER_URL and GREYWARD_TAURI_APPLICATION are required for a real Fedora performance run");
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
  const started = performance.now();
  const startedEpoch = Date.now();
  const browser = await remote({
    protocol: driverUrl.protocol.replace(":", ""),
    hostname: driverUrl.hostname,
    port: Number(driverUrl.port || 80),
    path: driverUrl.pathname || "/",
    logLevel: "warn",
    connectionRetryTimeout: 60000,
    connectionRetryCount: 5,
    capabilities,
  });
  t.after(async () => browser.deleteSession());

  await waitFor(browser, ".overview-brief");
  const startupMs = Math.round((performance.now() - started) * 100) / 100;
  const startupTimeline = await browser.execute((processStartEpoch) => {
    const timeOrigin = performance.timeOrigin;
    const marks = [...(window.__greywardStartupMarks || [])];
    return {
      time_origin: timeOrigin,
      marks: marks.map((entry) => ({
        ...entry,
        process_ms: Math.round((timeOrigin + entry.ms - processStartEpoch) * 100) / 100,
      })),
    };
  }, startedEpoch);
  await browser.execute(() => {
    window.__greywardPerformanceCalls = [];
  });

  const cold = {};
  for (const [route, marker] of routes) {
    await clearCalls(browser);
    cold[route] = {latency_ms: await navigate(browser, route, marker), calls: await readCalls(browser)};
  }
  await clearCalls(browser);
  const overviewReturnMs = await navigate(browser, "overview", ".overview-brief");
  const overviewReturnCalls = await readCalls(browser);

  await clearCalls(browser);
  const applicationsRevisitMs = await navigate(browser, "applications", ".inventory-section");
  const applicationsRevisitCalls = await readCalls(browser);
  await clearCalls(browser);
  const filesRevisitMs = await navigate(browser, "files", ".file-security-hero");
  const filesRevisitCalls = await readCalls(browser);

  const idleCallsBefore = await readCalls(browser);
  const cpuSamples = [];
  for (let index = 0; index < 5; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const {stdout} = await execFileAsync("bash", ["-lc", `pid=$(pgrep -u "$USER" -f '${application}($| )' | head -n1); if [ -n "$pid" ]; then ps -p "$pid" -o %cpu= -o rss=; fi`], {timeout: 5000});
    const values = stdout.trim().split(/\s+/).filter(Boolean).map(Number);
    if (values.length >= 2) cpuSamples.push({cpu_percent: values[0], rss_kb: values[1]});
  }
  const idleCallsAfter = await readCalls(browser);

  assert.ok(startupMs >= 0);
  console.log(`RUNTIME_STARTUP process_to_overview_ms=${startupMs} timeline=${JSON.stringify(startupTimeline)}`);
  console.log(`RUNTIME_PERF startup_ms=${startupMs} cold=${JSON.stringify(cold)} overview_return_ms=${overviewReturnMs} overview_return_calls=${JSON.stringify(overviewReturnCalls)} applications_revisit_ms=${applicationsRevisitMs} applications_revisit_calls=${JSON.stringify(applicationsRevisitCalls)} files_revisit_ms=${filesRevisitMs} files_revisit_calls=${JSON.stringify(filesRevisitCalls)} idle_calls_added=${JSON.stringify(idleCallsAfter.slice(idleCallsBefore.length))} idle_process_samples=${JSON.stringify(cpuSamples)}`);
});
