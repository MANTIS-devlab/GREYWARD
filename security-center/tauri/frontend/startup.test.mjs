import assert from "node:assert/strict";
import test from "node:test";
import {createTauriCapabilities} from "@wdio/tauri-service";
import {remote} from "webdriverio";

const endpoint = process.env.GREYWARD_TAURI_WEBDRIVER_URL;
const application = process.env.GREYWARD_TAURI_APPLICATION;

async function waitForOverview(browser) {
  await browser.waitUntil(
    async () => (await browser.$(".overview-brief")).isExisting() || (await browser.$(".error-state")).isExisting(),
    {timeout: 10000, interval: 50, timeoutMsg: "Timed out waiting for authoritative Overview"},
  );
  assert.equal(await browser.$(".error-state").isExisting(), false);
}

async function launchOnce() {
  const capabilities = createTauriCapabilities(application, {
    driverProvider: "external",
    appBinaryPath: application,
    tauriDriverPort: 4444,
    startTimeout: 60000,
  });
  delete capabilities["wdio:tauriServiceOptions"];
  const driverUrl = new URL(endpoint);
  const processStartEpoch = Date.now();
  const processStart = performance.now();
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
  try {
    await waitForOverview(browser);
    await browser.executeAsync((done) => requestAnimationFrame(() => done()));
    const sessionMs = Math.round((performance.now() - processStart) * 100) / 100;
    const timeline = await browser.execute((startEpoch) => {
      const timeOrigin = performance.timeOrigin;
      return [...(window.__greywardStartupMarks || [])].map((entry) => ({
        ...entry,
        process_ms: Math.round((timeOrigin + entry.ms - startEpoch) * 100) / 100,
      }));
    }, processStartEpoch);
    return {session_ms: sessionMs, timeline};
  } finally {
    await browser.deleteSession();
  }
}

test("measures one real Tauri startup phase", async (t) => {
  if (!(endpoint && application)) {
    t.skip("GREYWARD_TAURI_WEBDRIVER_URL and GREYWARD_TAURI_APPLICATION are required for a real Fedora startup run");
    return;
  }
  console.log(`RUNTIME_STARTUP ${JSON.stringify(await launchOnce())}`);
});
