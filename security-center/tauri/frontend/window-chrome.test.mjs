import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("./window-chrome.js", import.meta.url), "utf8");
const settle = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const element = dataset => ({dataset, listeners: {}, addEventListener(type, fn) {this.listeners[type] = fn;}, imgs: [{}, {}], querySelectorAll() {return this.imgs;}});
  const buttons = [element({windowAction: "minimize", windowAsset: "iconify"}), element({windowAction: "toggleMaximize", windowAsset: "max"}), element({windowAction: "close", windowAsset: "close"})];
  const drag = element({}), edge = element({windowEdge: "SouthEast"}), feedback = {};
  const bar = {innerHTML: "", querySelectorAll: () => buttons, querySelector: selector => selector.includes("toggleMaximize") ? buttons[1] : selector.includes("feedback") ? feedback : drag};
  const edges = {innerHTML: "", querySelectorAll: () => [edge]};
  const body = {dataset: {}}, calls = [], events = {};
  const state = {maximized: false, focused: true};
  const window = {GREYWARD_I18N: {t: key => key}, addEventListener: (event, fn) => {events[event] = fn;}, __TAURI__: {event: {listen: (event, fn) => {events[event] = fn;}}}, __TAURI_INTERNALS__: {invoke: async (command, args) => {
    calls.push({command, ...args});
    if (args.action === "toggleMaximize") state.maximized = !state.maximized;
    return {...state};
  }}};
  vm.runInNewContext(source, {window, document: {body, querySelector: selector => selector === "#window-titlebar" ? bar : edges}});
  return {bar, body, buttons, drag, edge, feedback, calls, events, window};
}

test("controls retain native labels and refresh actual maximize/focus state", async () => {
  const f = fixture(); await settle();
  assert.match(f.bar.innerHTML, /type="button"/);
  assert.doesNotMatch(f.bar.innerHTML, /GREYWARD|Security Center|<svg/);
  await f.buttons[1].listeners.click();
  assert.equal(f.body.dataset.windowMaximized, "true");
  assert.equal(f.buttons[1].ariaLabel, "window.restore");
  await f.buttons[1].listeners.click();
  assert.equal(f.buttons[1].ariaLabel, "window.maximize");
  f.events["tauri://focus"]({payload: false});
  assert.match(f.buttons[0].imgs[0].src, /iconify-inactive.svg$/);
  assert.match(f.buttons[2].imgs[1].src, /close_hover-inactive.svg$/);
});

test("drag and resize use bounded native actions; maximization disables resizing", async () => {
  const f = fixture(); await settle();
  const event = {button: 0, detail: 1, preventDefault() {}};
  f.drag.listeners.mousedown(event); await settle();
  assert.equal(f.calls.at(-1).action, "drag");
  f.edge.listeners.mousedown(event); await settle();
  assert.equal(f.calls.at(-1).edge, "SouthEast");
  f.drag.listeners.mousedown({...event, detail: 2}); await settle();
  assert.equal(f.calls.at(-1).action, "toggleMaximize");
  const count = f.calls.length;
  f.edge.listeners.mousedown(event);
  f.drag.listeners.mousedown({...event, button: 2});
  assert.equal(f.calls.length, count);
});

test("failed window operations stay local and do not invent a successful state", async () => {
  const f = fixture(); await settle();
  f.window.__TAURI_INTERNALS__.invoke = async () => {throw Error("unavailable");};
  await f.buttons[1].listeners.click();
  assert.equal(f.body.dataset.windowMaximized, "false");
  assert.equal(f.feedback.textContent, "window.failed");
});

test("all window artwork is byte-identical to the canonical GREYWARD Labwc theme", () => {
  for (const glyph of ["iconify", "max", "close"]) for (const state of ["active", "inactive"]) for (const hover of ["", "_hover"]) {
    const name = `${glyph}${hover}-${state}.svg`;
    assert.deepEqual(readFileSync(new URL(`./assets/window-controls/${name}`, import.meta.url)), readFileSync(new URL(`../../../environment/session/labwc/Greyward/${name}`, import.meta.url)));
  }
});
