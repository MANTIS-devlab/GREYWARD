import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("./network-rules.js", import.meta.url), "utf8");
const i18n = readFileSync(new URL("./i18n.js", import.meta.url), "utf8");
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[c]);
function fixture(request, locale = "en") {
  const context = {navigator: {language: locale}, console, setTimeout, clearTimeout};
  vm.runInNewContext(source, context);
  vm.runInNewContext(i18n, context);
  return {api: context.GREYWARD_NETWORK_RULES, controller: context.GREYWARD_NETWORK_RULES.create({
    request, esc, icon: () => "<svg></svg>", identity: (_kind, values) => `<span>${esc(values[0])}</span>`,
    t: context.GREYWARD_I18N.t,
  })};
}
const rule = {id: "greyward-01234567890123456789", provider: "application", path: "/usr/bin/example", name: "Example",
  action: "deny", enabled: true, scope: "user", uid: 1000, ports: [[443, 443]], protocols: ["tcp"], destinations: [], lifetime: "permanent", position: 0, state: "SAVED"};
const page = (rules = [rule], extra = {}) => ({ok: true, revision: 1, rules, total: rules.length, next_offset: null, capabilities: {edit: true}, ...extra});

test("the complete bundled script order boots with network rules enabled", async () => {
  const index = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const scripts = [...index.matchAll(/<script src="([^"]+)"/g)].map(match => match[1]);
  for (const route of ["overview", "network-rules"]) {
    const calls = [], errors = [];
    const element = () => ({innerHTML: "", dataset: {}, style: {},
      classList: {add() {}, remove() {}, toggle() {}},
      querySelector: () => null, querySelectorAll: () => [],
      setAttribute() {}, addEventListener() {}});
    const app = element(), control = element(), bar = element(), edges = element();
    bar.querySelector = () => control;
    const context = {URLSearchParams, performance, navigator: {language: "en"},
      location: {search: `?page=${route}`}, localStorage: {getItem: () => null},
      console: {error: (...args) => errors.push(args), warn() {}, log() {}},
      setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {},
      requestAnimationFrame: callback => callback(), addEventListener() {},
      document: {hidden: false, documentElement: element(), addEventListener() {},
        querySelector: selector => ({"#app": app, "#window-titlebar": bar, "#window-resize-edges": edges}[selector] || null)},
      // Keep real provider reads pending: this checks bootstrap, not fake security state.
      __TAURI_INTERNALS__: {invoke: command => { calls.push(command); return new Promise(() => {}); }}};
    context.window = context;
    vm.createContext(context);
    for (const script of scripts) {
      vm.runInContext(readFileSync(new URL(script, import.meta.url), "utf8"), context, {filename: script});
    }
    await Promise.resolve();
    assert.ok(context.__greywardStartupMarks.some(mark => mark.name === "frontend_bootstrap_complete"), route);
    assert.match(app.innerHTML, /app-shell/, route);
    assert.doesNotMatch(app.innerHTML, /Security Center could not start/);
    assert.deepEqual(errors, []);
    if (route === "network-rules") assert.ok(calls.includes("network_rules_list"));
  }
});

test("new rule controls remain unavailable when the real read fails", async () => {
  const {controller} = fixture(async () => { throw new Error("Provider unavailable"); });
  await controller.load();
  const html = controller.markup();
  assert.match(html, /data-rule-new disabled/);
  assert.match(html, /Rule service unavailable/);
  assert.doesNotMatch(html, /Observed matching/);
});

test("a slow application response cannot replace the newly selected incoming provider", async () => {
  let finish;
  const {controller} = fixture(async (_command, {payload}) => payload.provider === 'application'
    ? new Promise(resolve => { finish = resolve; }) : page([], {provider: 'incoming', revision: 2}));
  const old = controller.load();
  controller.state.provider = 'incoming';
  await controller.load();
  finish(page([rule], {provider: 'application'}));
  await old;
  assert.equal(controller.state.data.provider, 'incoming');
  assert.equal(controller.state.data.revision, 2);
});

test("saved rules are not rendered as observed or protected", async () => {
  const {controller} = fixture(async () => page());
  await controller.load();
  const html = controller.markup();
  assert.match(html, /state-saved/);
  assert.doesNotMatch(html, /state-observed|state-protected/);
  assert.match(html, /\/usr\/bin\/example/);
});

test("untrusted rule names and paths are escaped", async () => {
  const {controller} = fixture(async () => page([{...rule, name: '<img src=x onerror="alert(1)">', path: '/tmp/<script>evil</script>'}]));
  await controller.load();
  const html = controller.markup();
  assert.doesNotMatch(html, /<script>|<img src=x/);
  assert.match(html, /&lt;script&gt;/);
});

test("English and French rule vocabulary has parity and joins the main catalog", () => {
  const {api} = fixture(async () => page());
  assert.deepEqual(Object.keys(api.copy.en).sort(), Object.keys(api.copy.fr).sort());
  const {controller} = fixture(async () => page(), "fr-FR");
  assert.match(controller.markup(), /Règles réseau/);
  assert.doesNotMatch(controller.markup(), /network\.rules\./);
});

test("creating from Activity only prepares a draft, never a policy write", async () => {
  const calls = [];
  const {controller} = fixture(async (...args) => { calls.push(args); return page(); });
  controller.begin({path: "/usr/bin/example", action: "deny"});
  assert.equal(calls.length, 0);
  assert.equal(controller.state.draft.path, "/usr/bin/example");
  assert.match(controller.markup(), /data-rule-form/);
});

test("reviewing a bulk change cannot automatically authenticate or apply", async () => {
  const calls = [];
  const {controller} = fixture(async (command, args) => {
    calls.push({command, args});
    return command === "network_rules_list" ? page() : {ok: true, transaction: "opaque-review", changes: [{operation: "delete", rule}], warnings: []};
  });
  await controller.reviewCommands([{operation: "delete", id: rule.id}]);
  assert.deepEqual(calls.map(c => c.command), ["network_rules_list", "network_rules_preview"]);
  assert.match(controller.markup(), /Authenticate and apply/);
});

test("exports all pages at one revision and preserves incoming source restrictions", async () => {
  const incoming = {...rule, provider: "incoming", source: "192.0.2.0/24", zone: "public", owner: "GREYWARD"};
  const {controller} = fixture(async (_command, {payload}) => payload.offset === 100
    ? page([{...incoming, id: "greyward-11111111111111111111"}])
    : page([incoming], {next_offset: 100}));
  controller.state.provider = "incoming";
  await controller.load();
  const exported = await controller.exportDocument();
  assert.equal(exported.rules.length, 2);
  assert.equal(exported.rules[0].source, "192.0.2.0/24");
  assert.equal(exported.rules[0].owner, undefined);
  assert.equal(exported.rules[0].state, undefined);
});

test("export refuses changed revisions and a repeated page cursor", async () => {
  for (const changeRevision of [true, false]) {
    let count = 0;
    const {controller} = fixture(async () => {
      count += 1;
      return count === 1 ? page() : page([], changeRevision ? {revision: 2} : {next_offset: 0});
    });
    await controller.load();
    await assert.rejects(controller.exportDocument());
  }
});

test("destination and port presentation preserve precise scopes", () => {
  const {api} = fixture(async () => page());
  assert.deepEqual(JSON.parse(JSON.stringify(api.destinations("*.example.org, 2001:db8::/32, 203.0.113.4"))), [
    {kind: "domain", value: "example.org"}, {kind: "network", value: "2001:db8::/32"}, {kind: "ip", value: "203.0.113.4"},
  ]);
  assert.equal(api.portsText([[80, 80], [8000, 8010]]), "80, 8000-8010");
  assert.equal(api.portsText("443,8000-8010"), "443,8000-8010");
});
