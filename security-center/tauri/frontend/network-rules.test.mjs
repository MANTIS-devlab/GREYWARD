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
    request: async (command,args,...rest) => {
      const result = await request(command,args,...rest);
      if (command === "network_rules_list" && result.provider == null && Array.isArray(result.rules)) {
        const rows = result.rules.filter(r=>r.provider === args.payload.provider);
        return {...result,provider:args.payload.provider,rules:rows,total:rows.length,
          next_offset:rows.length ? result.next_offset:null};
      }
      return result;
    }, esc, icon: () => "<svg></svg>", identity: (_kind, values) => `<span>${esc(values[0])}</span>`,
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

test("an older mixed snapshot cannot replace a new snapshot or its traffic filter", async () => {
  let finish, appCalls=0, incomingCalls=0;
  const {controller} = fixture(async (_command,{payload}) => {
    if(payload.provider === "incoming") return page([],{provider:"incoming",revision:++incomingCalls});
    return ++appCalls === 1 ? new Promise(resolve=>{finish=resolve;}) : page([{...rule,name:"New snapshot"}],{provider:"application",revision:2});
  });
  const old = controller.load();
  controller.state.filterProvider = 'incoming';
  await controller.load();
  finish(page([rule], {provider: 'application'}));
  await old;
  assert.equal(controller.state.filterProvider, 'incoming');
  assert.equal(controller.state.data.rules[0].name, 'New snapshot');
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
  assert.equal(calls.filter(c=>c.command==="network_rules_list").length,2);
  assert.deepEqual(calls.filter(c=>c.command!=="network_rules_list").map(c=>c.command),["network_rules_preview"]);
  assert.equal(calls.at(-1).args.payload.provider,"application");
  assert.match(controller.markup(), /Authenticate and apply/);
});

test("exports all pages at one revision and preserves incoming source restrictions", async () => {
  const incoming = {...rule, provider: "incoming", source: "192.0.2.0/24", zone: "public", owner: "GREYWARD"};
  const {controller} = fixture(async (_command,{payload}) => payload.provider === "application" ? page([],{provider:"application"}) : payload.offset === 100
    ? page([{...incoming, id:"greyward-11111111111111111111"}],{provider:"incoming"})
    : page([incoming], {provider:"incoming",next_offset:100}));
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
    let bad = false;
    const {controller} = fixture(async (_command,{payload}) => {
      if(payload.provider==="incoming")return page([],{provider:"incoming"});
      return !bad ? page() : page([rule],changeRevision ? {revision:2}:{next_offset:0});
    });
    await controller.load();
    bad=true;
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

test("mixed rules share one source/destination/service table and provider-local bulk controls",async()=>{
  const incoming={...rule,id:"greyward-11111111111111111111",provider:"incoming",path:undefined,source:"192.0.2.0/24",zone:"public",service:"https",ports:[],position:0};
  const catalog={zones:["public"],services:["https"],service_details:[{id:"https",label:"Secure WWW (HTTPS)",ports:[["443","tcp"]],simple:true}]};
  const {controller}=fixture(async(_,{payload})=>payload.provider==="incoming" ? page([incoming],{provider:"incoming",catalog}):page([rule],{provider:"application"}));
  await controller.load();controller.state.selected.add(rule.id);controller.state.selected.add(incoming.id);
  const html=controller.markup();
  assert.match(html,/network-rule-table/);assert.match(html,/192\.0\.2\.0\/24/);assert.match(html,/\/usr\/bin\/example/);
  assert.match(html,/443\/TCP/);assert.match(html,/OpenSnitch/);assert.match(html,/firewalld/);
  assert.match(html,/data-provider="application"/);assert.match(html,/data-provider="incoming"/);
  assert.match(html,/A1/);assert.match(html,/I1/);assert.doesNotMatch(html,/network\.rules\./);
});

test("services search by real name or port and expose precise protocol mappings",async()=>{
  const catalog={zones:["public"],services:["https","ssh"],service_details:[{id:"https",label:"Secure WWW (HTTPS)",ports:[["443","tcp"]],simple:true},{id:"ssh",label:"SSH",ports:[["22","tcp"]],simple:true}]};
  const {controller,api}=fixture(async(_,{payload})=>page([],{provider:payload.provider,catalog}));
  await controller.load();controller.begin({path:"/usr/bin/example"});controller.state.serviceOpen=true;controller.state.serviceQuery="443";
  let html=controller.markup();assert.match(html,/data-rule-service="https"/);assert.doesNotMatch(html,/data-rule-service="ssh"/);assert.match(html,/443\/TCP/);
  controller.state.serviceQuery="SSH";html=controller.markup();assert.match(html,/data-rule-service="ssh"/);assert.match(html,/22\/TCP/);
  assert.deepEqual(JSON.parse(JSON.stringify(api.serviceScope({simple:true,ports:[["53","tcp"],["53","udp"]]}))),{ports:[[53,53]],protocols:["tcp","udp"]});
  assert.equal(api.serviceScope({simple:true,ports:[["80","tcp"],["443","udp"]]}),null,"Never create the extra 80/UDP or 443/TCP combinations");
  assert.equal(api.serviceScope({simple:false,ports:[["21","tcp"]]}),null,"Complex service helpers are not flattened into ports");
});

test("an unreadable provider is not rendered as an empty healthy rule set",async()=>{
  const {controller}=fixture(async(_,{payload})=>{if(payload.provider==="incoming")throw new Error("Incoming unavailable");return page();});
  await controller.load();controller.state.filterProvider="incoming";
  const html=controller.markup();assert.match(html,/Some directions could not be read/);assert.match(html,/Rule service unavailable/);assert.doesNotMatch(html,/<h2>No rules here yet/);
});


test("availability controls and restore reviews retain clear localized actions",async()=>{
  for(const locale of ["en-US","fr-FR"]){
    const {controller}=fixture(async(command)=>command==="network_rules_list" ? page([rule]):{ok:true,transaction:"restore",changes:[{operation:"restore order",rule:{name:"application rule order and membership"}}],warnings:[]},locale);
    await controller.load();controller.state.selected.add(rule.id);
    let html=controller.markup();assert.match(html,locale==="fr-FR" ? /Activer/:/Enable/);
    await controller.reviewCommands([]);html=controller.markup();
    assert.doesNotMatch(html,/network\.rules\.|undefined|restore order/);
    assert.match(html,locale==="fr-FR" ? /Restaurer l’ordre des règles/:/Restore rule order/);
  }
});


test("both traffic directions share fully translated editor fields",async()=>{
  for(const locale of ["en-US","fr-FR"]){
    const {controller}=fixture(async(_,{payload})=>page([],{provider:payload.provider,catalog:{zones:["public"],service_details:[]}}),locale);
    await controller.load();
    for(const provider of ["application","incoming"]){
      controller.state.provider=provider;controller.begin({provider});controller.state.serviceOpen=true;
      const html=controller.markup();assert.doesNotMatch(html,/network\.rules\.|undefined/);assert.match(html,/data-rule-service-search/);assert.match(html,/network-flow-path/);
    }
  }
});
