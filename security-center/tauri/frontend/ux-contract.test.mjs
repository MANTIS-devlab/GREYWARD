import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("./app.js", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
const index = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const i18nSource = readFileSync(new URL("./i18n.js", import.meta.url), "utf8");
const iconCatalog = readFileSync(new URL("./assets/network-icons/catalog.js", import.meta.url), "utf8");

function i18nFor(language) {
  const context = {navigator: {language}};
  context.globalThis = context;
  vm.runInNewContext(i18nSource, context);
  return context.GREYWARD_I18N;
}

test("keeps five task-oriented primary destinations without menu numbering", () => {
  assert.match(source, /\["overview", "nav\.overview".*\["system", "nav\.system".*\["network", "nav\.network".*\["privacy", "nav\.privacy".*\["updates", "nav\.updates"/s);
  assert.doesNotMatch(source, /\["protection", "Protection"/);
  assert.doesNotMatch(source, /\["files", "File Security"/);
  assert.doesNotMatch(source, /nav-number/);
});

test("normalizes legacy protection navigation and keeps contextual tools discoverable", () => {
  assert.match(source, /pageAliases = Object\.freeze\(\{protection: "evidence", system: "evidence"\}\)/);
  assert.match(source, /const normalizePage/);
  assert.match(source, /const pageParents = Object\.freeze\(\{files: "system"/);
  assert.match(source, /function contextNavigation/);
  assert.match(source, /\["network", "network\.protection"\], \["activity", "network\.activity"\]/);
  assert.doesNotMatch(source, /function systemSecurityMarkup/);
  assert.match(source, /\["evidence", "route\.evidence"\], \["files", "system\.files"\], \["applications", "system\.apps"\], \["devices", "system\.devices"\]/);
  assert.equal(i18nFor("en").t("route.evidence"), "System checks");
  assert.equal(i18nFor("fr").t("route.evidence"), "Contrôles système");
});

test("an empty overview digest does not resurrect older fallback activity", () => {
  const start = source.indexOf("function overviewActivity(");
  const end = source.indexOf("function updateHistoryMarkup(", start);
  const context = {};
  vm.runInNewContext(source.slice(start, end), context);
  const old = {title: "Old export"};
  assert.equal(context.overviewActivity({activity: [old]}, {recent_activity: []}).length, 0);
  assert.equal(context.overviewActivity({activity: [old]}, {})[0], old);
  assert.equal(context.overviewActivity({}, {recent_activity: [{summary: "New event"} ]})[0].detail, "New event");
});

test("update history leads with newest records and keeps older records available", () => {
  const start = source.indexOf("function updateHistoryMarkup(");
  const end = source.indexOf("function updateHistoryResultKey(", start);
  const context = {
    esc: String, icon: () => "", copy: (key) => key,
    localizedTime: (value) => `LOCAL:${value}`,
    updateHistoryVersionLine: () => "versions", updateHistoryResultKey: () => "unknown",
    technicalDisclosure: (title, count, body) => `<details><summary>${title} ${count}</summary>${body}</details>`,
  };
  vm.runInNewContext(source.slice(start, end), context);
  const records = Array.from({length: 7}, (_, i) => ({name: `Update ${i}`, timestamp: `2026-09-0${i + 1}T12:00:00Z`}));
  const result = context.updateHistoryMarkup(records);
  assert.ok(result.indexOf("Update 6") < result.indexOf("Update 5"));
  assert.equal(result.split("<details>")[0].match(/data-update-history-row/g).length, 5);
  assert.equal(result.match(/data-update-history-row/g).length, 7);
  assert.match(result, /LOCAL:2026-09-07/);
  assert.equal(records[0].name, "Update 0");
  assert.match(context.updateHistoryMarkup([{}]), /updates.history.unnamed/);
  assert.equal(context.updateHistoryMarkup([]), "");
});

test("selects French from a French system locale and otherwise falls back to English", () => {
  assert.equal(i18nFor("fr").locale, "fr");
  assert.equal(i18nFor("fr-FR").locale, "fr");
  assert.equal(i18nFor("en-US").locale, "en");
  assert.equal(i18nFor("de-DE").locale, "en");
  assert.equal(i18nFor("fr-FR").t("nav.system"), "Sécurité du système");
  assert.equal(i18nFor("en-US").t("nav.system"), "System security");
});

test("keeps semantic French and English catalogs complete without literal text replacement", () => {
  const french = i18nFor("fr-FR");
  assert.equal(french.catalogParity(), true);
  assert.match(index, /i18n\.js[\s\S]*app\.js/);
  assert.equal(french.t("applications.title"), "Accès des applications");
  assert.equal(french.t("backup.restore.limit", {limit: 100}), "Sélectionnez au maximum 100 objets pour une restauration.");
  assert.doesNotMatch(i18nSource, /frenchLiterals|localizeMarkup|localizeText|createTreeWalker/);
});

test("keeps accepted findings presented as the plain protected posture", () => {
  const english = i18nFor("en-US");
  const french = i18nFor("fr-FR");
  assert.equal(english.t("design.posture.protected"), "Protected");
  assert.equal(french.t("design.posture.protected"), "Protégé");
  assert.equal(english.t("overview.posture.protected.message"), "All required protections are active.");
  assert.equal(french.t("overview.posture.protected.message"), "Toutes les protections requises sont actives.");
  assert.doesNotMatch(english.t("overview.posture.protected.message"), /ignored|exception|deviation/i);
  assert.doesNotMatch(french.t("overview.posture.protected.message"), /ignor|exception|déviation/i);
});

test("keeps startup, DNS, and Network Protection product copy in the semantic catalog", () => {
  const french = i18nFor("fr-FR");
  assert.equal(french.t("network.dns.modeLabel"), "Mode DNS");
  assert.equal(french.t("network.protection.removeRule"), "Supprimer la règle");
  assert.equal(french.t("startup.title"), "Le Centre de sécurité n’a pas pu démarrer");
  assert.match(source, /copy\("network\.dns\.modeLabel"\)/);
  assert.match(source, /copy\("network\.protection\.removeRule"\)/);
  assert.match(source, /localize\("startup\.title"/);
  assert.doesNotMatch(source, /<div class="eyebrow">SECURE DNS<\/div>/);
  assert.doesNotMatch(source, /<div class="eyebrow">NETWORK PROTECTION<\/div>/);
});

test("keeps Network Activity and technical timestamps in the localized product contract", () => {
  const french = i18nFor("fr-FR");
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.equal(french.t("network.activity.title"), "Activité réseau");
  assert.equal(french.t("network.activity.clearFilters"), "Effacer les filtres");
  assert.match(source, /network\.activity\.historyUnavailable/);
  assert.match(source, /function localizedTime/);
  assert.match(source, /localizedTime\(technical\.observed_at\)/);
  assert.match(rust, /snapshot\.generated_at\.to_rfc3339\(\)/);
  assert.doesNotMatch(source, /<div class="eyebrow">OBSERVATION<\/div>/);
});

test("uses a narrow delta API for live activity without a full-page poll rerender", () => {
  assert.match(source, /get_network_activity/);
  assert.match(source, /setInterval\(refreshNetworkActivity, 2000\)/);
  assert.match(source, /data-network-activity-list/);
  assert.match(source, /const listMarkup = networkActivityRowsMarkup\(\)/);
  assert.match(source, /listMarkup !== networkActivityState\.renderedListMarkup/);
  assert.match(source, /const active = document\.activeElement/);
});

test("pauses background polling while the Tauri window is hidden", () => {
  assert.match(source, /function stopNavigationPolling/);
  assert.match(source, /function startNavigationPolling/);
  assert.match(source, /function handleVisibilityChange/);
  assert.match(source, /document\.addEventListener\("visibilitychange", handleVisibilityChange\)/);
  assert.match(source, /if \(document\.hidden \|\| navigationRequestBusy/);
  assert.match(source, /stopFileSecurityPolling\(\)/);
});

test("keeps network identity enrichment local and deterministic", () => {
  assert.match(source, /function identityColor/);
  assert.match(source, /function identityInitial/);
assert.match(source, /function networkIdentityMark/);
assert.match(source, /palette = kind === "application"/);
assert.match(source, /icon\(glyph\)/);
assert.match(source, /assets\/network-icons\/\$\{localIcon\}\.svg/);
assert.match(source, /function localNetworkIcon/);
assert.doesNotMatch(source, /https?:\/\/.*(?:favicon|icon)/i);
assert.match(source, /get_network_activity", \{sinceSequence:/);
assert.doesNotMatch(source, /get_network_activity", \{since_sequence:/);
  assert.doesNotMatch(source, /favicon|fetch\(|XMLHttpRequest|DESTINATION_LOGOS/);
});

test("shows a locally resolved endpoint-country flag or neutral fallback", () => {
  assert.match(source, /country_code/);
  assert.doesNotMatch(source, /networkCountrySuffixes|networkKnownDomainCountries|networkKnownIpCountries/);
  assert.match(source, /function networkCountrySignal/);
  assert.match(source, /function networkCountryFlag/);
  assert.match(source, /networkCountryFlag\(destination\)/);
  assert.match(source, /networkDestinationIdentity\(destination\)/);
  assert.match(source, /role="img" aria-label="\$\{esc\(label\)\}" title="\$\{esc\(label\)\}"/);
  assert.match(i18nSource, /network\.activity\.country\.inferred/);
  assert.match(i18nSource, /network\.activity\.country\.conflict/);
  assert.match(i18nSource, /network\.activity\.country\.unknown/);
  assert.match(styles, /\.network-country-flag/);
  assert.match(source, /function networkCountryFlagSvg/);
  assert.match(styles, /\.network-country-flag-art/);
});

test("uses only backend country metadata and never treats a domain suffix as location", () => {
  const start = source.indexOf("function networkCountrySignal");
  const end = source.indexOf("function networkActivityMeta");
  assert.ok(start >= 0 && end > start, "country resolver block is present");
  const context = {
    copy: (key, values = {}) => key.endsWith("country.inferred") ? `Endpoint country: ${values.country}` : key.endsWith("country.domainHint") ? `Domain hint: ${values.country}` : key.endsWith("country.conflict") ? `Conflict: ${values.country}` : key.includes("country.confidence") ? "low confidence" : "Endpoint country unavailable locally",
    esc: (value) => String(value),
    icon: () => "<svg></svg>",
    i18n: {locale: "en"},
  };
  context.globalThis = context;
  vm.runInNewContext(`${source.slice(start, end)}; globalThis.countrySignal = networkCountrySignal; globalThis.countryFlag = networkCountryFlag;`, context);
  assert.equal(context.countrySignal({host: "updates.example.fr", country_code: "FR"}).code, "FR");
  assert.equal(context.countrySignal({host: "updates.example.fr"}).code, "");
  assert.equal(context.countrySignal({host: "cdn.example.co.uk", country_code: "GB"}).code, "GB");
  assert.equal(context.countrySignal({host: "dl.flathub.org", ip: "9.9.9.9"}).code, "");
  assert.equal(context.countrySignal({host: "192.168.1.8", ip: "192.168.1.8"}).code, "");
  assert.equal(context.countrySignal({host: "service.example.com"}).code, "");
  assert.match(context.countryFlag({host: "service.example.de", country_code: "DE"}), /data-country="DE"/);
  assert.match(context.countryFlag({host: "9.9.9.9", country_code: "CH"}), /data-country="CH"/);
  assert.match(context.countryFlag({host: "9.9.9.9", country_code: "CH", country_confidence: "LOW", country_converged: false}), /Conflict: Switzerland/);
  const suffixHint = context.countryFlag({host: "updates.example.fr", country_code: "FR", country_source: "DOMAIN_SUFFIX", country_confidence: "VERY_LOW"});
  assert.match(suffixHint, /data-country="FR"/);
  assert.match(suffixHint, /Domain hint: France/);
  assert.doesNotMatch(suffixHint, /data-country-confidence/);
  assert.doesNotMatch(context.countryFlag({host: "9.9.9.9"}), /data-country="CH"/);
  assert.match(context.countryFlag({host: "192.168.1.8"}), /network-country-flag-unknown/);
  assert.match(context.countryFlag("192.168.1.8"), /data-country="UN"/);
});

test("renders the country marker on every network observation row", () => {
  const start = source.indexOf("function networkActivityDestination");
  const end = source.indexOf("function networkActivityRowsMarkup");
  assert.ok(start >= 0 && end > start, "network activity row block is present");
  const context = {
    app: {},
    copy: (key, values = {}) => key === "network.activity.country.inferred" ? `Domain country: ${values.country}` : key,
    esc: (value) => String(value),
    icon: (name) => name === "globe" ? "<svg data-icon=globe></svg>" : "<svg></svg>",
    localizedTime: (value) => value || "unknown",
    networkActivityState: {expanded: new Set(), mutationAvailable: false},
    networkIdentityMark: () => "<span data-identity></span>",
  };
  context.globalThis = context;
  vm.runInNewContext(`${source.slice(start, end)}; globalThis.renderRow = networkActivityRowMarkup;`, context);
  const inferred = context.renderRow({
    event_id: "fr-event",
    application: "curl",
    destination: {host: "mirror.example.fr", ip: "203.0.113.10", port: 443, country_code: "FR", country_confidence: "LOW", country_converged: false},
    decision: "ALLOWED",
    protocol: "HTTPS",
    occurred_at: "2026-08-31T05:00:00Z",
  });
  const fallback = context.renderRow({
    event_id: "ip-event",
    application: "curl",
    destination: {host: "203.0.113.10", ip: "203.0.113.10", port: 443},
    decision: "ALLOWED",
    protocol: "HTTPS",
    occurred_at: "2026-08-31T05:00:00Z",
  });
  assert.match(inferred, /data-country="FR"/);
  assert.match(fallback, /network-country-flag-unknown/);
  assert.match(fallback, /data-country="UN"/);
});

test("loads a broad local icon catalog before rendering network activity", () => {
  assert.match(index, /assets\/network-icons\/catalog\.js/);
  assert.match(index, /assets\/network-icons\/catalog\.js[\s\S]*app\.js/);
  assert.match(source, /GREYWARD_NETWORK_ICON_CATALOG/);
  assert.match(iconCatalog, /Simple Icons 16\.28\.0/);
  assert.match(iconCatalog, /"firefox":"firefox"/);
  assert.match(iconCatalog, /"github":"github"/);
});

test("keeps Network Activity focused on app, destination, and decision", () => {
  assert.match(source, /network-activity-application/);
  assert.match(source, /network-activity-destination/);
  assert.match(source, /network-decision/);
  assert.match(source, /networkActivityMeta/);
  assert.match(source, /protocol/);
  assert.doesNotMatch(source, /throughput|active connections|ASN|geolocation|reputation/i);
});

test("keeps application and destination identities in aligned columns with a legend", () => {
  assert.match(source, /network-activity-application/);
  assert.match(source, /network-activity-destination/);
  assert.match(source, /function networkActivityLegendMarkup/);
  assert.match(source, /networkActivityLegendMarkup\(\)/);
  assert.match(styles, /\.network-activity-row-main,?[^\n]*grid-template-columns/);
  assert.match(styles, /\.network-activity-legend[^\n]*grid-template-columns/);
  assert.match(i18nSource, /network\.activity\.legend\.application/);
  assert.match(i18nSource, /network\.activity\.legend\.destination/);
});

test("does not claim network protection when freshness, DNS, or firewall zone is unavailable", () => {
  assert.match(source, /healthFreshness = String\(opensnitch\.health\?\.freshness/);
  assert.match(source, /healthFreshness === "STALE"/);
  assert.match(source, /opensnitchDegraded = linkState === "DEGRADED"/);
  assert.match(source, /COMPATIBILITYFALLBACK/);
  assert.match(source, /firewallZone = String\(firewalld\.zone/);
  assert.match(source, /NO ZONE REPORTED/);
  assert.match(source, /network\.protection\.detail\.dnsDegraded/);
  assert.match(source, /network\.protection\.capability\.installed/);
  assert.match(source, /capabilities\?\.activity && linkState === "OPERATING"/);
});

test("keeps firewall actions aligned with the authoritative active zone", () => {
  assert.match(source, /zone === "trusted"/);
  assert.match(source, /trustedActive/);
  assert.match(source, /data-zone="public"/);
  assert.match(source, /zone === "public"/);
  assert.match(source, /publicActive/);
  assert.match(source, /await loadPage\("network", \{force: true\}\)/);
});

test("keeps historical activity in the existing page and uses bounded backend queries", () => {
  assert.match(source, /data-activity-mode/);
  assert.match(source, /get_network_history/);
  assert.match(source, /network\.activity\.range\.thirtyMinutes/);
  assert.match(source, /network\.activity\.range\.sevenDays/);
  assert.match(source, /HISTORY_QUERY_DEBOUNCE_MS = 250/);
  assert.match(source, /scheduleNetworkHistoryLoad/);
  assert.match(source, /querySequence !== historyQuerySequence/);
  assert.match(source, /NETWORK_HISTORY_PAGE_SIZE = 120/);
  assert.match(source, /historyCursor/);
  assert.match(source, /network\.activity\.loadOlder/);
  assert.match(source, /data-activity-load-more/);
  assert.doesNotMatch(source, /localStorage|indexedDB/);
});

test("keeps Network Activity pause state and pending count authoritative", () => {
  assert.match(source, /function syncNetworkActivityData\(payload, \{trackPending = false\} = \{\}\)/);
  assert.match(source, /if \(trackPending && networkActivityState\.paused\) networkActivityState\.pending \+= addedCount/);
  assert.match(source, /renderNetworkActivityView\(\{renderRows: !networkActivityState\.paused\}\)/);
  assert.match(source, /syncNetworkActivityControls\(\)/);
  const start = source.indexOf("function syncNetworkActivityData");
  const end = source.indexOf("function renderNetworkActivityView");
  const context = {
    copy: () => "unavailable",
    networkActivityState: {
      sessionId: "session-1",
      nextSequence: 1,
      events: [{event_id: "old", sequence: 1}],
      expanded: new Set(),
      paused: true,
      pending: 0,
    },
  };
  context.globalThis = context;
  vm.runInNewContext(`${source.slice(start, end)}; globalThis.sync = syncNetworkActivityData;`, context);
  const payload = {session_id: "session-1", next_sequence: 3, events: [{event_id: "old", sequence: 1}, {event_id: "new", sequence: 2}], state: "OPERATING", detail: "ok", rule_mutation: "TYPED_POLICY"};
  context.sync(payload, {trackPending: true});
  context.sync(payload, {trackPending: true});
  assert.equal(context.networkActivityState.pending, 1, "duplicate polling results inflated the pending count");
  assert.equal([...context.networkActivityState.events].map((event) => event.event_id).join(","), "new,old");
});

test("keeps Network Activity filters as one model across mode and clear transitions", () => {
  assert.match(source, /const DEFAULT_NETWORK_ACTIVITY_FILTERS = Object\.freeze/);
  assert.match(source, /function networkActivityDefaultFilters\(\)/);
  assert.match(source, /networkActivityState\.filters = networkActivityDefaultFilters\(\)/);
  assert.match(source, /data-activity-toolbar data-activity-mode-state/);
  assert.match(source, /toolbar\.dataset\.activityModeState !== networkActivityState\.mode/);
  assert.match(source, /if \(search && search\.value !== filters\.search\) search\.value = filters\.search/);
  assert.match(source, /if \(windowControl && windowControl\.value !== filters\.window\) windowControl\.value = filters\.window/);
  assert.match(source, /clear\.disabled = networkActivityFiltersAreDefault\(\)/);
  assert.match(source, /networkActivityState\.mode === "history"\) loadNetworkHistory\(\); else renderNetworkActivityView\(\)/);
});

test("matches the Tauri argument names for network rules and history", () => {
  assert.match(source, /const filters = \{from, limit: NETWORK_HISTORY_PAGE_SIZE/);
  assert.match(source, /invokeBounded\("get_network_history", \{filters\}, 12000\)/);
  assert.match(source, /invokeBounded\("network_set_rule", \{payload\}, 15000\)/);
  assert.match(source, /invokeBounded\("network_remove_rule", \{ruleId: button\.dataset\.ruleId\}, 15000\)/);
});

test("refreshes GREYWARD-owned rules from the typed policy service", () => {
  const userBus = readFileSync(new URL("../../security-context/greyward_security_context/user_bus.py", import.meta.url), "utf8");
  const policy = readFileSync(new URL("../../security-context/greyward_security_context/network_policy_service.py", import.meta.url), "utf8");
  assert.match(userBus, /call_blocking\([^\n]+"ListRules","",\(\),timeout=DBUS_CALL_TIMEOUT\)/);
  assert.match(userBus, /def _merge_policy_rules\(value\):/);
  assert.match(userBus, /return _normalize_network_capabilities\(_merge_policy_rules\(value\)\)[\s\S]*def network_activity/);
  assert.match(userBus, /RECENT_POLICY_RULES\[result\["rule_id"\]\]=_recent_policy_rule/);
  assert.match(policy, /def list_rules\(\):/);
  assert.match(policy, /def ListRules\(self\):/);
  const busPolicy = readFileSync(new URL("../../security-context/dbus/systems.mantis.greyward.OpenSnitchPolicy1.conf", import.meta.url), "utf8");
  assert.match(busPolicy, /send_member="ListRules"/);
});

test("uses typed D-Bus values for Security Context JSON instead of gdbus display text", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(rust, /use dbus::blocking::Connection;/);
  assert.match(rust, /fn security_context_json_call<A>/);
  assert.match(rust, /Connection::new_session\(\)/);
  assert.match(rust, /let member = method\s+\.rsplit\('\.'\)/);
  assert.match(rust, /\.method_call\(SECURITY_CONTEXT_BUS_NAME, member, arguments\)/);
  assert.match(rust, /security_context_json_call\(method, \(path,\)\)/);
  assert.match(rust, /security_context_json_call\(method, \(payload,\)\)/);
  assert.doesNotMatch(rust.slice(rust.indexOf("fn security_context_string_method"), rust.indexOf("fn session_gdbus_call")), /strip_prefix\("\('\"\)/);
});

test("packages deliberate Security Center deep-link destinations", () => {
  const route = readFileSync(new URL("../../data/greyward-security-center-route", import.meta.url), "utf8");
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(route, /overview\|system\|network\|privacy\|updates\|files\|applications\|devices\|evidence\|activity/);
  assert.match(route, /threats\)/);
  assert.match(route, /\[\[ -n "\$event_id" && ! "\$event_id"/);
  assert.match(route, /\[\[ "\$page" == "threats" && -n "\$event_id" \]\]/);
  assert.match(route, /exit 64/);
  assert.match(rust, /const SECURITY_CENTER_ROUTES: &\[&str\]/);
  assert.match(rust, /SECURITY_CENTER_ROUTES\.contains\(&value\.as_str\(\)\)/);
  assert.match(rust, /app\.emit\("security-navigation", &value\)/);
});

test("keeps live and historical observations dense while retaining identity cues", () => {
  assert.match(styles, /\.network-activity-row \{ min-height: 0; \}/);
  assert.match(styles, /\.network-activity-row-main \{ min-height: 52px; padding: 8px 12px/);
  assert.match(styles, /\.network-activity-details\[hidden\] \{ display: none !important; \}/);
  assert.match(styles, /\.network-activity-identity \.network-identity-logo \{ width: 28px; height: 28px/);
  assert.match(styles, /\.network-activity-row strong \{ font-size: 14px; \}/);
});

test("keeps primary navigation labels on one line with readable sizing", () => {
  assert.match(styles, /\.nav-item \{ min-height: 46px; grid-template-columns: 24px minmax\(0, 1fr\);/);
  assert.match(styles, /\.nav-item > span:last-child \{ min-width: 0; white-space: nowrap; font-size: 15\.5px; \}/);
});

test("keeps device history behind backend projections and keeps overview on its fast local path", () => {
  assert.match(source, /device_history/);
  assert.match(source, /devices\.history\.newUnknown/);
  assert.match(source, /network\.activity\.historyUnavailable/);
  assert.match(source, /page === "overview"[\s\S]*invokeBounded\("get_overview"/);
  assert.doesNotMatch(source, /Promise\.all\(\[\s*invokeBounded\("get_overview"/);
});

test("shares a short-lived authoritative core snapshot across read-only pages", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(rust, /CORE_SNAPSHOT_CACHE_TTL: Duration = Duration::from_secs\(3\)/);
  assert.match(rust, /fn core_collection_for_read\(\)/);
  assert.match(rust, /fn invalidate_core_snapshot_cache\(\)/);
  assert.match(rust, /fn get_overview\(\)[\s\S]*core_collection_for_read\(\)/);
  assert.match(rust, /fn get_evidence\(\)[\s\S]*core_collection_for_read\(\)/);
  assert.match(rust, /fn get_devices\(\)[\s\S]*collect_device_snapshot\(\)/);
  assert.match(rust, /fn emit_state_changed\([\s\S]*invalidate_core_snapshot_cache\(\)/);
});

test("bypasses presentation caches after mutable security actions", () => {
  assert.match(source, /await loadPage\("network", \{force: true\}\)/);
  assert.match(source, /await loadPage\("privacy", \{force: true\}\)/);
  assert.match(source, /await loadPage\("files", \{force: true\}\)/);
  assert.match(source, /pageCache\.delete\("updates"\); await loadPage\("updates"\)/);
  assert.match(source, /pageCache\.delete\("devices"\)/);
  assert.match(source, /getPageData\(page\)[\s\S]*`get_\$\{page\}`/);
  assert.doesNotMatch(source, /const APPLICATION_PERMISSION_CACHE/);
});

test("keeps cold provider reads page-specific and Flatpak inspection bounded", () => {
  const adapters = readFileSync(new URL("../../crates/greyward-security-backends/src/adapters.rs", import.meta.url), "utf8");
  assert.match(adapters, /pub fn collect_device_facts\(\)/);
  assert.match(adapters, /pub fn collect_flatpak_facts\(\)[\s\S]*thread::scope/);
  assert.match(adapters, /descriptors\.chunks\(4\)/);
  assert.match(adapters, /flatpak_permissions\(&app_id, scope_flag\.as_str\(\)\)/);
  assert.match(adapters, /flatpak_overrides\(&app_id, scope_flag\.as_str\(\)\)/);
  assert.match(adapters, /pub fn collect_portal_facts\(\)[\s\S]*thread::scope/);
});

test("reuses fresh page data for navigation while refreshes still query the current state", () => {
  assert.match(source, /const PAGE_CACHE_TTL_MS = 5000/);
  assert.match(source, /const PAGE_CACHE_REUSE_ROUTES = new Set\(\["overview", "evidence"\]\)/);
  assert.match(source, /const pageDataRequests = new Map\(\)/);
  assert.match(source, /const existing = pageDataRequests\.get\(key\)/);
  assert.match(source, /request\.finally\(\(\) =>/);
  assert.match(source, /const initialCachedData = cachedData/);
  assert.doesNotMatch(source, /relatedCachedData/);
  assert.match(source, /const canReuseCachedPage = options\.force !== true && PAGE_CACHE_REUSE_ROUTES\.has\(currentPage\)/);
  assert.match(source, /if \(canReuseCachedPage\) return/);
  assert.match(source, /pageCache\.set\(currentPage, \{data, loadedAt: Date\.now\(\)\}\)/);
  assert.match(source, /if \(canReuseCachedPage && preserveScroll\)/);
});

test("keeps update polling mounted and avoids full-shell reloads", () => {
  assert.match(source, /async function refreshUpdates\(\)/);
  assert.match(source, /invokeBounded\("get_updates", undefined, 12000\)/);
  assert.match(source, /frame\.innerHTML = renderContent\("updates", data\)/);
  assert.match(source, /startUpdatePolling\(\)/);
  assert.doesNotMatch(source, /setInterval\(\(\) => loadPage\("updates"\), 1500\)/);
});

test("does not show a review list when no updates are ready", () => {
  assert.match(source, /const availableSection = available\.length/);
  assert.match(source, /\n    : "";/);
  assert.doesNotMatch(source, /No updates ready/);
  assert.doesNotMatch(source, /Changes to review/);
});

test("keeps technical evidence and provider detail behind disclosure", () => {
  assert.match(source, /<details class="evidence-group">/);
  assert.match(source, /function technicalDisclosure/);
  assert.match(source, /technicalDisclosure\(copy\("updates\.sources\.title"\)/);
});

test("counts only actionable evidence findings and treats unknown as attention", () => {
  assert.match(source, /\["REVIEW NEEDED", "ACTION REQUIRED", "UNAVAILABLE", "UNKNOWN"\]/);
  assert.match(source, /row\.accepted_deviation !== true/);
  assert.match(source, /const protectedCount = rows\.filter/);
});

test("gives system checks an explicit resolution workflow", () => {
  assert.match(i18nSource, /system\.protection\": \"System updates & checks/);
  assert.doesNotMatch(source, /class="evidence-workflow"/);
  assert.match(source, /function evidenceNextStep/);
  assert.match(source, /const remediation = row\?\.remediation/);
  assert.match(source, /copy\(remediation\.action_key, evidenceValues\(row\)\)/);
  assert.doesNotMatch(source, /const routes = \{/);
  assert.match(source, /class="evidence-resolution-card/);
  assert.match(source, /data-deviation-id="recovery\.readiness"/);
  assert.match(source, /function recoveryDeviationAction/);
});

test("lets users ignore unavailable recommendations and refreshes posture", () => {
  assert.match(source, /\["REVIEW NEEDED", "ACTION REQUIRED", "UNAVAILABLE"\]/);
  assert.match(source, /evidence\.deviation\.ignore/);
  assert.match(source, /invokeBounded\("set_deviation", \{checkId: button\.dataset\.deviationId, accepted\}/);
  assert.match(source, /pageCache\.set\("overview", \{data: updatedOverview/);
  assert.match(source, /pageCache\.delete\("evidence"\)/);
  assert.match(source, /setDeviationFeedback\(workingCopy\)/);
  assert.match(source, /const deviationState = \{feedback: ""\}/);
});

test("does not present unavailable posture as if nothing needs attention", () => {
  assert.match(source, /posture\.state === "UNAVAILABLE"/);
  assert.match(source, /overview\.unavailable\.title/);
  assert.match(i18nSource, /overview\.unavailable\.title/);
});

test("keeps optional unavailable evidence visible without downgrading protected posture", () => {
  assert.match(source, /const limited = Number\(overview\.metrics\?\.unavailable/);
  assert.match(source, /overview\.limited\.title/);
  assert.match(i18nSource, /overview\.posture\.limited\.message/);
});

test("keeps Update Center responsive while provider data refreshes", () => {
  assert.match(source, /snapshot_refreshing === true/);
  assert.match(source, /updates\.message\.reading/);
  assert.match(source, /presentation\.progressKey/);
  assert.doesNotMatch(source, /transaction\.current_item \|\| "Applying/);
  assert.match(source, /pageCache\.delete\("updates"\)/);
  assert.match(source, /presentation\.transactionActive && transaction\.current_item/);
  assert.match(source, /transaction\.error/);
  assert.match(source, /updates\.diagnostic\.title/);
});

test("gives current availability precedence over historical completion", () => {
  const start = source.indexOf("const UPDATE_ACTIVE_PHASES");
  const end = source.indexOf("function updateHistoryResultKey");
  assert.ok(start >= 0 && end > start, "Updates presentation model is present");
  const context = {UPDATE_PAGE_SIZE: 100};
  context.globalThis = context;
  vm.runInNewContext(`${source.slice(start, end)}; globalThis.present = updatePresentation;`, context);
  const available = context.present({
    transaction: {phase: "COMPLETE", progress: 100},
    records: [{id: "system.dnf5.kernel.x86_64", update_available: true}],
    providers: {DNF5: {state: "AVAILABLE"}},
  });
  assert.equal(available.state, "AVAILABLE");
  assert.equal(available.action, "apply");
  assert.equal(available.progress, false);
  const complete = context.present({
    transaction: {phase: "COMPLETE", progress: 100},
    records: [{id: "system.dnf5", update_available: false}],
    providers: {DNF5: {state: "AVAILABLE"}},
  });
  assert.equal(complete.state, "COMPLETE");
  assert.equal(complete.progress, false);
});

test("exposes the same Apply-all action when only an optional provider has updates", () => {
  const start = source.indexOf("const UPDATE_ACTIVE_PHASES");
  const end = source.indexOf("function updateHistoryResultKey");
  const context = {UPDATE_PAGE_SIZE: 100};
  context.globalThis = context;
  vm.runInNewContext(`${source.slice(start, end)}; globalThis.present = updatePresentation;`, context);
  const available = context.present({
    transaction: {phase: "COMPLETE"},
    records: [{id: "application.flatpak.user.org.example.App", category: "application", update_available: true}],
    providers: {DNF5: {state: "AVAILABLE"}, Flatpak: {state: "AVAILABLE"}},
  });
  assert.equal(available.state, "AVAILABLE");
  assert.equal(available.action, "apply");
});

test("keeps one phase mapping for busy, terminal, and provider-degraded states", () => {
  const start = source.indexOf("const UPDATE_ACTIVE_PHASES");
  const end = source.indexOf("function updateHistoryResultKey");
  const context = {UPDATE_PAGE_SIZE: 100};
  context.globalThis = context;
  vm.runInNewContext(`${source.slice(start, end)}; globalThis.present = updatePresentation;`, context);
  const resolving = context.present({transaction: {phase: "RESOLVING", progress: 42}, records: [], providers: {DNF5: {state: "AVAILABLE"}}});
  assert.equal(resolving.state, "RESOLVING");
  assert.equal(resolving.progress, true);
  assert.equal(resolving.progressKey, "updates.phase.resolving");
  const degraded = context.present({transaction: {phase: "IDLE"}, records: [], providers: {DNF5: {state: "DEGRADED"}, Flatpak: {state: "AVAILABLE"}}});
  assert.equal(degraded.state, "DEGRADED");
  assert.equal(degraded.availableCount, 0);
  const unavailable = context.present({transaction: {phase: "IDLE"}, records: [], providers: {DNF5: {state: "UNAVAILABLE"}}});
  assert.equal(unavailable.state, "UNAVAILABLE");
  assert.equal(unavailable.progress, false);
  const retryRestart = context.present({transaction: {phase: "FAILED", restart_required: "REQUIRED", error: "The system did not restart."}, records: [], providers: {DNF5: {state: "AVAILABLE"}}});
  assert.equal(retryRestart.state, "FAILED");
  assert.equal(retryRestart.action, "restart");
});

test("surfaces provider failures recorded by a completed UpdateAll transaction", () => {
  const start = source.indexOf("const UPDATE_ACTIVE_PHASES");
  const end = source.indexOf("function updateHistoryResultKey");
  const context = {UPDATE_PAGE_SIZE: 100};
  context.globalThis = context;
  vm.runInNewContext(`${source.slice(start, end)}; globalThis.present = updatePresentation;`, context);
  const degraded = context.present({
    transaction: {phase: "COMPLETE", provider_results: [{provider: "fwupd", state: "DEGRADED", reason: "Firmware update failed."}]},
    records: [],
    providers: {DNF5: {state: "AVAILABLE"}},
  });
  assert.equal(degraded.state, "DEGRADED");
  assert.match(source, /transaction\.provider_results/);
  assert.match(source, /last operation/);
});

test("renders update history as an identified version/result record", () => {
  assert.match(source, /data-update-history-row/);
  assert.match(source, /item\.name \|\| item\.identity/);
  assert.match(source, /updateHistoryVersionLine\(item\)/);
  assert.match(source, /updateHistoryResultKey\(item\.result\)/);
  assert.match(source, /updates\.history\.versionsUnavailable/);
  assert.match(source, /updates\.history\.result\.unknown/);
});

test("uses explicit accessible feedback for file and DNS operations", () => {
  assert.match(source, /copy\("network\.dns\.saving"\)/);
  assert.match(i18nSource, /network\.dns\.saving/);
  assert.match(source, /copy\("file\.feedback\.openingCopy"\)/);
  assert.match(source, /id="safe-open-status" class="action-status" role="status" aria-live="polite"/);
});

test("keeps File Security focused on scan, detection, and remediation", () => {
  assert.match(source, /data-file-scan-file/);
  assert.match(source, /data-file-scan-folder/);
  assert.match(source, /data-file-scan-system/);
  assert.match(source, /file\.detections\.eyebrow/);
  assert.match(source, /data-file-quarantine/);
  assert.match(source, /data-file-restore/);
  assert.match(source, /data-file-delete/);
  assert.match(source, /file\.protection\.readyCopy/);
  assert.doesNotMatch(source, /data-file-ignore|Ignore threat/i);
});

test("keeps a durable, state-specific last scan result with its measured scope", () => {
  assert.match(source, /file\.operation\.lastEyebrow/);
  assert.match(source, /operation\.scope\?\.label/);
  assert.match(source, /operation\.ended_at \|\| operation\.started_at/);
  assert.match(source, /state === "PARTIAL"/);
  assert.match(source, /state === "CANCELLED"/);
  assert.match(source, /state === "INTERRUPTED"/);
  assert.match(source, /file\.operation\.partialCopy/);
  assert.match(source, /file\.operation\.cancelledCopy/);
  assert.match(source, /file\.operation\.failedCopy/);
  assert.match(source, /PARTIAL: "state\.partial"/);
});

test("keeps File Security action feedback visible as well as announced", () => {
  assert.match(source, /const fileSecurityState = \{operationId: null, polling: null, pollDelayMs: 900, requestBusy: false, feedback: ""\}/);
  assert.match(source, /id="file-security-action-status" class="action-status" role="status" aria-live="polite"/);
  assert.match(source, /function setFileSecurityFeedback\(message\)/);
  assert.match(source, /file\.feedback\.restored/);
  assert.match(source, /result\?\.staging_path \|\| result\?\.restore_staging_path/);
});

test("renders File Security safely while the local status is still loading", () => {
  assert.match(source, /currentPage === "files"\s*\?\s*filesMarkup\(\{loading: true/);
  assert.match(source, /const scanAvailable = !loading/);
  assert.match(source, /file\.protection\.unavailable/);
  assert.match(source, /file\.protection\.checkingCopy/);
  assert.match(source, /A broken optional control must not strand the whole page/);
});

test("polls file scans by operation without replacing the whole page", () => {
  assert.match(source, /get_file_security_scan_status/);
  assert.match(source, /file-security-operation/);
  assert.match(source, /operation\.innerHTML = fileSecurityOperationMarkup\(result\)/);
  assert.doesNotMatch(source, /setInterval\(\(\) => loadPage\("files"\)/);
  assert.match(source, /pollDelayMs = Math\.min\(fileSecurityState\.pollDelayMs \+ 500, 3000\)/);
  assert.match(source, /scheduleFileSecurityPolling\(\)/);
});

test("preserves scroll position when the current page is refreshed", () => {
  assert.match(source, /const destination = normalizePage\(page\)/);
  assert.match(source, /const preserveScroll = destination === currentPage/);
  assert.match(source, /let scrollPosition = preserveScroll \? readPageScrollPosition\(\) : null/);
  assert.match(source, /function readPageScrollPosition\(\)/);
  assert.match(source, /function applyPageScroll\(position\)/);
  assert.match(source, /applyPageScroll\(scrollPosition\)/);
});

test("refreshes the mounted view in place instead of showing a loading shell", () => {
  assert.match(source, /const refreshInPlace = preserveScroll && Boolean\(app\.querySelector\("\.app-shell \.content-frame"\)\)/);
  assert.match(source, /if \(refreshInPlace\) \{\s+setRefreshBusy\(true\);/);
  assert.match(source, /app\.querySelector\("\.content-frame"\)\.innerHTML = renderContent\(currentPage, data\)/);
  assert.match(source, /function setRefreshBusy\(busy\)/);
  assert.match(source, /function bindContent\(\)/);
});

test("keeps Recovery V1 results durable, bounded, and separate from integrity verification", () => {
  assert.match(source, /backup\.status\.completed/);
  assert.match(source, /data-backup-now/);
  assert.match(source, /data-backup-verify/);
  assert.match(source, /backup\.retention\.daily/);
  assert.match(source, /data-recovery-create/);
  assert.match(source, /backup\.configure\.setup/);
  assert.match(source, /backup\.panel\.notConfigured/);
  assert.match(source, /backup\.configure\.choose/);
  assert.doesNotMatch(source, /local GREYWARD default/);
  assert.match(source, /recovery-operation-queue/);
  assert.match(source, /recovery-operation-progress/);
  assert.match(source, /backup\.operation/);
  assert.match(source, /syncRestoreSelectionLimit/);
  assert.match(source, /restore_selection_limit|selection_limit/);
  assert.doesNotMatch(source, /recoveryOperationState|setRecoveryOperationState/);
  assert.match(source, /state === "FAILED"/);
  assert.match(source, /backup\.recovery\.copy/);
});

test("keeps recovery operation wording aligned with terminal state", () => {
  assert.match(source, /operationState === "COMPLETED"/);
  assert.match(source, /backup\.operation\.completed/);
  assert.match(source, /operationState === "PREPARING" \|\| operationState === "QUEUED"/);
  assert.match(source, /backup\.operation\.preparing/);
  assert.match(source, /backup\.operation\.active/);
});

test("labels restore candidates and clears the picker after success", () => {
  assert.match(source, /result\?\.candidates/);
  assert.match(source, /backup\.restore\.directory/);
  assert.match(source, /backup\.restore\.file/);
  assert.match(source, /function resetRestorePicker\(\)/);
  assert.match(source, /resetRestorePicker\(\); setStatus\("#backup-action-status"/);
  assert.match(source, /replaceChildren\(\)/);
});

test("uses typed effective application access and keeps raw grants behind disclosure", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  const backend = readFileSync(new URL("../../crates/greyward-security-backends/src/facts.rs", import.meta.url), "utf8");
  assert.match(rust, /fn normalize_application_access/);
  assert.match(rust, /resolve_flatpak_access/);
  assert.match(rust, /access_categories/);
  assert.match(rust, /review_needed_count/);
  assert.match(rust, /inventory_state/);
  assert.match(backend, /pub struct EffectiveFlatpakAccess/);
  assert.match(backend, /filesystems/);
  assert.match(backend, /support the `!permission` form/);
  assert.match(source, /applications\.inventory\.count/);
  assert.match(source, /applications\.inventory\.partialCount/);
  assert.match(source, /applications\.access\.unavailable/);
  assert.match(rust, /applications\.status\.isolation/);
  assert.match(rust, /applications\.status\.integration/);
  assert.match(source, /item\.technical/);
  assert.doesNotMatch(source, /access_summary|broad_access|home_filesystem/);
});

test("keeps evidence product-first and moves implementation references into a technical record", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(rust, /pub struct EvidenceTechnicalDetails/);
  assert.match(rust, /recorded_result/);
  assert.match(rust, /recommendation/);
  assert.match(source, /system\.checks\.technicalRecord/);
  assert.match(source, /technical\.reference/);
  assert.doesNotMatch(source, /<code>\$\{esc\(row\.check_id\)\}<\/code>/);
});

test("uses the DMS localization mechanism and product-safe privacy feedback", () => {
  const widget = readFileSync(new URL("../../../environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml", import.meta.url), "utf8");
  assert.match(widget, /qsTr\("Status unavailable"\)/);
  assert.match(widget, /qsTr\("Privacy profile applied"\)/);
  assert.match(widget, /qsTr\("Privacy profile could not be applied"\)/);
  assert.doesNotMatch(widget, /actionMessage = result && result\.ok \? .*result\?\.detail/);
});

test("keeps Privacy profile transitions authoritative and single-flight", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  const helper = readFileSync(new URL("../../crates/greyward-security-backends/src/bin/greyward-security-profile.rs", import.meta.url), "utf8");
  assert.match(source, /const privacyState = \{feedback: "", (?:exportPath: "", )?profilePending: null/);
  assert.match(source, /data-privacy-profile-state/);
  assert.match(source, /if \(privacyState\.profilePending \|\| !\["STANDARD", "PRIVATE", "TRAVEL"\]/);
  assert.match(source, /result\?\.ok !== true \|\| confirmed !== target/);
  assert.match(source, /loadPage\("privacy", \{force: true\}\)/);
  assert.match(source, /pageCache\.delete\("privacy"\)/);
  assert.match(source, /data-profile-pending/);
  assert.match(rust, /pub profile: Option<String>/);
  assert.match(rust, /confirmed_profile\.as_deref\(\) == Some\(target\.as_str\(\)\)/);
  assert.match(helper, /fn failed_state_payload/);
  assert.match(helper, /payload\["effective_state"\]/);
});

test("keeps Privacy export destination feedback visible and failure-safe", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(source, /privacy\.local\.exported/);
  assert.match(source, /const path = String\(result\.path \|\| ""\)\.trim\(\)/);
  assert.match(source, /The export completed without a returned destination/);
  assert.match(source, /privacyState\.feedback = privacyActionError/);
  assert.doesNotMatch(source, /window\.setTimeout\(\(\) => loadPage\("privacy"\)/);
  assert.match(rust, /pub path: Option<String>/);
  assert.match(rust, /path: Some\(path\.to_string_lossy\(\)\.into_owned\(\)\)/);
});

test("keeps a confirmed DMS snapshot visible only while its replacement read is in flight", () => {
  const widget = readFileSync(new URL("../../../environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml", import.meta.url), "utf8");
  assert.match(widget, /items: showingSnapshot \? presentation.items/);
  assert.match(widget, /activities: showingSnapshot \? presentation.activity/);
  assert.match(widget, /readonly property bool fresh: freshnessLeaseValid/);
  assert.match(widget, /readonly property bool showingSnapshot: fresh \|\| requestPending/);
  assert.match(widget, /Date.parse\(presentation.fresh_until/);
  assert.match(widget, /Current security status cannot be confirmed/);
  assert.match(widget, /const nextFreshUntil = Date.parse\(next\.fresh_until \|\| ""\)/);
  assert.match(widget, /initialized = Number\.isFinite\(nextFreshUntil\)/);
  assert.match(widget, /Reading security status/);
});

test("uses the native DMS subscription for live privacy capsule changes", () => {
  const widget = readFileSync(new URL("../../../environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml", import.meta.url), "utf8");
  assert.match(widget, /dbusSubscribe\("session", busName, objectPath, busName, "ShellSummaryChanged"/);
  assert.match(widget, /call\("GetShellPresentation"/);
  assert.match(widget, /onDbusSignalReceived/);
  assert.match(widget, /previousIds/);
  assert.match(widget, /interval: 10000; onTriggered: root.attentionId = ""/);
  assert.match(widget, /duration: root.reducedMotion \? 0 : 200/);
  assert.match(widget, /greyward-security-status/);
  assert.match(widget, /liveIcons.slice\(0,2\)/);
  assert.match(widget, /Layout.minimumHeight: 34/);
  assert.match(widget, /capsuleWatchdogIntervalMs: 15000/);
  assert.match(widget, /readonly property bool freshnessLeaseValid/);
  assert.match(widget, /readonly property bool fresh: freshnessLeaseValid/);
  assert.match(widget, /readonly property bool showingSnapshot: fresh \|\| requestPending/);
  assert.match(widget, /if \(!freshnessLeaseValid \|\| actionPending\) return;/);
  assert.doesNotMatch(widget, /gdbus monitor|notify-send/);
});

test("cleans up local request timers and bounds Security Context D-Bus calls", () => {
  assert.match(source, /function invokeBounded/);
  assert.match(source, /window\.clearTimeout\(timeout\)/);
  assert.doesNotMatch(source, /Promise\.race\(\[/);
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(rust, /fn update_center_dbus_method\(method: &str\)/);
  assert.match(rust, /org\.greyward\.Update1/);
  assert.match(rust, /SECURITY_CONTEXT_CALL_TIMEOUT/);
  assert.match(rust, /const FAST_HELPER_TIMEOUT_SECONDS: u64 = 20/);
  assert.match(rust, /Command::new\("\/usr\/bin\/timeout"\)/);
  assert.match(rust, /output\.status\.code\(\) == Some\(124\)/);
  const widget = readFileSync(new URL("../../../environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml", import.meta.url), "utf8");
  assert.match(widget, /requestGeneration/);
  assert.match(widget, /requestTimeout/);
  assert.match(widget, /"--timeout", "6"/);
});

test("keeps update cancellation and package labels truthful", () => {
  const updates = readFileSync(new URL("../../security-context/greyward_security_context/update_center_bus.py", import.meta.url), "utf8");
  assert.match(updates, /"cancellable": False/);
  assert.match(updates, /def package_progress_label\(nevra\)/);
  assert.match(updates, /return f"Updating \{name\}\."/);
  assert.match(updates, /if current\.get\("cancellable"\) is not True:/);
  assert.match(source, /transaction\.cancellable === true/);
});

test("makes wrong Restic passphrases actionable without exposing them", () => {
  assert.match(source, /copy\("feedback\.passphrase"/);
  assert.match(source, /message\.includes\("wrong password"\)/);
  assert.doesNotMatch(source, /password.*console\.(log|warn|error)/i);
});

test("explains missing Polkit authorization for privileged recovery actions", () => {
  assert.match(source, /authentication agent/);
  assert.match(source, /create_recovery_point/);
  assert.match(source, /controlling terminal/);
  assert.match(source, /feedback\.authorizationSession/);
});

test("primary navigation retains its selected parent for contextual destinations", () => {
  const context = {primaryNav: [["system", "System", "shield"], ["network", "Network", "network"]], pageParents: {files: "system", activity: "network"}, normalizePage: (page) => page === "system" ? "evidence" : page, currentPage: "files", esc: String, t: String, icon: () => ""};
  vm.runInNewContext(source.slice(source.indexOf("function primaryNavMarkup("), source.indexOf("function shell(")), context);
  for (const [page, parent] of [["files", "system"], ["evidence", "system"], ["activity", "network"]]) {
    context.currentPage = page;
    const html = context.primaryNavMarkup();
    const selected = html.match(/<button[^>]*class="nav-item active"[^>]*>/g);
    assert.equal(selected.length, 1);
    assert.ok(selected[0].includes(`data-page="${parent}"`));
    assert.match(selected[0], /aria-label=/);
  }
});

test("recovery queue shows real pending work without inventing an idle checklist", () => {
  const context = {copy: String, esc: String, status: String, backupProblemCopy: String, recoveryOperationLabels: {backup_now: ["Backup", "Copy"], verify_backup: ["Verify", "Check"]}};
  vm.runInNewContext(source.slice(source.indexOf("function recoveryQueueItem("), source.indexOf("function recoveryMarkup(")), context);
  assert.equal(context.recoveryQueueMarkup({}), "");
  assert.equal(context.recoveryQueueMarkup({backup: {operation: {kind: "BACKUP", state: "COMPLETED"}}}), "");
  for (const state of ["QUEUED", "PREPARING", "RUNNING"]) {
    const html = context.recoveryQueueMarkup({backup: {operation: {kind: "BACKUP", state}}});
    assert.equal((html.match(/<article/g) || []).length, 1);
    assert.match(html, /role="progressbar"/);
    assert.ok(html.includes(state));
  }
});

test("file review preserves unresolved actions while collapsing deleted history", () => {
  const context = {copy: String, esc: String, icon: () => "", status: String, localizedTime: String, pageHeader: () => "", actionButton: (a,b,c,attrs) => `<button ${attrs}>${a}</button>`, emptyState: (a) => a, technicalDisclosure: (title,count,body) => `<details><summary>${title}</summary>${body}</details>`, fileSecurityState: {feedback: ""}, fileSecurityOperationMarkup: () => "ACTIVE_SCAN", activityMarkup: () => ""};
  vm.runInNewContext(source.slice(source.indexOf("function filesMarkup("), source.indexOf("function privacyMarkup(")), context);
  const data = {state: "AVAILABLE", clamav: {status: "CURRENT", engine_version: "1"}, detections: [{state: "DELETED", detection_name: "Old deleted", detection_id: "old"}, {state: "DETECTED", detection_name: "Unresolved", detection_id: "pending"}, {state: "QUARANTINED", detection_name: "Contained", detection_id: "contained"}]};
  const html = context.filesMarkup(data);
  assert.ok(html.indexOf("Unresolved") < html.indexOf("Old deleted"));
  assert.match(html, /<details><summary>design.files.resolved<\/summary>[\s\S]*Old deleted/);
  assert.match(html, /data-file-quarantine="pending"/);
  assert.match(html, /data-file-restore="contained"/);
  assert.match(html, /data-file-delete="contained"/);
  const active = context.filesMarkup({...data, active_scan: {state: "RUNNING"}});
  assert.ok(active.indexOf("ACTIVE_SCAN") < active.indexOf("Unresolved"));
  assert.equal((active.match(/id="file-security-action-status"/g) || []).length, 1);
  const unavailable = context.filesMarkup({state: "UNAVAILABLE"});
  assert.match(unavailable, /disabled aria-disabled="true" data-file-scan-file/);
});

test("busy buttons keep their original label through repeated refresh requests", () => {
  const context = {};
  const start = source.indexOf("function beginButton(");
  vm.runInNewContext(source.slice(start, source.indexOf("async function probeNetwork(", start)), context);
  const classes = new Set();
  const button = {innerHTML: "Refresh", dataset: {}, disabled: false, classList: {contains: (x) => classes.has(x), add: (x) => classes.add(x), remove: (x) => classes.delete(x)}, setAttribute() {}, removeAttribute() {}, querySelector() {return null;}};
  context.beginButton(button, "Refreshing");
  button.innerHTML = "Refreshing";
  context.beginButton(button, "Refreshing again");
  context.endButton(button);
  assert.equal(button.innerHTML, "Refresh");
  assert.equal(button.disabled, false);
  button.disabled = true;
  context.endButton(button);
  assert.equal(button.disabled, true, "ending an unrelated refresh must not enable an unavailable action");
});

test("disclosure continuity distinguishes identical labels in different applications", () => {
  const context = {};
  vm.runInNewContext(source.slice(source.indexOf("function disclosureKey("), source.indexOf("function captureViewState(")), context);
  const details = (owner) => ({querySelector: () => ({querySelector: () => ({textContent: "Technical details"})}), closest: (selector) => selector === "[data-view-key]" ? {dataset: {viewKey: owner}} : null});
  assert.notEqual(context.disclosureKey(details("Brave:user")), context.disclosureKey(details("Office:user")));
  assert.equal(context.disclosureKey(details("Brave:user")), context.disclosureKey(details("Brave:user")));
});

test("modal decisions default to cancel and survive application rerenders", async () => {
  let dialog, closeHandler, focused = false;
  const trigger = {isConnected: true, focus: () => {focused = true;}};
  const context = {copy: String, esc: String, icon: () => "", document: {activeElement: trigger, querySelector: () => null, createElement: () => (dialog = {setAttribute() {}, addEventListener: (event, handler) => {closeHandler = handler;}, showModal() {}, remove() {}}), body: {append() {}}}};
  vm.runInNewContext(source.slice(source.indexOf("function confirmAction("), source.indexOf("function viewControlKey(")), context);
  const canceled = context.confirmAction("Clear", "Cannot undo", "Clear", true);
  assert.match(dialog.innerHTML, /value="cancel" autofocus/);
  dialog.returnValue = "cancel"; closeHandler();
  assert.equal(await canceled, false);
  assert.equal(focused, true);
  const confirmed = context.confirmAction("Scan", "Scan files", "Scan");
  dialog.returnValue = "confirm"; closeHandler();
  assert.equal(await confirmed, true);
});

test("privacy IPC dispatch runs off the window thread without changing the typed boundary", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(rust, /#\[tauri::command\(async\)\]\s*fn set_privacy_profile\(/);
  assert.match(rust, /#\[tauri::command\(async\)\]\s*fn get_privacy\(/);
  assert.doesNotMatch(index, /id="app" aria-live/);
});


test("page collection is dispatched off the window thread", () => {
  const rust = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  for (const name of ["get_overview", "get_evidence", "get_filesecurity", "get_devices", "get_applications", "get_updates", "get_network_protection", "get_network_activity", "get_threat_protection", "get_secure_dns", "get_security_center_digest"]) {
    assert.ok(rust.replace(/\r\n/g, "\n").includes(`#[tauri::command(async)]\nfn ${name}(`), name);
  }
});
