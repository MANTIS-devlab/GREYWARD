const startupMark = (name) => window.__greywardStartupMark?.(name);
const startupMarkOnce = (name) => window.__greywardStartupMarkOnce?.(name);
startupMark("app_script_start");
const app = document.querySelector("#app");
function renderStartupFailure(error) {
  if (!app) return;
  const localize = (key, fallback) => globalThis.GREYWARD_I18N?.t?.(key) || fallback;
  const detail = String(error?.message || error || localize("startup.unknownError", "Unknown startup error"));
  app.innerHTML = `<main style="display:grid;min-height:100vh;place-items:center;padding:32px;background:#000;color:#edf5f8;font:16px/1.5 sans-serif"><section style="max-width:580px;padding:28px;border:1px solid #4b5c65;border-radius:16px;background:rgba(26,34,40,.9)"><p style="margin:0;color:#b9d8e6">GREYWARD ${localize("app.name", "Security Center")}</p><h1 style="margin:10px 0">${localize("startup.title", "Security Center could not start")}</h1><p>${localize("startup.copy", "Restart Security Center. Your security services continue to run independently.")}</p><details><summary>${localize("startup.technical", "Technical details")}</summary><pre style="white-space:pre-wrap">${detail.replace(/[&<>]/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[character]))}</pre></details></section></main>`;
}
window.addEventListener("error", (event) => renderStartupFailure(event.error || event.message));
window.addEventListener("unhandledrejection", (event) => renderStartupFailure(event.reason));
const i18n = window.GREYWARD_I18N;
const t = (key, values) => i18n?.t(key, values) ?? key;
const copy = (key, values) => t(key, values);

const pages = ["overview", "system", "network", "privacy", "updates", "files", "applications", "devices", "evidence", "activity", "threats"];
const pageAliases = Object.freeze({protection: "evidence", system: "evidence"});
const pageParents = Object.freeze({files: "system", applications: "system", devices: "system", evidence: "system", activity: "network", threats: "network"});
const primaryNav = [
  ["overview", "nav.overview", "overview"],
  ["system", "nav.system", "shield"],
  ["network", "nav.network", "network"],
  ["privacy", "nav.privacy", "privacy"],
  ["updates", "nav.updates", "updates"],
];
const pageNameKeys = Object.freeze({
  overview: "nav.overview", system: "nav.system", network: "nav.network", privacy: "nav.privacy", updates: "nav.updates",
  files: "route.files", activity: "route.activity", threats: "network.threats", applications: "route.apps", devices: "route.devices", evidence: "route.evidence",
});
const normalizePage = (page) => pageAliases[String(page || "").trim().toLowerCase()] || String(page || "").trim().toLowerCase();
const pageName = (page) => t(pageNameKeys[page] || pageNameKeys[normalizePage(page)] || "nav.overview");

let currentPage = "overview";
let requestSequence = 0;
let updatePoll = null;
let updateRequestBusy = false;
let updatePhase = "IDLE";
let eventsBound = false;
const pageCache = new Map();
const pageDataRequests = new Map();
const PAGE_CACHE_TTL_MS = 5000;
// Only derived posture presentations are safe to reuse briefly. Mutable
// surfaces (permissions, network policy, scans, updates, privacy, and device
// trust) must collect a current backend projection whenever they are opened.
const PAGE_CACHE_REUSE_ROUTES = new Set(["overview", "evidence"]);
const HISTORY_QUERY_DEBOUNCE_MS = 250;
const NETWORK_HISTORY_PAGE_SIZE = 120;
const UPDATE_PAGE_SIZE = 100;
const UPDATE_ACTIVE_PHASES = Object.freeze(["AUTHENTICATING", "RESOLVING", "DOWNLOADING", "INSTALLING", "VERIFYING", "CHECKPOINTING", "PREPARING_RESTART", "UPDATING_APPLICATIONS", "UPDATING_FIRMWARE", "UPDATING_SECURITY", "RESTARTING"]);
const UPDATE_TERMINAL_PHASES = Object.freeze(["COMPLETE", "CANCELLED", "FAILED"]);
const UPDATE_PHASE_PRESENTATION = Object.freeze({
  CHECKING: {stateKey: "updates.phase.checking", messageKey: "updates.message.reading", action: "none", busy: true, progress: true},
  CURRENT: {stateKey: "updates.phase.current", messageKey: "updates.message.current", action: "check", busy: false, progress: false},
  AVAILABLE: {stateKey: "updates.phase.available", messageKey: "updates.message.review", action: "apply", busy: false, progress: false},
  IDLE: {stateKey: "updates.phase.idle", messageKey: "updates.message.idle", action: "check", busy: false, progress: false},
  RESOLVED: {stateKey: "updates.phase.resolved", messageKey: "updates.message.review", action: "apply", busy: false, progress: false},
  AUTHENTICATING: {stateKey: "updates.phase.authenticating", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  RESOLVING: {stateKey: "updates.phase.resolving", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  DOWNLOADING: {stateKey: "updates.phase.downloading", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  INSTALLING: {stateKey: "updates.phase.installing", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  VERIFYING: {stateKey: "updates.phase.verifying", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  CHECKPOINTING: {stateKey: "updates.phase.checkpointing", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  PREPARING_RESTART: {stateKey: "updates.phase.preparing_restart", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  UPDATING_APPLICATIONS: {stateKey: "updates.phase.updating_applications", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  UPDATING_FIRMWARE: {stateKey: "updates.phase.updating_firmware", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  UPDATING_SECURITY: {stateKey: "updates.phase.updating_security", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  RESTARTING: {stateKey: "updates.phase.restarting", messageKey: "updates.message.running", action: "cancel-or-none", busy: true, progress: true},
  READY_TO_RESTART: {stateKey: "updates.phase.ready_to_restart", messageKey: "updates.message.restart", action: "restart", busy: false, progress: false},
  COMPLETE: {stateKey: "updates.phase.complete", messageKey: "updates.message.completed", action: "check", busy: false, progress: false},
  CANCELLED: {stateKey: "updates.phase.cancelled", messageKey: "updates.message.cancelled", action: "check", busy: false, progress: false},
  FAILED: {stateKey: "updates.phase.failed", messageKey: "updates.message.failed", action: "check", busy: false, progress: false},
  DEGRADED: {stateKey: "updates.phase.degraded", messageKey: "updates.message.degraded", action: "check", busy: false, progress: false},
  UNAVAILABLE: {stateKey: "updates.phase.unavailable", messageKey: "updates.message.unavailable", action: "check", busy: false, progress: false},
});
let historyQueryTimer = null;
let historyQuerySequence = 0;
let fileContextDismissed = false;
let fileContextActionPending = false;
const privacyState = {feedback: "", exportPath: "", profilePending: null, localActionPending: false, feedbackScope: "local"};
const updateListState = {limit: UPDATE_PAGE_SIZE};
const fileSecurityState = {operationId: null, polling: null, pollDelayMs: 900, requestBusy: false, feedback: ""};
const deviationState = {feedback: ""};
const DEFAULT_NETWORK_ACTIVITY_FILTERS = Object.freeze({search: "", decision: "ALL", protocol: "ALL", port: "", window: "30m"});
function networkActivityDefaultFilters() { return {...DEFAULT_NETWORK_ACTIVITY_FILTERS}; }
const networkActivityState = {
  sessionId: null,
  nextSequence: 0,
  events: [],
  summary: {total: 0, allowed: 0, blocked: 0, unknown: 0, buckets: []},
  filters: networkActivityDefaultFilters(),
  expanded: new Set(),
  paused: false,
  pending: 0,
  requestBusy: false,
  mode: "live",
  historyEvents: [],
  historyCursor: null,
  historyState: "AVAILABLE",
  renderedListMarkup: null,
  renderedSummaryMarkup: null,
  renderedProtocolOptions: null,
};
const networkActionState = {feedback: ""};
let focusedThreatEventId = "";
const recoveryOperationLabels = Object.freeze({
  create_recovery_point: ["backup.queue.localPoint", "backup.queue.localPointCopy"],
  cleanup_recovery_points: ["backup.queue.cleanup", "backup.queue.cleanupCopy"],
  configure_backup: ["backup.queue.setup", "backup.queue.setupCopy"],
  backup_now: ["backup.queue.personal", "backup.queue.personalCopy"],
  verify_backup: ["backup.queue.verify", "backup.queue.verifyCopy"],
});

const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[character]));
const invoke = (command, args) => {
  const api = window.__TAURI_INTERNALS__;
  return api?.invoke ? api.invoke(command, args) : Promise.reject(new Error(copy("feedback.ipcUnavailable")));
};
function invokeBounded(command, args, timeoutMs = 10000) {
  if (Array.isArray(window.__greywardPerformanceCalls)) window.__greywardPerformanceCalls.push(String(command));
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => reject(new Error("The request timed out.")), timeoutMs);
    invoke(command, args).then(
      (value) => { window.clearTimeout(timeout); resolve(value); },
      (error) => { window.clearTimeout(timeout); reject(error); },
    );
  });
}

function icon(name) {
  const paths = {
    overview: '<path d="M4 12.2 12 5l8 7.2v7.3H4z"/><path d="M9.3 19.5v-5h5.4v5"/>',
    network: '<circle cx="5" cy="12" r="1.8"/><circle cx="19" cy="6" r="1.8"/><circle cx="19" cy="18" r="1.8"/><path d="m6.7 11.3 10.5-4.6M6.7 12.8l10.5 4.5"/>',
    applications: '<rect x="4" y="4" width="6.2" height="6.2" rx="1"/><rect x="13.8" y="4" width="6.2" height="6.2" rx="1"/><rect x="4" y="13.8" width="6.2" height="6.2" rx="1"/><rect x="13.8" y="13.8" width="6.2" height="6.2" rx="1"/>',
    devices: '<rect x="3.5" y="5.2" width="17" height="11.4" rx="1.8"/><path d="M8.5 20h7M12 16.8V20"/>',
    evidence: '<path d="M6.2 3.5h8.2l3.4 3.5v13.5H6.2z"/><path d="M14.2 3.5v4h3.6M9 12h6M9 15.5h6"/>',
    updates: '<path d="M4 7h16M4 12h16M4 17h10"/><path d="m16 15 2 2 3-3"/>',
    privacy: '<path d="M12 3.3 19 6v5c0 4.6-2.7 8-7 9.9C7.7 19 5 15.6 5 11V6z"/><path d="m9 12 2.1 2.1L15.5 9.6"/>',
    arrow: '<path d="M5 12h13M13 6.5 18.5 12 13 17.5"/>',
    chevron: '<path d="m9 6 6 6-6 6"/>',
    shield: '<path d="M12 3.1 19.2 6v5.1c0 4.7-2.9 8.1-7.2 10-4.3-1.9-7.2-5.3-7.2-10V6z"/><path d="m9.1 12 2 2 4-4"/>',
    activity: '<path d="M4 12h3l2-5 3.2 10 2.1-5H20"/>',
    export: '<path d="M12 3v11M8 10l4 4 4-4M5 18.5h14"/>',
    clean: '<path d="M5.5 7.5h13M9.5 7.5V5h5v2.5M8 10.5v7M12 10.5v7M16 10.5v7M7 7.5l.8 12h8.4l.8-12"/>',
    lock: '<rect x="5.5" y="10.4" width="13" height="9" rx="1.6"/><path d="M8.5 10.4V7.5a3.5 3.5 0 0 1 7 0v2.9"/>',
    file: '<path d="M6.5 3.5h7.6l3.4 3.4v13.6h-11z"/><path d="M14 3.7v4h3.7M9 12h6M9 15.5h4"/>',
    folder: '<path d="M3.5 7.5h6l1.7 2h9.3v9.5h-17z"/><path d="M3.5 7.5v-1h6l1.7 2"/>',
    travel: '<path d="M5 7.5h14v12H5z"/><path d="M8 7.5V5h8v2.5M8.5 12h7M12 9.5v5"/>',
    refresh: '<path d="M19 8.5A7.5 7.5 0 1 0 20 13"/><path d="M19 4.5v4h-4"/>',
    warning: '<path d="m12 4 8 15H4z"/><path d="M12 9v4M12 16.5h.01"/>',
    check: '<path d="m5 12 4.2 4.2L19 6.5"/>',
    recovery: '<path d="M12 4.2 19 7v4.8c0 4.1-2.6 7.3-7 8.9-4.4-1.6-7-4.8-7-8.9V7z"/><path d="M9 12.2h6M12 9.2v6"/>',
    globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.8 12h16.4M12 3.5c2.1 2.3 3.2 5.1 3.2 8.5s-1.1 6.2-3.2 8.5c-2.1-2.3-3.2-5.1-3.2-8.5S9.9 5.8 12 3.5z"/>',
  };
  return `<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.overview}</svg>`;
}

function identitySeed(value) {
  return String(value || "unknown").trim().toLowerCase().replace(/[^a-z0-9]+/g, " ").trim() || "unknown";
}
function identityInitial(value) {
  const words = identitySeed(value).split(" ").filter(Boolean);
  return (words.length > 1 ? words[0][0] + words[1][0] : words[0].slice(0, 2)).toUpperCase();
}
function identityColor(value) {
  let hash = 0;
  for (const character of identitySeed(value)) hash = ((hash << 5) - hash + character.charCodeAt(0)) | 0;
  return Math.abs(hash) % 6;
}
const localNetworkIcons = {
  application: {
    firefox: "firefox", brave: "brave", chrome: "googlechrome", chromium: "googlechrome",
    safari: "safari", opera: "opera", tor: "torbrowser", curl: "curl", docker: "docker",
    podman: "podman", flatpak: "flatpak", electron: "electron", terminal: "gnometerminal",
    bash: "gnubash", python: "python", npm: "npm", rust: "rust", go: "go", ruby: "ruby",
    php: "php", tauri: "tauri", gnome: "gnome", wikipedia: "wikipedia", youtube: "youtube",
  },
  destination: {
    apple: "apple", cloudflare: "cloudflare", duckduckgo: "duckduckgo", github: "github",
    google: "google", youtube: "youtube", wikipedia: "wikipedia", mozilla: "mozilla",
    "cppreference.com": "cplusplus", fedora: "fedora", debian: "debian", ubuntu: "ubuntu",
    opensuse: "opensuse", redhat: "redhat", npm: "npm",
  },
};
function localNetworkIcon(kind, values) {
  const candidates = (Array.isArray(values) ? values : [values])
    .filter(Boolean)
    .map((value) => String(value).toLowerCase().replace(/[^a-z0-9.+-]+/g, " "));
  const known = localNetworkIcons[kind] || {};
  for (const [needle, slug] of Object.entries(known)) {
    if (candidates.some((candidate) => candidate === needle || candidate.includes(needle))) return slug;
  }
  const catalog = window.GREYWARD_NETWORK_ICON_CATALOG || {};
  for (const candidate of candidates) {
    const compact = candidate.replace(/[^a-z0-9]/g, "");
    if (catalog[compact]) return catalog[compact];
    for (const token of candidate.split(/[^a-z0-9]+/).filter(Boolean)) {
      if (catalog[token]) return catalog[token];
    }
  }
  return "";
}
function networkIdentityMark(kind, values) {
  const candidate = Array.isArray(values) ? values.find(Boolean) : values;
  const className = "network-identity-logo network-identity-logo-" + kind;
  const palette = kind === "application"
    ? ["applications", "file", "folder", "shield", "activity", "lock"]
    : ["network", "globe", "shield", "lock", "folder", "activity"];
  const glyph = palette[identityColor(candidate)];
  const localIcon = localNetworkIcon(kind, values);
  const visual = localIcon
    ? `<img src="./assets/network-icons/${localIcon}.svg" alt="" draggable="false">`
    : icon(glyph);
  return `<span class="${className}${localIcon ? " has-local-icon" : " network-identity-fallback"} identity-color-${identityColor(candidate)}" aria-hidden="true" title="${esc(identityInitial(candidate))}">${visual}</span>`;
}

function stateLabel(value) {
  const normalized = String(value || "UNAVAILABLE").toUpperCase().replace(/-/g, "_");
  const labels = {
    ACTION_REQUIRED: "state.reviewNeeded", ATTENTION: "state.reviewNeeded", REVIEW_NEEDED: "state.reviewNeeded",
    SECURE: "state.secure", PROTECTED: "state.protected", UNAVAILABLE: "state.unavailable", UNKNOWN: "state.unknown",
    AVAILABLE: "state.available", SCOPED: "state.scoped", COMPLETED: "state.completed", SUCCESSFUL: "state.completed",
    PARTIAL: "state.partial", CANCELLED: "state.cancelled", INTERRUPTED: "state.interrupted", FAILED: "state.failed", RUNNING: "state.working", READY: "state.ready", BLOCKED: "state.blocked",
    VERIFIED: "state.verified", STAGED: "state.staged", NOT_CONFIGURED: "state.notConfigured",
    DESTINATION_UNAVAILABLE: "state.destinationUnavailable", NOT_RUN_YET: "state.notRunYet",
    CURRENT: "state.current", OUTDATED: "state.outdated", DEGRADED: "state.degraded", OPERATING: "state.active",
    ACTIVE: "state.active", INACTIVE: "state.inactive", DISABLED: "state.inactive", ERROR: "state.unavailable",
    DETECTED: "file.state.detected", QUARANTINED: "file.state.quarantined", RESTORED: "file.state.restored",
    DELETED: "file.state.deleted", QUARANTINE_FAILED: "file.state.quarantineFailed", RESTORE_FAILED: "file.state.restoreFailed",
    DELETE_FAILED: "file.state.deleteFailed", SCANNING: "file.state.scanning", FINALIZING: "file.state.finalizing", QUEUED: "file.state.queued",
  };
  if (labels[normalized]) return copy(labels[normalized]);
  return normalized.replace(/_/g, " ");
}
function tone(value) {
  const normalized = String(value || "unknown").toLowerCase();
  if (["secure", "protected", "current", "healthy", "complete", "success", "operating", "allowed"].includes(normalized)) return "positive";
  if (["review", "review needed", "needs attention", "attention", "action_required", "outdated", "degraded", "available"].includes(normalized)) return "review";
  if (["action", "threat", "failed", "error", "denied"].includes(normalized)) return "critical";
  if (["unknown", "stale", "checking", "running", "pending"].includes(normalized)) return "uncertain";
  return "muted";
}
function status(value, valueTone = value, options = {}) {
  const label = options.canonical ? stateLabel(value) : String(value || "UNKNOWN").replace(/_/g, " ");
  return `<span class="status status-${tone(valueTone)}"${options.markerOnly ? ` aria-label="${esc(label)}" title="${esc(label)}"` : ""}><i aria-hidden="true"></i>${options.markerOnly ? "" : `<span>${esc(label)}</span>`}</span>`;
}
function primaryNavMarkup() {
  return primaryNav.map(([id, labelKey, glyph]) => {
    const active = currentPage === normalizePage(id) || pageParents[currentPage] === id;
    return `<button class="nav-item ${active ? "active" : ""}" data-page="${id}" aria-label="${esc(t(labelKey))}" title="${esc(t(labelKey))}" aria-current="${active ? "page" : "false"}"><span class="nav-icon">${icon(glyph)}</span><span>${esc(t(labelKey))}</span></button>`;
  }).join("");
}
function shell(content, options = {}) {
  const label = pageName(currentPage);
  const parent = pageParents[currentPage];
  const path = parent ? `<span>${esc(t("app.name"))}</span><b aria-hidden="true">/</b><button class="breadcrumb-link" data-page="${esc(parent)}">${esc(pageName(parent))}</button><b aria-hidden="true">/</b><strong>${esc(label)}</strong>` : `<span>${esc(t("app.name"))}</span><b aria-hidden="true">/</b><strong>${esc(label)}</strong>`;
  return `<div class="app-shell" aria-busy="${options.busy ? "true" : "false"}"><aside class="security-index"><div class="index-brand"><img src="./greyward-symbol.svg" alt="GREYWARD"><div><strong>GREYWARD</strong><span>${esc(t("app.name"))}</span></div></div><nav class="nav-list" aria-label="${esc(t("app.sections"))}">${primaryNavMarkup()}</nav><div class="index-foot"><span class="status-mark" aria-hidden="true"></span><div><strong>${esc(t("app.localSecurity"))}</strong><small>${esc(t("app.measured"))}</small></div></div></aside><main class="workspace"><header class="context-strip"><div class="context-path">${path}</div></header><div class="content-frame">${content}</div><div class="action-status app-action-status" data-live-status role="status" aria-live="polite" aria-atomic="true">${esc(deviationState.feedback)}</div></main></div>`;
}function pageHeader(eyebrow, title, copy, action = "") {
  return `<header class="page-header"><div class="page-heading"><div class="page-heading-row"><h1>${esc(title)}</h1></div>${copy ? `<p>${esc(copy)}</p>` : ""}</div>${action ? `<div class="page-header-action">${action}</div>` : ""}</header>`;
}function actionButton(label, detail, kind = "secondary", attrs = "", glyph = "arrow") {
  return `<button class="action-button ${kind}" ${attrs} title="${esc(detail || label)}"><span class="action-icon">${icon(glyph)}</span><span class="action-label">${esc(label)}</span>${kind === "primary" && glyph !== "arrow" ? `<span class="action-arrow">${icon("arrow")}</span>` : ""}</button>`;
}
function statusRow(row, compact = false, action = "") {
  const safeRow = row || {label_key: "ui.unavailable", value: "UNAVAILABLE", detail_key: "ui.unavailableCopy"};
  const values = safeRow.copy_values || {};
  const label = copy(safeRow.label_key || "", values) || safeRow.label || copy("ui.unavailable");
  const value = copy(safeRow.value_key || "", values) || safeRow.value || copy("state.unknown");
  const detail = copy(safeRow.detail_key || "", values) || safeRow.detail || copy("ui.unavailableCopy");
  const end = action ? `<div class="status-row-end">${status(value, safeRow.tone)}${action}</div>` : status(value, safeRow.tone);
  return `<article class="status-row ${compact ? "compact" : ""}"><div class="status-row-main"><span class="status-label">${esc(label)}</span><p>${esc(detail)}</p></div>${end}</article>`;
}
function emptyState(title, copy, glyph = "shield", kind = "quiet") {
  return `<div class="empty-state ${kind}"><span class="empty-icon">${icon(glyph)}</span><div><strong>${esc(title)}</strong><p>${esc(copy)}</p></div></div>`;
}
function errorState(title, copy, retry = true) {
  return `<section class="state-panel error-state"><span class="state-panel-icon">${icon("warning")}</span><div><div class="eyebrow">${esc(t("error.eyebrow"))}</div><h2>${esc(title)}</h2><p>${esc(copy)}</p></div>${retry ? actionButton(t("ui.retry"), t("error.retry.detail"), "primary", "data-retry", "refresh") : ""}</section>`;
}
function loadingState(label = t("loading.status")) {
  return `<section class="loading-state" role="status" aria-live="polite" aria-busy="true"><div class="loading-orb">${icon("shield")}</div><div><div class="eyebrow">${esc(t("loading.eyebrow"))}</div><h2>${esc(label)}</h2><p>${esc(t("ui.readingEvidence"))}</p></div><div class="loading-line" aria-hidden="true"><span></span></div></section>`;
}
function technicalDisclosure(title, count, content) {
  return `<details class="technical-disclosure"><summary><span>${esc(title)}</span>${count ? `<span class="section-meta">${esc(count)}</span>` : ""}</summary><div class="technical-disclosure-content">${content}</div></details>`;
}
function findingMarkup(finding, index) {
  const values = finding.copy_values || {};
  const title = copy(finding.title_key || "", values) || finding.title || copy("overview.finding.unnamed");
  const summary = copy(finding.summary_key || "", values) || finding.summary || copy("overview.finding.noSummary");
  const context = copy(finding.context_key || "", values) || finding.context || copy("overview.finding.noContext");
  return `<button class="finding-row" data-page="${esc(normalizePage(finding.destination || "system"))}"><span class="finding-copy"><strong>${esc(title)}</strong><span>${esc(summary)}</span><small>${esc(context)}</small></span><span class="finding-state">${status(finding.state || "REVIEW NEEDED", finding.tone, {canonical:true})}${icon("arrow")}</span></button>`;
}
function domainMarkup(domain) {
  const destination = domain.destination || "protection";
  const nameKey = domain.name_key || "";
  const glyph = nameKey === "evidence.domain.network" ? "network" : nameKey === "evidence.domain.applications" ? "applications" : nameKey === "evidence.domain.devices" ? "devices" : nameKey === "evidence.domain.privacy" ? "privacy" : "shield";
  const values = domain.copy_values || {};
  const name = copy(nameKey, values) || domain.name || copy("overview.domain.unnamed");
  const context = copy(domain.context_key || "", values) || domain.context || copy("overview.domain.noContext");
  return `<button class="domain-row" data-page="${esc(destination)}"><span class="domain-name"><span class="domain-icon">${icon(glyph)}</span><strong>${esc(name)}</strong></span><span class="domain-context">${esc(context)}</span><span class="domain-meta">${esc(copy("overview.domain.checks", {count: domain.checks ?? 0}))}</span><span class="domain-state">${status(domain.state, domain.tone, {canonical:true})}${icon("arrow")}</span></button>`;
}
function activityMarkup(item) {
  return `<article class="activity-row"><span class="activity-icon">${icon("activity")}</span><div class="activity-copy"><strong>${esc(item.title || copy("activity.unnamed"))}</strong><p class="activity-detail">${esc(item.detail || "")}</p></div><time class="activity-time">${esc(localizedTime(item.occurred_at, ""))}</time></article>`;
}
function localizedTime(value, fallback = copy("ui.unavailable")) {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], {dateStyle: "medium", timeStyle: "short"});
}
function deviationAction(row) {
  const accepted = row.accepted_deviation === true;
  if (!accepted && !["REVIEW NEEDED", "ACTION REQUIRED", "UNAVAILABLE"].includes(String(row.state || "").toUpperCase())) return "";
  const label = accepted ? copy("evidence.deviation.restore") : copy("evidence.deviation.ignore");
  return `<button class="text-button evidence-deviation" data-deviation-id="${esc(row.check_id)}" data-deviation-accepted="${accepted ? "false" : "true"}">${label} ${icon("arrow")}</button>`;
}
function recoveryDeviationAction(row) {
  const value = String(row?.value || "").toUpperCase();
  const accepted = value === "PROTECTED";
  return ["REVIEW NEEDED", "ACTION REQUIRED", "UNAVAILABLE", "PROTECTED"].includes(value)
    ? `<button class="text-button evidence-deviation" data-deviation-id="recovery.readiness" data-deviation-accepted="${accepted ? "false" : "true"}">${esc(copy(accepted ? "evidence.deviation.restore" : "evidence.deviation.ignore"))} ${icon("arrow")}</button>`
    : "";
}
function evidenceValues(row) {
  const values = {...(row?.copy_values || {})};
  if (values.missing) values.missing = String(values.missing).split("|").filter(Boolean).map((key) => copy(key)).join(", ");
  return values;
}
function evidenceCopy(row, key, fallback) {
  return copy(row?.[key] || fallback, evidenceValues(row));
}
function evidenceNextStep(row) {
  const remediation = row?.remediation;
  return remediation?.route && remediation?.action_key
    ? `<button class="text-button evidence-next-action" data-page="${esc(remediation.route)}">${esc(copy(remediation.action_key, evidenceValues(row)))} ${icon("arrow")}</button>`
    : `<span class="evidence-next-copy">${esc(evidenceCopy(row, "no_remediation_key", "evidence.remediation.noDirect"))}</span>`;
}
function evidenceResolutionMarkup(row) {
  return `<article class="evidence-resolution-card tone-${tone(row.tone)}"><div class="evidence-resolution-top"><div class="evidence-resolution-title"><strong>${esc(evidenceCopy(row, "title_key", "system.checks.unnamed"))}</strong></div>${status(row.state, row.tone, {canonical:true})}</div><div class="evidence-resolution-summary"><p>${esc(evidenceCopy(row, "summary_key", "system.checks.noSummary"))}</p></div><div class="evidence-next-step"><p>${esc(evidenceCopy(row, "recommendation_key", "system.checks.noAction"))}</p><div class="evidence-next-actions">${evidenceNextStep(row)}${deviationAction(row)}</div></div></article>`;
}
function evidenceTechnicalMarkup(row) {
  const technical = row.technical || {};
  const technicalRecord = `<dl><div><dt>${esc(copy("system.checks.reference"))}</dt><dd><code>${esc(technical.reference || row.check_id || copy("ui.unavailable"))}</code></dd></div><div><dt>${esc(copy("system.checks.technicalReason"))}</dt><dd><code>${esc(technical.reason_code || copy("ui.unavailable"))}</code></dd></div><div><dt>${esc(copy("system.checks.observed"))}</dt><dd>${esc(localizedTime(technical.observed_at))}</dd></div><div><dt>${esc(copy("system.checks.freshUntil"))}</dt><dd>${esc(localizedTime(technical.fresh_until))}</dd></div></dl>`;
  return `<article class="evidence-row tone-${tone(row.tone)}"><div class="evidence-row-top"><strong>${esc(evidenceCopy(row, "title_key", "system.checks.unnamed"))}</strong>${status(row.state, row.tone, {canonical:true})}</div><p>${esc(evidenceCopy(row, "summary_key", "system.checks.noSummary"))}</p><small>${esc(evidenceCopy(row, "recorded_result_key", "system.checks.notRecorded"))} · ${esc(t("system.checks.evidenceCount", {count: row.evidence_count ?? 0}))}</small><p>${esc(evidenceCopy(row, "recommendation_key", "system.checks.noAction"))}</p>${technicalDisclosure(copy("system.checks.technicalRecord"), "", technicalRecord)}${deviationAction(row)}</article>`;
}

function overviewMarkup(data, digest = {}) {
  const overview = data.overview || data;
  const posture = overview.posture || {state:"UNAVAILABLE", tone:"unavailable", message_key:"overview.posture.unavailable.message", care_key:"overview.posture.unavailable.care", evaluated_at:copy("ui.unknown")};
  const digestFindings = Array.isArray(digest.unresolved_findings) ? digest.unresolved_findings.map((item) => ({...item, state:"REVIEW NEEDED", tone:"review", summary:item.summary, context:copy("overview.digest.context"), destination:item.destination || "overview"})) : [];
  const findings = (overview.priority_findings || []).length ? overview.priority_findings : digestFindings;
  const domains = overview.domains || [];
  const activity = overviewActivity(overview, digest);
  const next = findings[0];
  const remainingFindings = findings.slice(1);
  const postureValues = posture.copy_values || {};
  const postureMessage = posture.state === "REVIEW NEEDED" ? copy("overview.posture.review.next") : copy(posture.message_key || "", postureValues) || posture.message || copy("overview.posture.unavailable.message");
  const nextValues = next?.copy_values || {};
  const nextTitle = next ? (copy(next.title_key || "", nextValues) || next.title || copy("overview.finding.unnamed")) : "";
  const nextSummary = next ? (copy(next.summary_key || "", nextValues) || next.summary || copy("overview.finding.noSummary")) : "";
  const limited = Number(overview.metrics?.unavailable || 0) > 0 && ["PROTECTED", "SECURE"].includes(posture.state);
  const decision = next ? `<div class="brief-decision"><div class="eyebrow">${esc(t("overview.next"))}</div><h2>${esc(nextTitle)}</h2><p>${esc(nextSummary)}</p>${actionButton(copy("overview.reviewAction", {name: nextTitle}), copy("overview.reviewAction.detail"), "primary", `data-page="${esc(normalizePage(next.destination || "system"))}"`, "arrow")}</div>` : `<div class="brief-decision ${posture.state === "UNAVAILABLE" || limited ? "review" : "calm"}"><div class="eyebrow">${esc(t("overview.next"))}</div><h2>${esc(copy(posture.state === "UNAVAILABLE" ? "overview.unavailable.title" : limited ? "overview.limited.title" : "overview.noAction.title"))}</h2>${actionButton(t("overview.viewSystem"), copy("overview.viewSystem.detail"), "secondary", 'data-page="system"', "shield")}</div>`;
  const findingsSection = remainingFindings.length ? `<section class="overview-section priority-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("overview.more.eyebrow"))}</div><h2>${esc(copy("overview.more.count", {count: remainingFindings.length}))}</h2></div></div><div class="finding-list">${remainingFindings.map((finding, index) => findingMarkup(finding, index + 2)).join("")}</div></section>` : "";
  const digestState = digest.source_state?.state || "AVAILABLE";
  const digestActivity = digestState === "AVAILABLE" ? activity : [];
  return `${pageHeader(copy("overview.eyebrow"), t("nav.overview"), "", actionButton(t("ui.refresh"), copy("overview.refresh.detail"), "secondary", "data-refresh", "refresh"))}<section class="overview-brief tone-${tone(posture.tone)}"><div class="brief-index"><div class="eyebrow">${esc(copy("overview.posture.eyebrow"))}</div></div><div class="brief-main"><div class="brief-state"><div class="eyebrow">${esc(copy("design.overview.scope"))}</div><h2>${esc(copy(`design.posture.${posture.state === "SECURE" ? "secure" : posture.state === "PROTECTED" ? "protected" : posture.state === "REVIEW NEEDED" ? "review" : "unavailable"}`))}</h2></div>${posture.state === "REVIEW NEEDED" ? "" : `<p>${esc(postureMessage)}</p>`}<div class="brief-context"><span>${esc(copy(posture.care_key || "", postureValues) || posture.care || copy("overview.posture.unavailable.care"))}</span><time>${esc(t("ui.checked", {time: localizedTime(posture.evaluated_at, copy("ui.unknown"))}))}</time></div></div>${decision}</section>${findingsSection}<div class="overview-lower product-overview"><section class="overview-section domain-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("overview.domains.eyebrow"))}</div><h2>${esc(copy("overview.domains.title"))}</h2></div><button class="text-button" data-page="system">${esc(copy("overview.domains.action"))} ${icon("arrow")}</button></div><div class="domain-list">${domains.map(domainMarkup).join("")}</div></section><details class="technical-disclosure overview-section activity-section"><summary><span>${esc(copy("overview.activity.title"))}</span></summary>${digestState !== "AVAILABLE" ? emptyState(copy("overview.activity.unavailable.title"), copy("overview.activity.unavailable.copy"), "activity") : digestActivity.length ? `<div class="activity-list">${digestActivity.slice(0, 5).map(activityMarkup).join("")}</div>` : emptyState(copy("overview.activity.empty.title"), copy("overview.activity.empty.copy"), "activity")}</details></div>`;
}function plainSection(eyebrow, title, rows, glyph) { return `<section class="plain-section"><div class="section-heading"><div><div class="eyebrow">${esc(eyebrow)}</div><h2>${esc(title)}</h2></div></div>${rows.length ? rows.map((row) => statusRow(row, true)).join("") : emptyState(copy("ui.unavailable"), copy("ui.unavailableCopy"), glyph)}</section>`; }

function secureDnsMarkup(dns) {
  const state = String(dns.effective_policy || "UNAVAILABLE");
  const transport = String(dns.effective_transport || "UNKNOWN");
  const mode = String(dns.desired_policy || "Automatic");
  const toneName = state === "SecureProvider" || state === "VPNOwned" ? "positive" : state === "CompatibilityFallback" ? "review" : "unavailable";
  const options = [["Automatic", "network.dns.mode.automatic"], ["Privacy", "network.dns.mode.privacy"], ["NetworkDefault", "network.dns.mode.networkDefault"]].map(([value, labelKey]) => `<option value="${value}"${value === mode ? " selected" : ""}>${esc(copy(labelKey))}</option>`).join("");
  const chain = (dns.provider_order || ["quad9", "controld", "adguard"]).map((value) => ({quad9:"Quad9", controld:"Control D", adguard:"AdGuard"}[value] || value)).join(" → ");
  const stateKey = {SecureProvider:"network.dns.state.secure", VPNOwned:"network.dns.state.vpn", CompatibilityFallback:"network.dns.state.fallback"}[state] || "network.dns.state.unavailable";
  const detail = dns.degradation_reason ? copy("network.dns.detail.degraded") : (dns.effective_owner === "VPN" ? copy("network.dns.detail.vpn") : copy("network.dns.detail.measured"));
  const facts = `<p>${esc(copy("network.dns.facts", {transport, validation:dns.validation || copy("network.dns.unknown"), provider:dns.provider || copy("network.dns.unknown")}))}</p>`;
  const readOnly = dns.runtime_mutation === "DISABLED_READ_ONLY";
  return `<section class="secure-dns-panel tone-${toneName}"><div><div class="eyebrow">${esc(copy("network.dns.eyebrow"))}</div><h3>${esc(copy(stateKey))}</h3><p>${esc(detail)}</p><div class="secure-dns-facts"><span><b>${esc(copy("network.dns.configuredMode"))}</b> ${esc(copy({Automatic:"network.dns.mode.automatic", Privacy:"network.dns.mode.privacy", NetworkDefault:"network.dns.mode.networkDefault"}[mode] || "network.dns.unknown"))}</span><span><b>${esc(copy("network.dns.failoverChain"))}</b> ${esc(chain)}</span></div>${technicalDisclosure(copy("network.dns.resolverDetails"), "", facts)}</div><div class="secure-dns-controls"><label for="secure-dns-mode">${esc(copy("network.dns.modeLabel"))}</label><select id="secure-dns-mode" data-secure-dns-mode${readOnly ? ' disabled aria-disabled="true"' : ""}>${options}</select><button class="text-button" data-secure-dns-retry${readOnly ? ' disabled aria-disabled="true"' : ""}>${esc(copy("network.dns.retry"))} ${icon("refresh")}</button><small>${esc(readOnly ? copy("network.dns.readOnly") : copy("network.dns.verifyAfterChange"))}</small></div></section>`;
}

function networkProtectionMarkup(data) {
  const opensnitch = data.opensnitch || {};
  const linkState = String(opensnitch.state || "UNAVAILABLE").toUpperCase();
  const healthState = String(opensnitch.health?.state || linkState).toUpperCase();
  const healthFreshness = String(opensnitch.health?.freshness || "FRESH").toUpperCase();
  const firewalld = data.firewalld || {};
  const dns = data.secure_dns || {};
  const applications = data.applications || [];
  const rules = data.rules || [];
  const mutationAvailable = linkState === "OPERATING" && opensnitch.capabilities?.rule_mutation === "TYPED_POLICY";
  const firewallState = String(firewalld.state || "UNAVAILABLE").toUpperCase();
  const dnsState = String(dns.effective_policy || "UNAVAILABLE").toUpperCase();
  const firewallZone = String(firewalld.zone || "").trim().toUpperCase();
  const firewallUnavailable = !firewalld.state || ["UNAVAILABLE", "UNKNOWN", "FAILED", "INACTIVE"].includes(firewallState) || !firewallZone || ["UNKNOWN", "NO ZONE REPORTED", "UNAVAILABLE"].includes(firewallZone);
  const dnsDegraded = ["UNAVAILABLE", "UNKNOWN", "NONE", "COMPATIBILITYFALLBACK"].includes(dnsState);
  const opensnitchDegraded = linkState === "DEGRADED" || healthState === "DEGRADED" || healthFreshness === "STALE";
  const overallState = linkState === "UNAVAILABLE" || firewallUnavailable ? "UNAVAILABLE" : opensnitchDegraded || dnsDegraded ? "NEEDS ATTENTION" : "PROTECTED";
  const connectionHeadline = overallState === "PROTECTED" ? copy("network.protection.protected") : overallState === "NEEDS ATTENTION" ? copy("network.protection.attention") : copy("network.protection.unavailable");
  const healthLabel = healthState === "IDLE" && linkState === "OPERATING" && healthFreshness !== "STALE" ? copy("network.protection.visibility.ready") : healthState === "UNAVAILABLE" || linkState === "UNAVAILABLE" ? copy("network.protection.visibility.unavailable") : healthState === "DEGRADED" || linkState === "DEGRADED" || healthFreshness === "STALE" ? copy("network.protection.visibility.degraded") : copy("network.protection.visibility.active");
  const statusMessage = linkState === "UNAVAILABLE" ? copy("network.protection.detail.unavailable") : firewallUnavailable ? copy("network.protection.firewallUnavailable") : opensnitchDegraded ? (opensnitch.health?.detail || opensnitch.detail || copy("network.protection.detail.degraded")) : dnsDegraded ? copy("network.protection.detail.dnsDegraded", {reason: dns.degradation_reason || copy("network.dns.unknown")}) : copy("network.protection.detail.active");
  const zone = String(firewalld.zone || "").trim().toLowerCase();
  const zoneControls = zone === "trusted"
    ? `<span class="network-zone-current">${esc(copy("network.protection.trustedActive"))}</span>${actionButton(copy("network.protection.restorePublic"), copy("network.protection.restorePublicDetail"), "secondary", 'data-zone="public"', "network")}`
    : zone === "public"
      ? `${actionButton(copy("network.protection.trust"), copy("network.protection.trustDetail"), "secondary", 'data-zone="trusted"', "lock")}<span class="network-zone-current">${esc(copy("network.protection.publicActive"))}</span>`
      : `${actionButton(copy("network.protection.trust"), copy("network.protection.trustDetail"), "secondary", 'data-zone="trusted"', "lock")}${actionButton(copy("network.protection.restorePublic"), copy("network.protection.restorePublicDetail"), "secondary", 'data-zone="public"', "network")}`;
  const controls = firewalld.interface ? `<div class="action-stack">${zoneControls}</div>` : emptyState(copy("network.protection.noConnection"), copy("network.protection.noConnectionCopy"), "network");
  const appRows = applications.length ? applications.map((item) => `<article class="network-app-row"><div class="network-app-title">${networkIdentityMark("application", [item.application, item.executable])}<div><strong>${esc(item.application || copy("network.protection.unknownApplication"))}</strong><small>${esc(item.executable || copy("network.protection.pathUnavailable"))}</small></div></div><div class="network-app-metrics"><span><b>${esc(item.allowed ?? 0)}</b> ${esc(copy("network.protection.allowed"))}</span><span><b>${esc(item.blocked ?? 0)}</b> ${esc(copy("network.protection.blocked"))}</span><span><b>${esc(item.unknown ?? 0)}</b> ${esc(copy("network.protection.unknown"))}</span></div><div class="network-app-destinations">${(item.destinations || []).slice(0, 4).map((destination) => `<span class="network-destination-chip">${networkDestinationIdentity(destination)}<span>${esc(destination)}</span></span>`).join("") || `<span>${esc(copy("network.protection.noDestination"))}</span>`}</div>${mutationAvailable && item.executable ? `<div class="network-app-actions"><button class="text-button" data-network-set data-application="${esc(item.executable)}" data-network-action="allow">${esc(copy("network.protection.alwaysAllow"))} ${icon("arrow")}</button><button class="text-button" data-network-set data-application="${esc(item.executable)}" data-network-action="deny">${esc(copy("network.protection.alwaysBlock"))} ${icon("arrow")}</button></div>` : ""}</article>`).join("") : emptyState(
    linkState === "UNAVAILABLE" ? copy("network.protection.visibility.unavailable") : copy("network.protection.noActivity"),
    linkState === "UNAVAILABLE" ? copy("network.protection.detail.unavailable") : copy("network.protection.noActivityCopy"),
    "applications",
  );
  const ruleRows = rules.length ? rules.map((rule) => `<article class="network-rule-row"><div><strong>${esc(rule.name || copy("network.protection.connectionRule"))}</strong><p class="network-rule-scope"><span class="network-activity-identity">${networkIdentityMark("application", rule.scope?.application)}<span>${esc(rule.scope?.application || copy("network.protection.allApplications"))}</span></span>${rule.scope?.destination ? ` · <span class="network-activity-identity">${networkDestinationIdentity(rule.scope.destination.host || rule.scope.destination.ip || copy("network.protection.noDestination"))}<span>${esc(rule.scope.destination.host || rule.scope.destination.ip || copy("network.protection.noDestination"))}${rule.scope.destination.port ? `:${esc(rule.scope.destination.port)}` : ""}</span></span>` : ""}</p></div>${status(rule.action || "UNKNOWN", rule.action === "ALLOW" ? "allowed" : "review")}${rule.mutable ? `<button class="text-button" data-network-remove data-rule-id="${esc(rule.id)}" title="${esc(copy("network.protection.removeRuleDetail"))}">${esc(copy("network.protection.removeRule"))} ${icon("clean")}</button>` : `<span class="network-readonly">${esc(copy("network.protection.managedElsewhere"))}</span>`}</article>`).join("") : emptyState(copy("network.protection.noRules"), linkState === "UNAVAILABLE" ? copy("network.protection.noRulesUnavailable") : copy("network.protection.noRulesCopy"), "shield");
  const capabilityDetails = `${statusRow({label:copy("network.protection.capability.installed"),value:opensnitch.capabilities?.installed ? "INSTALLED" : "UNAVAILABLE",tone:opensnitch.capabilities?.installed ? "positive" : "unavailable",detail:copy("network.protection.capability.installedDetail")}, true)}${statusRow({label:copy("network.protection.capability.activity"),value:opensnitch.capabilities?.activity && linkState === "OPERATING" ? "AVAILABLE" : "UNAVAILABLE",tone:opensnitch.capabilities?.activity && linkState === "OPERATING" ? "positive" : "unavailable",detail:copy("network.protection.capability.activityDetail")}, true)}${statusRow({label:copy("network.protection.capability.rules"),value:mutationAvailable ? "AVAILABLE" : "UNAVAILABLE",tone:mutationAvailable ? "positive" : "unavailable",detail:mutationAvailable ? copy("network.protection.capability.rulesAvailable") : copy("network.protection.capability.rulesUnavailable")}, true)}`;
  const actionStatus = data.probe_feedback || networkActionState.feedback || (opensnitch.capabilities?.interactive_prompts === "DEFERRED" ? copy("network.protection.interactiveDeferred") : statusMessage);
  return `${pageHeader(copy("network.protection.eyebrow"), copy("network.protection"), copy("network.protection.copy"), actionButton(copy("ui.refresh"), copy("network.protection.refresh"), "secondary", "data-refresh", "refresh") + actionButton(copy("network.protection.test"), copy("network.protection.testDetail"), "secondary", "data-network-probe", "network"))}<section class="network-protection-hero tone-${tone(overallState)}"><div><h2>${esc(connectionHeadline)}</h2><p>${esc(overallState === "PROTECTED" ? copy("network.protection.detail.protected") : overallState === "UNAVAILABLE" ? copy("design.network.unavailable") : copy("design.network.attention"))}</p></div></section><section class="network-protection-grid"><article class="network-capability-card"><div class="eyebrow">${esc(copy("network.protection.appControl"))}</div><h3>${esc(healthLabel)}</h3>${technicalDisclosure(copy("ui.technical"), "", `<p>${esc(statusMessage)}</p>`)}<button class="text-button" data-page="activity">${esc(copy("network.protection.viewActivity"))} ${icon("arrow")}</button></article><article class="network-capability-card"><div class="eyebrow">${esc(copy("network.protection.firewallControl"))}</div><h3>${esc(firewalld.zone || copy("network.protection.noZone"))}</h3><p>${esc(copy("network.protection.firewallBoundary"))}</p><div class="network-card-actions">${controls}</div></article></section>${secureDnsMarkup(dns)}<div class="network-action-status" id="network-action-status" role="status" aria-live="polite">${esc(actionStatus)}</div><section class="plain-section network-applications-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("network.protection.appControl"))}</div><h2>${esc(copy("network.protection.observedApplications"))}</h2></div><span class="section-meta">${esc(applications.length)}</span></div><div class="network-app-list">${appRows}</div></section>${technicalDisclosure(copy("network.protection.savedRules"), rules.length, `<div class="network-rule-list">${ruleRows}</div>`)}${technicalDisclosure(copy("network.protection.capability"), "", capabilityDetails)}`;
}
function threatEventMarkup(item, focused = false) {
  const destination = item.destination || {};
  const threat = item.threat || {};
  const eventId = String(item.event_id || "");
  const exception = item.executable && destination.ip && destination.port
    ? `<button class="text-button" data-threat-exception data-application="${esc(item.executable)}" data-threat-ip="${esc(destination.ip)}" data-threat-port="${esc(destination.port)}">${esc(copy("network.threats.allow"))} ${icon("arrow")}</button>`
    : "";
  return `<article class="network-threat-event${focused ? " is-focused" : ""}" data-threat-event="${esc(eventId)}"><div><strong>${esc(item.application || copy("network.protection.unknownApplication"))}</strong><p>${esc(destination.ip || copy("network.protection.noDestination"))}:${esc(destination.port || "")}</p><small>${esc(copy("network.threats.time"))} · ${esc(localizedTime(item.occurred_at, copy("network.activity.unknownTime")))}</small>${threat.malware ? `<small>${esc(copy("network.threats.malware"))}: ${esc(threat.malware)}</small>` : ""}</div>${exception}</article>`;
}
function threatProtectionMarkup(data) {
  const threat = data || {};
  const state = String(threat.state || "ERROR").toUpperCase();
  const recent = Array.isArray(threat.recent_blocked_connections) ? threat.recent_blocked_connections : [];
  const exceptions = Array.isArray(threat.exceptions) ? threat.exceptions : [];
  const exceptionRows = exceptions.length ? exceptions.map((rule) => `<article class="network-rule-row"><div><strong>${esc(rule.name || copy("network.threats.exceptions"))}</strong><p>${esc(rule.scope?.application || copy("network.protection.unknownApplication"))} · ${esc(rule.scope?.destination?.ip || "")}:${esc(rule.scope?.destination?.port || "")}</p></div><button class="text-button" data-network-remove data-rule-id="${esc(rule.id)}">${esc(copy("network.threats.revoke"))} ${icon("clean")}</button></article>`).join("") : emptyState(copy("network.threats.noExceptions"), copy("network.threats.noExceptionsCopy"), "shield");
  const recentRows = recent.length ? recent.map((item) => threatEventMarkup(item, String(item.event_id) === focusedThreatEventId)).join("") : emptyState(copy("network.threats.empty"), copy("network.threats.emptyCopy"), "network");
  const statusText = state === "DISABLED" ? copy("network.threats.disabled") : state === "READY" || state === "EMPTY" ? copy("network.threats.enabled") : copy("network.threats.unavailable");
  const toggle = actionButton(state === "DISABLED" ? copy("network.threats.enable") : copy("network.threats.disable"), copy("network.threats.action"), state === "DISABLED" ? "primary" : "secondary", "data-threat-toggle", state === "DISABLED" ? "shield" : "clean");
  return `${pageHeader(copy("network.threats.eyebrow"), copy("network.threats"), copy("network.threats.copy"), actionButton(copy("ui.refresh"), copy("network.protection.refresh"), "secondary", "data-refresh", "refresh"))}<section class="network-threat-hero tone-${tone(state)}"><div><div class="eyebrow">${esc(copy("network.threats.state"))}</div><h2>${esc(stateLabel(state))}</h2><p>${esc(statusText)}</p><div class="network-card-actions">${toggle}</div></div><div class="network-threat-facts"><span><b>${esc(copy("network.threats.provider"))}</b> Feodo</span><span><b>${esc(copy("network.threats.indicators"))}</b> ${esc(threat.indicator_count ?? 0)}</span><span><b>${esc(copy("network.threats.lastUpdate"))}</b> ${esc(threat.last_successful_update || copy("ui.unavailable"))}</span></div></section><div class="network-action-status" id="network-action-status" role="status" aria-live="polite">${esc(networkActionState.feedback || (focusedThreatEventId ? copy("network.threats.focused") : ""))}</div><section class="plain-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("network.threats.recent"))}</div><h2>${esc(copy("network.threats.recent"))}</h2></div><span class="section-meta">${esc(recent.length)}</span></div><div class="network-threat-list">${recentRows}</div></section><section class="plain-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("network.threats.exceptions"))}</div><h2>${esc(copy("network.threats.exceptions"))}</h2></div><span class="section-meta">${esc(exceptions.length)}</span></div><div class="network-rule-list">${exceptionRows}</div></section>`;
}
function networkActivityDestination(item) {
  const destination = item?.destination || {};
  const host = destination.host || destination.ip || copy("network.activity.unknownDestination");
  return {
    host,
    ip: destination.ip || "",
    port: Number(destination.port || 0),
    country_code: destination.country_code || "",
    country_confidence: destination.country_confidence || "NONE",
    country_converged: destination.country_converged !== false,
    country_source_count: Number(destination.country_source_count || 0),
    country_source: destination.country_source || "LOCAL",
  };
}
// Country markers are based only on backend metadata from local sources. A
// domain suffix is not evidence of endpoint location. The backend may retain
// its deterministic best match when local sources disagree.
function networkCountrySignal(destination) {
  const object = destination && typeof destination === "object" ? destination : {};
  const value = object.country_code;
  const code = /^[a-z]{2}$/i.test(String(value || "")) ? String(value).toUpperCase() : "";
  const confidenceValue = String(object.country_confidence || "NONE").toUpperCase();
  const confidence = ["HIGH", "MEDIUM", "LOW", "VERY_LOW"].includes(confidenceValue) ? confidenceValue : code ? "MEDIUM" : "NONE";
  const source = String(object.country_source || (code ? "LOCAL" : "NONE")).toUpperCase();
  if (!code) return {code: "", label: copy("network.activity.country.unknown"), confidence, source, converged: false, flag: ""};
  let label = code;
  try {
    label = new Intl.DisplayNames([i18n.locale || "en"], {type: "region"}).of(code) || code;
  } catch (_) { /* Older WebViews can still show the ISO code in the tooltip. */ }
  return {code, label, confidence, source, converged: object.country_converged !== false};
}
function networkCountryFlagSvg(code) {
  const flags = {
    UN: '<svg class="network-country-flag-art" data-country="UN" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" rx="2" fill="#164E63"/><circle cx="15" cy="10" r="6" fill="none" stroke="#BAE6FD" stroke-width="1.2"/><path d="M9 10h12M15 4c2 2 3 4 3 6s-1 4-3 6c-2-2-3-4-3-6s1-4 3-6zM10.2 6.2c2 1 7 1 9.6 0M10.2 13.8c2-1 7-1 9.6 0" fill="none" stroke="#BAE6FD" stroke-width=".7"/></svg>',
    FR: '<svg class="network-country-flag-art" data-country="FR" viewBox="0 0 30 20" aria-hidden="true"><rect width="10" height="20" fill="#0055A4"/><rect x="10" width="10" height="20" fill="#FFF"/><rect x="20" width="10" height="20" fill="#EF4135"/></svg>',
    DE: '<svg class="network-country-flag-art" data-country="DE" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="6.67" fill="#000"/><rect y="6.67" width="30" height="6.66" fill="#DD0000"/><rect y="13.33" width="30" height="6.67" fill="#FFCE00"/></svg>',
    GB: '<svg class="network-country-flag-art" data-country="GB" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#012169"/><path d="M0 0 30 20M30 0 0 20" stroke="#FFF" stroke-width="4"/><path d="M0 0 30 20M30 0 0 20" stroke="#C8102E" stroke-width="1.8"/><path d="M15 0v20M0 10h30" stroke="#FFF" stroke-width="6"/><path d="M15 0v20M0 10h30" stroke="#C8102E" stroke-width="3"/></svg>',
    US: '<svg class="network-country-flag-art" data-country="US" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#FFF"/><path d="M0 0h30v2H0zm0 4h30v2H0zm0 4h30v2H0zm0 4h30v2H0zm0 4h30v2H0z" fill="#B22234"/><rect width="13" height="11" fill="#3C3B6E"/></svg>',
    CA: '<svg class="network-country-flag-art" data-country="CA" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#FFF"/><rect width="7.5" height="20" fill="#D80621"/><rect x="22.5" width="7.5" height="20" fill="#D80621"/><path d="m15 3 1.2 4 3-.8-1.3 2.7 2.5 1.6-3.1.4.2 3.1-2.5-2-2.5 2 .2-3.1-3.1-.4 2.5-1.6-1.3-2.7 3 .8z" fill="#D80621"/></svg>',
    IT: '<svg class="network-country-flag-art" data-country="IT" viewBox="0 0 30 20" aria-hidden="true"><rect width="10" height="20" fill="#009246"/><rect x="10" width="10" height="20" fill="#FFF"/><rect x="20" width="10" height="20" fill="#CE2B37"/></svg>',
    ES: '<svg class="network-country-flag-art" data-country="ES" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#AA151B"/><rect y="5" width="30" height="10" fill="#F1BF00"/></svg>',
    BE: '<svg class="network-country-flag-art" data-country="BE" viewBox="0 0 30 20" aria-hidden="true"><rect width="10" height="20" fill="#000"/><rect x="10" width="10" height="20" fill="#FFD90C"/><rect x="20" width="10" height="20" fill="#EF3340"/></svg>',
    NL: '<svg class="network-country-flag-art" data-country="NL" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="6.67" fill="#AE1C28"/><rect y="6.67" width="30" height="6.66" fill="#FFF"/><rect y="13.33" width="30" height="6.67" fill="#21468B"/></svg>',
    CH: '<svg class="network-country-flag-art" data-country="CH" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" rx="2" fill="#D52B1E"/><path d="M12 4h6v5h5v5h-5v5h-6v-5H7V9h5z" fill="#FFF"/></svg>',
    RU: '<svg class="network-country-flag-art" data-country="RU" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="6.67" fill="#FFF"/><rect y="6.67" width="30" height="6.66" fill="#0039A6"/><rect y="13.33" width="30" height="6.67" fill="#D52B1E"/></svg>',
    JP: '<svg class="network-country-flag-art" data-country="JP" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#FFF"/><circle cx="15" cy="10" r="6" fill="#BC002D"/></svg>',
    CN: '<svg class="network-country-flag-art" data-country="CN" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#DE2910"/><path d="m6 3 1 2.1 2.3.2-1.7 1.5.5 2.2L6 7.8 3.9 9l.5-2.2-1.7-1.5L5 5.1z" fill="#FFDE00"/></svg>',
    IN: '<svg class="network-country-flag-art" data-country="IN" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="6.67" fill="#FF9933"/><rect y="6.67" width="30" height="6.66" fill="#FFF"/><rect y="13.33" width="30" height="6.67" fill="#138808"/><circle cx="15" cy="10" r="2.1" fill="none" stroke="#000080" stroke-width=".7"/></svg>',
    BR: '<svg class="network-country-flag-art" data-country="BR" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#009B3A"/><path d="m15 2 12 8-12 8L3 10z" fill="#FFDF00"/><circle cx="15" cy="10" r="4.5" fill="#002776"/></svg>',
    MX: '<svg class="network-country-flag-art" data-country="MX" viewBox="0 0 30 20" aria-hidden="true"><rect width="10" height="20" fill="#006847"/><rect x="10" width="10" height="20" fill="#FFF"/><rect x="20" width="10" height="20" fill="#CE1126"/><circle cx="15" cy="10" r="1.6" fill="#8B5A2B"/></svg>',
    PL: '<svg class="network-country-flag-art" data-country="PL" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="10" fill="#FFF"/><rect y="10" width="30" height="10" fill="#DC143C"/></svg>',
    KR: '<svg class="network-country-flag-art" data-country="KR" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#FFF"/><circle cx="15" cy="10" r="4.6" fill="#CD2E3A"/><path d="M15 10a4.6 4.6 0 0 1 0-9.2 2.3 2.3 0 0 0 0 4.6 2.3 2.3 0 0 1 0 4.6z" fill="#0047A0"/></svg>',
    IL: '<svg class="network-country-flag-art" data-country="IL" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#FFF"/><path d="M0 3h30v3H0zM0 14h30v3H0z" fill="#0038B8"/><path d="m15 6 3.5 6h-7zM15 14 11.5 8h7z" fill="none" stroke="#0038B8" stroke-width=".8"/></svg>',
  };
  return flags[code] || `<svg class="network-country-flag-art network-country-flag-code" data-country="${esc(code)}" viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#334155"/><text x="15" y="13" text-anchor="middle" fill="#FFF" font-size="8" font-family="sans-serif" font-weight="700">${esc(code)}</text></svg>`;
}
function networkCountryFlag(destination) {
  const signal = networkCountrySignal(destination);
  let label = copy("network.activity.country.unknown");
  if (signal.code) {
    const confidence = copy(`network.activity.country.confidence.${signal.confidence.toLowerCase()}`);
    if (signal.source === "DOMAIN_SUFFIX") {
      label = copy("network.activity.country.domainHint", {country: signal.label}) + ` · ${confidence}`;
    } else {
      const base = copy("network.activity.country.inferred", {country: signal.label});
      label = signal.converged || signal.confidence !== "LOW"
        ? `${base} · ${confidence}`
        : copy("network.activity.country.conflict", {country: signal.label, confidence});
    }
  }
  const visual = signal.code ? networkCountryFlagSvg(signal.code) : networkCountryFlagSvg("UN");
  return `<span class="network-country-flag${signal.code ? "" : " network-country-flag-unknown"}" role="img" aria-label="${esc(label)}" title="${esc(label)}">${visual}</span>`;
}
function networkDestinationIdentity(host) {
  const destination = host && typeof host === "object" ? host : {host};
  return `${networkIdentityMark("destination", destination.host)}${networkCountryFlag(destination)}`;
}
function networkActivityMeta(item) {
  const destination = networkActivityDestination(item);
  const protocol = String(item?.protocol || "").trim().toUpperCase();
  const meta = [];
  if (protocol) meta.push(protocol);
  if (destination.port) meta.push(copy("network.activity.portValue", {port: destination.port}));
  return meta.join(" · ") || copy("network.activity.detailsUnavailable");
}
function networkActivityFiltersAreDefault() {
  const filters = networkActivityState.filters;
  return filters.search === DEFAULT_NETWORK_ACTIVITY_FILTERS.search
    && filters.decision === DEFAULT_NETWORK_ACTIVITY_FILTERS.decision
    && filters.protocol === DEFAULT_NETWORK_ACTIVITY_FILTERS.protocol
    && filters.port === DEFAULT_NETWORK_ACTIVITY_FILTERS.port
    && filters.window === DEFAULT_NETWORK_ACTIVITY_FILTERS.window;
}
function networkActivitySource() {
  return networkActivityState.mode === "history" ? networkActivityState.historyEvents : networkActivityState.events;
}
function networkActivityProtocols() {
  const protocols = new Set(networkActivitySource().map((item) => String(item.protocol || "").toUpperCase()).filter(Boolean));
  if (networkActivityState.filters.protocol !== "ALL") protocols.add(networkActivityState.filters.protocol);
  return [...protocols].sort();
}
function networkActivityStatusText() {
  if (networkActivityState.mode === "history") return copy("network.activity.boundedHistory");
  const status = networkActivityState.paused ? copy("network.activity.updatesPaused") : copy("network.activity.updating");
  return networkActivityState.pending ? `${status} · ${copy("network.activity.newEvents", {count: networkActivityState.pending})}` : status;
}
function networkActivityProtocolOptionsMarkup(protocols) {
  return `<option value="ALL">${esc(copy("network.activity.protocol.all"))}</option>${protocols.map((protocol) => `<option value="${esc(protocol)}"${networkActivityState.filters.protocol === protocol ? " selected" : ""}>${esc(protocol)}</option>`).join("")}`;
}
function networkActivityToolbarMarkup() {
  const filters = networkActivityState.filters;
  const windowControl = networkActivityState.mode === "history" ? `<label><span class="sr-only">${esc(copy("network.activity.historyRange"))}</span><select data-activity-window><option value="30m"${filters.window === "30m" ? " selected" : ""}>${esc(copy("network.activity.range.thirtyMinutes"))}</option><option value="6h"${filters.window === "6h" ? " selected" : ""}>${esc(copy("network.activity.range.sixHours"))}</option><option value="24h"${filters.window === "24h" ? " selected" : ""}>${esc(copy("network.activity.range.twentyFourHours"))}</option><option value="7d"${filters.window === "7d" ? " selected" : ""}>${esc(copy("network.activity.range.sevenDays"))}</option></select></label>` : "";
  const mode = `<div class="activity-mode" role="group" aria-label="${esc(copy("network.activity.mode"))}"><button class="text-button ${networkActivityState.mode === "live" ? "active" : ""}" data-activity-mode="live" aria-pressed="${networkActivityState.mode === "live" ? "true" : "false"}">${esc(copy("network.activity.live"))}</button><button class="text-button ${networkActivityState.mode === "history" ? "active" : ""}" data-activity-mode="history" aria-pressed="${networkActivityState.mode === "history" ? "true" : "false"}">${esc(copy("network.activity.history"))}</button></div>`;
  return `<div class="network-activity-toolbar" data-activity-toolbar data-activity-mode-state="${esc(networkActivityState.mode)}">${mode}<label class="network-activity-search"><span class="sr-only">${esc(copy("network.activity.search"))}</span><input type="search" data-activity-search placeholder="${esc(copy("network.activity.searchPlaceholder"))}" value="${esc(filters.search)}"></label><label><span class="sr-only">${esc(copy("network.activity.decision"))}</span><select data-activity-decision><option value="ALL">${esc(copy("network.activity.decision.all"))}</option><option value="ALLOWED"${filters.decision === "ALLOWED" ? " selected" : ""}>${esc(copy("network.activity.decision.allowed"))}</option><option value="BLOCKED"${filters.decision === "BLOCKED" ? " selected" : ""}>${esc(copy("network.activity.decision.blocked"))}</option><option value="UNKNOWN"${filters.decision === "UNKNOWN" ? " selected" : ""}>${esc(copy("network.activity.decision.unknown"))}</option></select></label><label><span class="sr-only">${esc(copy("network.activity.protocol"))}</span><select data-activity-protocol>${networkActivityProtocolOptionsMarkup(networkActivityProtocols())}</select></label><label><span class="sr-only">${esc(copy("network.activity.detail.port"))}</span><input inputmode="numeric" data-activity-port placeholder="${esc(copy("network.activity.detail.port"))}" value="${esc(filters.port)}"></label>${windowControl}<button class="text-button" type="button" data-activity-clear${networkActivityFiltersAreDefault() ? " disabled" : ""}>${esc(copy("network.activity.clearFilters"))}</button><span class="network-activity-toolbar-status" data-activity-status role="status" aria-live="polite" aria-atomic="true">${esc(networkActivityStatusText())}</span></div>`;
}
function syncNetworkActivityControls() {
  if (currentPage !== "activity") return;
  const pauseButton = app.querySelector("[data-activity-pause]");
  if (pauseButton) {
    const label = copy(networkActivityState.paused ? "network.activity.resume" : "network.activity.pause");
    const iconSlot = pauseButton.querySelector(".action-icon");
    const labelSlot = pauseButton.querySelector(".action-label");
    if (iconSlot) iconSlot.innerHTML = icon(networkActivityState.paused ? "arrow" : "activity");
    if (labelSlot) labelSlot.textContent = label;
    pauseButton.title = copy("network.activity.pauseDetail");
    pauseButton.setAttribute("aria-pressed", String(networkActivityState.paused));
  }
  const toolbar = app.querySelector("[data-activity-toolbar]");
  if (!toolbar) return;
  if (toolbar.dataset.activityModeState !== networkActivityState.mode) {
    toolbar.outerHTML = networkActivityToolbarMarkup();
    bindNetworkActivityContent();
    return;
  }
  const filters = networkActivityState.filters;
  const search = toolbar.querySelector("[data-activity-search]");
  const decision = toolbar.querySelector("[data-activity-decision]");
  const protocol = toolbar.querySelector("[data-activity-protocol]");
  const port = toolbar.querySelector("[data-activity-port]");
  const windowControl = toolbar.querySelector("[data-activity-window]");
  if (search && search.value !== filters.search) search.value = filters.search;
  if (decision && decision.value !== filters.decision) decision.value = filters.decision;
  if (protocol) {
    const options = networkActivityProtocolOptionsMarkup(networkActivityProtocols());
    if (networkActivityState.renderedProtocolOptions !== options) {
      protocol.innerHTML = options;
      networkActivityState.renderedProtocolOptions = options;
    }
    if (protocol.value !== filters.protocol) protocol.value = filters.protocol;
  }
  if (port && port.value !== filters.port) port.value = filters.port;
  if (windowControl && windowControl.value !== filters.window) windowControl.value = filters.window;
  toolbar.querySelectorAll("[data-activity-mode]").forEach((button) => {
    const active = button.dataset.activityMode === networkActivityState.mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const clear = toolbar.querySelector("[data-activity-clear]");
  if (clear) clear.disabled = networkActivityFiltersAreDefault();
  const statusElement = toolbar.querySelector("[data-activity-status]");
  if (statusElement) statusElement.textContent = networkActivityStatusText();
}
function networkActivityMatches(item) {
  const destination = networkActivityDestination(item);
  const search = networkActivityState.filters.search.trim().toLowerCase();
  const haystack = [item.application, item.executable, destination.host, destination.ip, item.protocol, item.rule_name, item.source].join(" ").toLowerCase();
  if (search && !haystack.includes(search)) return false;
  if (networkActivityState.filters.decision !== "ALL" && item.decision !== networkActivityState.filters.decision) return false;
  if (networkActivityState.filters.protocol !== "ALL" && String(item.protocol || "").toUpperCase() !== networkActivityState.filters.protocol) return false;
  if (networkActivityState.filters.port && String(destination.port) !== networkActivityState.filters.port) return false;
  return true;
}
function activityDecisionClass(value) {
  return String(value || "UNKNOWN").toLowerCase();
}
function networkActivityDecisionLabel(value) {
  const labels = {ALLOWED: "network.activity.decision.allowed", BLOCKED: "network.activity.decision.blocked", UNKNOWN: "network.activity.decision.unknown"};
  return copy(labels[String(value || "UNKNOWN").toUpperCase()] || "network.activity.decision.unknown");
}
function networkActivityRowMarkup(item) {
  const eventId = String(item.event_id || `event-${item.sequence || "unknown"}`);
  const expanded = networkActivityState.expanded.has(eventId);
  const destination = networkActivityDestination(item);
  const decision = String(item.decision || "UNKNOWN").toUpperCase();
  const mutationAvailable = networkActivityState.mutationAvailable && Boolean(item.executable);
  const dnsBypass = mutationAvailable && [53, 853].includes(Number(destination.port));
  const actions = mutationAvailable && (destination.host || destination.ip) ? `<div class="network-activity-actions"><button class="text-button" data-network-set data-application="${esc(item.executable)}" data-network-host="${esc(destination.host || "")}" data-network-ip="${esc(destination.ip || "")}" data-network-port="${esc(destination.port || "")}" data-network-action="allow">${esc(copy("network.protection.alwaysAllow"))} ${icon("arrow")}</button>${dnsBypass ? `<button class="text-button" data-network-set data-network-dns-bypass="true" data-application="${esc(item.executable)}" data-network-port="${esc(destination.port || "")}" data-network-action="allow">${esc(copy("network.protection.allowDnsBypass"))} ${icon("arrow")}</button>` : ""}<button class="text-button" data-network-set data-application="${esc(item.executable)}" data-network-host="${esc(destination.host || "")}" data-network-ip="${esc(destination.ip || "")}" data-network-port="${esc(destination.port || "")}" data-network-action="deny">${esc(copy("network.protection.alwaysBlock"))} ${icon("arrow")}</button></div>` : "";
  const occurredAt = localizedTime(item.occurred_at, copy("network.activity.unknownTime"));
  const destinationDetail = `<span class="network-activity-destination-detail">${networkCountryFlag(destination)}<span>${esc(destination.host)}${destination.ip && destination.host !== destination.ip ? ` · ${esc(destination.ip)}` : ""}</span></span>`;
  const details = `<div class="network-activity-details"${expanded ? "" : " hidden"}><div><span>${esc(copy("network.activity.detail.destination"))}</span><strong>${destinationDetail}</strong></div><div><span>${esc(copy("network.activity.detail.protocol"))}</span><strong>${esc(String(item.protocol || copy("network.activity.unknown")).toUpperCase())}</strong></div><div><span>${esc(copy("network.activity.detail.port"))}</span><strong>${esc(destination.port || copy("network.activity.unknown"))}</strong></div><div><span>${esc(copy("network.activity.detail.rule"))}</span><strong>${esc(item.rule_name || copy("network.activity.noMatchedRule"))}</strong></div><div><span>${esc(copy("network.activity.detail.source"))}</span><strong>${esc(item.source || copy("network.activity.unknown"))}</strong></div><div><span>${esc(copy("network.activity.detail.observed"))}</span><strong>${esc(occurredAt)}</strong></div>${actions}</div>`;
  return `<article class="network-activity-row${expanded ? " is-expanded" : ""}" data-activity-event="${esc(eventId)}"><button class="network-activity-row-main" type="button" data-activity-toggle="${esc(eventId)}" aria-expanded="${expanded ? "true" : "false"}"><span class="network-activity-identity network-activity-application">${networkIdentityMark("application", [item.application, item.executable])}<strong>${esc(item.application || copy("network.protection.unknownApplication"))}</strong></span><span class="network-activity-identity network-activity-destination">${networkDestinationIdentity(destination)}<strong>${esc(destination.host)}</strong></span><span class="network-decision ${activityDecisionClass(decision)}">${esc(networkActivityDecisionLabel(decision))}</span><span class="network-activity-meta">${esc(networkActivityMeta(item))}</span><time>${esc(occurredAt)}</time><span class="network-activity-expand" aria-hidden="true">${icon("chevron")}</span></button>${details}</article>`;
}
function networkActivityRowsMarkup() {
  const source = networkActivitySource();
  const events = source.filter(networkActivityMatches);
  if (networkActivityState.mode === "history" && networkActivityState.historyState !== "AVAILABLE") return emptyState(copy("network.activity.historyUnavailable"), copy("network.activity.historyUnavailableCopy"), "activity");
  if (!events.length) return emptyState(source.length ? copy("network.activity.noMatch") : networkActivityState.mode === "history" ? copy("network.activity.noHistory") : copy("network.activity.noRecent"), source.length ? copy("network.activity.noMatchCopy") : copy("network.activity.noRecentCopy"), "activity");
  const visible = networkActivityState.mode === "history" ? events : events.slice(0, 120);
  const note = networkActivityState.mode === "live" && events.length > visible.length ? `<p class="network-activity-window-note">${esc(copy("network.activity.newestCount", {shown: visible.length, total: events.length}))}</p>` : "";
  const more = networkActivityState.mode === "history" && networkActivityState.historyCursor
    ? `<div class="network-activity-more">${actionButton(copy("network.activity.loadOlder"), copy("network.activity.loadOlderDetail"), "secondary", "data-activity-load-more", "arrow")}</div>`
    : "";
  return visible.map(networkActivityRowMarkup).join("") + note + more;
}
function networkActivitySummaryMarkup() {
  const summary = networkActivityState.summary || {};
  const buckets = Array.isArray(summary.buckets) ? summary.buckets : [];
  const peak = Math.max(1, ...buckets.map((bucket) => Number(bucket.total || 0)));
  const bars = buckets.slice(-30).map((bucket) => `<span style="height:${Math.max(8, Math.round((Number(bucket.total || 0) / peak) * 100))}%" title="${esc(copy("network.activity.observedEvents", {count: bucket.total || 0}))}"></span>`).join("");
  const state = String(networkActivityState.state || "UNAVAILABLE").toUpperCase();
  const headline = state === "OPERATING" ? copy("network.activity.state.active") : state === "DEGRADED" ? copy("network.activity.state.delayed") : copy("network.activity.state.unavailable");
  const detail = state === "OPERATING" ? copy("network.activity.detail.operating") : networkActivityState.detail || copy("network.activity.detail.unavailable");
  return `<section class="network-activity-summary"><article class="network-activity-health"><div class="eyebrow">${esc(copy("network.activity.observation"))}</div><h2>${esc(headline)}</h2><p>${esc(detail)}</p>${status(headline, state === "OPERATING" ? "positive" : state === "DEGRADED" ? "review" : "unknown")}</article><article class="network-summary-card"><span>${esc(copy("network.activity.observed"))}</span><strong>${esc(summary.total || 0)}</strong><small>${esc(copy("network.activity.lastThirtyMinutes"))}</small></article><article class="network-summary-card"><span>${esc(copy("network.activity.decision.allowed"))}</span><strong>${esc(summary.allowed || 0)}</strong><small>${esc(copy("network.activity.observedDecisions"))}</small></article><article class="network-summary-card"><span>${esc(copy("network.activity.decision.blocked"))}</span><strong>${esc(summary.blocked || 0)}</strong><small>${esc(copy("network.activity.observedDecisions"))}</small></article><article class="network-activity-chart"><div><span>${esc(copy("network.activity.rhythm"))}</span><small>${esc(copy("network.activity.boundedWindow"))}</small></div><div class="network-activity-sparkline" aria-label="${esc(copy("network.activity.chartLabel"))}">${bars || "<span style=\"height:8%\"></span>"}</div></article></section>`;
}
function networkActivityLegendMarkup() {
  return `<div class="network-activity-legend" aria-label="${esc(copy("network.activity.legend"))}"><span class="network-activity-legend-key"><span class="network-activity-identity">${networkIdentityMark("application", "Application")}<span>${esc(copy("network.activity.legend.application"))}</span></span></span><span class="network-activity-legend-key"><span class="network-activity-identity">${networkDestinationIdentity({host: copy("network.activity.legend.destination"), country_code: ""})}<span>${esc(copy("network.activity.legend.destination"))}</span></span></span><span class="network-activity-legend-note">${esc(copy("network.activity.locationNote"))}</span></div>`;
}
function syncNetworkActivityData(payload, {trackPending = false} = {}) {
  if (!payload || typeof payload !== "object") return;
  const sessionId = payload.session_id || null;
  const hadSession = Boolean(networkActivityState.sessionId);
  const sessionChanged = Boolean(networkActivityState.sessionId && sessionId && networkActivityState.sessionId !== sessionId);
  const incoming = Array.isArray(payload.events) ? payload.events.filter((event) => event && event.event_id) : [];
  let addedCount = 0;
  if (!networkActivityState.sessionId || sessionChanged || payload.reset) {
    addedCount = incoming.length;
    networkActivityState.events = incoming;
    if (sessionChanged) networkActivityState.expanded.clear();
    networkActivityState.pending = trackPending && hadSession && networkActivityState.paused ? addedCount : 0;
  } else {
    const events = new Map(networkActivityState.events.map((event) => [event.event_id, event]));
    incoming.forEach((event) => {
      if (!events.has(event.event_id)) addedCount += 1;
      events.set(event.event_id, event);
    });
    networkActivityState.events = [...events.values()].sort((left, right) => Number(right.sequence || 0) - Number(left.sequence || 0)).slice(0, 4096);
    if (trackPending && networkActivityState.paused) networkActivityState.pending += addedCount;
  }
  networkActivityState.sessionId = sessionId;
  networkActivityState.nextSequence = Number(payload.next_sequence || networkActivityState.nextSequence || 0);
  networkActivityState.summary = payload.summary || networkActivityState.summary;
  networkActivityState.state = payload.state || "UNAVAILABLE";
  networkActivityState.detail = payload.detail || copy("network.activity.detail.unavailable");
  networkActivityState.mutationAvailable = payload.rule_mutation === "TYPED_POLICY";
  networkActivityState.expanded = new Set([...networkActivityState.expanded].filter((id) => networkActivityState.events.some((event) => event.event_id === id)));
  return addedCount;
}
function renderNetworkActivityView({renderRows = true} = {}) {
  if (currentPage !== "activity") return;
  const active = document.activeElement;
  const list = app.querySelector("[data-network-activity-list]");
  const listMarkup = networkActivityRowsMarkup();
  if (renderRows && list && !list.contains(active) && listMarkup !== networkActivityState.renderedListMarkup) {
    const scrollPosition = readPageScrollPosition();
    list.innerHTML = listMarkup;
    networkActivityState.renderedListMarkup = listMarkup;
    applyPageScroll(scrollPosition);
    bindNetworkActivityContent();
  }
  const summary = app.querySelector(".network-activity-summary");
  const summaryMarkup = networkActivitySummaryMarkup();
  if (summary && summaryMarkup !== networkActivityState.renderedSummaryMarkup) {
    summary.outerHTML = summaryMarkup;
    networkActivityState.renderedSummaryMarkup = summaryMarkup;
  }
  syncNetworkActivityControls();
}
async function refreshNetworkActivity() {
  if (networkActivityState.mode !== "live" || networkActivityState.requestBusy || currentPage !== "activity" || document.hidden) return;
  networkActivityState.requestBusy = true;
  try {
    const result = await invokeBounded("get_network_activity", {sinceSequence: networkActivityState.nextSequence, limit: 256}, 10000);
    syncNetworkActivityData(result, {trackPending: true});
    renderNetworkActivityView({renderRows: !networkActivityState.paused});
  } catch (error) {
    networkActivityState.state = "UNAVAILABLE";
    networkActivityState.detail = actionError(error, copy("network.activity.refreshAction"));
    if (!networkActivityState.paused) renderNetworkActivityView();
  } finally {
    networkActivityState.requestBusy = false;
  }
}
async function loadNetworkHistory(expectedSequence = null, append = false) {
  const querySequence = expectedSequence ?? ++historyQuerySequence;
  const filters = networkActivityState.filters;
  const queryFilters = {...filters};
  const seconds = queryFilters.window === "7d" ? 604800 : queryFilters.window === "24h" ? 86400 : queryFilters.window === "6h" ? 21600 : 1800;
  const from = new Date(Date.now() - seconds * 1000).toISOString();
  try {
    const cursor = append ? networkActivityState.historyCursor : null;
    if (append && !cursor) return;
    const filters = {from, limit: NETWORK_HISTORY_PAGE_SIZE, cursor: cursor || undefined, decision: queryFilters.decision === "ALL" ? undefined : queryFilters.decision, protocol: queryFilters.protocol === "ALL" ? undefined : queryFilters.protocol, port: queryFilters.port || undefined, search: queryFilters.search || undefined};
    const result = await invokeBounded("get_network_history", {filters}, 12000);
    if (querySequence !== historyQuerySequence || currentPage !== "activity" || networkActivityState.mode !== "history") return;
    const incoming = Array.isArray(result?.events) ? result.events : [];
    if (append) {
      const events = new Map(networkActivityState.historyEvents.map((event) => [event.event_id, event]));
      incoming.forEach((event) => events.set(event.event_id, event));
      networkActivityState.historyEvents = [...events.values()];
    } else {
      networkActivityState.historyEvents = incoming;
    }
    networkActivityState.historyCursor = result?.next_cursor || null;
    networkActivityState.historyState = result?.source_state?.state || "AVAILABLE";
  } catch (error) {
    if (querySequence !== historyQuerySequence || currentPage !== "activity" || networkActivityState.mode !== "history") return;
    if (append) {
      networkActivityState.historyCursor = null;
    } else {
      networkActivityState.historyEvents = [];
      networkActivityState.historyCursor = null;
      networkActivityState.historyState = "UNAVAILABLE";
    }
  }
  renderNetworkActivityView();
}
function scheduleNetworkHistoryLoad() {
  if (historyQueryTimer) window.clearTimeout(historyQueryTimer);
  const querySequence = ++historyQuerySequence;
  historyQueryTimer = window.setTimeout(() => {
    historyQueryTimer = null;
    loadNetworkHistory(querySequence);
  }, HISTORY_QUERY_DEBOUNCE_MS);
}
function cancelNetworkHistoryLoad() {
  if (historyQueryTimer) window.clearTimeout(historyQueryTimer);
  historyQueryTimer = null;
  historyQuerySequence += 1;
}
function bindNetworkActivityContent() {
  const bindOnce = (element, event, handler) => {
    if (!element || element.dataset.activityBound === "true") return;
    element.dataset.activityBound = "true";
    element.addEventListener(event, handler);
  };
  bindOnce(app.querySelector("[data-activity-search]"), "input", (event) => { networkActivityState.filters.search = event.currentTarget.value; if (networkActivityState.mode === "history") scheduleNetworkHistoryLoad(); else renderNetworkActivityView(); });
  bindOnce(app.querySelector("[data-activity-decision]"), "change", (event) => { networkActivityState.filters.decision = event.currentTarget.value; if (networkActivityState.mode === "history") loadNetworkHistory(); else renderNetworkActivityView(); });
  bindOnce(app.querySelector("[data-activity-protocol]"), "change", (event) => { networkActivityState.filters.protocol = event.currentTarget.value; if (networkActivityState.mode === "history") loadNetworkHistory(); else renderNetworkActivityView(); });
  bindOnce(app.querySelector("[data-activity-port]"), "input", (event) => { networkActivityState.filters.port = event.currentTarget.value.replace(/[^0-9]/g, ""); event.currentTarget.value = networkActivityState.filters.port; if (networkActivityState.mode === "history") scheduleNetworkHistoryLoad(); else renderNetworkActivityView(); });
  bindOnce(app.querySelector("[data-activity-window]"), "change", (event) => { networkActivityState.filters.window = event.currentTarget.value; loadNetworkHistory(); });
  bindOnce(app.querySelector("[data-activity-clear]"), "click", () => { networkActivityState.filters = networkActivityDefaultFilters(); if (networkActivityState.mode === "history") loadNetworkHistory(); else renderNetworkActivityView(); });
  app.querySelectorAll("[data-activity-mode]").forEach((button) => bindOnce(button, "click", async (event) => { networkActivityState.mode = event.currentTarget.dataset.activityMode; if (networkActivityState.mode === "history") await loadNetworkHistory(); else { cancelNetworkHistoryLoad(); renderNetworkActivityView(); } }));
  bindOnce(app.querySelector("[data-activity-load-more]"), "click", () => loadNetworkHistory(historyQuerySequence, true));
  bindOnce(app.querySelector("[data-activity-pause]"), "click", () => { networkActivityState.paused = !networkActivityState.paused; if (!networkActivityState.paused) networkActivityState.pending = 0; renderNetworkActivityView({renderRows: true}); });
  app.querySelectorAll("[data-network-set]").forEach((button) => bindOnce(button, "click", () => setNetworkRule(button)));
  app.querySelectorAll("[data-threat-exception]").forEach((button) => bindOnce(button, "click", () => setThreatException(button)));
  app.querySelectorAll("[data-threat-toggle]").forEach((button) => bindOnce(button, "click", () => setThreatProtectionEnabled(button)));
  app.querySelectorAll("[data-activity-toggle]").forEach((button) => bindOnce(button, "click", () => {
    const id = button.dataset.activityToggle;
    const expanded = networkActivityState.expanded.has(id);
    if (expanded) networkActivityState.expanded.delete(id); else networkActivityState.expanded.add(id);
    const row = button.closest("[data-activity-event]");
    const details = row?.querySelector(".network-activity-details");
    if (details) details.hidden = expanded;
    row?.classList.toggle("is-expanded", !expanded);
    button.setAttribute("aria-expanded", String(!expanded));
    renderNetworkActivityView();
  }));
}
function networkActivityMarkup(data) {
  syncNetworkActivityData(data);
  const pauseLabel = networkActivityState.paused ? copy("network.activity.resume") : copy("network.activity.pause");
  return `${pageHeader(copy("network.activity.eyebrow"), copy("network.activity.title"), copy("network.activity.copy"), actionButton(pauseLabel, copy("network.activity.pauseDetail"), "secondary", `data-activity-pause aria-pressed="${networkActivityState.paused ? "true" : "false"}"`, networkActivityState.paused ? "arrow" : "activity") + actionButton(copy("ui.refresh"), copy("network.activity.refreshDetail"), "secondary", "data-refresh", "refresh"))}${networkActivitySummaryMarkup()}<section class="plain-section network-activity-workspace">${networkActivityToolbarMarkup()}${networkActivityLegendMarkup()}<div class="network-activity-list" data-network-activity-list>${networkActivityRowsMarkup()}</div></section><div class="network-action-status" id="network-action-status" role="status" aria-live="polite">${esc(networkActionState.feedback || "")}</div>`;
}
function applicationAccessLabel(value) {
  const labels = {
    SCOPED: "applications.access.scoped", NETWORK: "applications.access.network", PERSONAL_FILES: "applications.access.personalFiles",
    HOST_FILES: "applications.access.hostFiles", DEVICES: "applications.access.devices", ALL_DEVICES: "applications.access.allDevices",
    DESKTOP_SERVICES: "applications.access.desktopServices",
  };
  return copy(labels[String(value || "SCOPED").toUpperCase()] || "applications.access.scoped");
}
function applicationsMarkup(data) {
  const rows = [...(data.apps || [])].sort((a, b) => Number(b.access_state === "REVIEW_NEEDED") - Number(a.access_state === "REVIEW_NEEDED"));
  const total = Number(data.inventory_total ?? rows.length);
  const shown = Number(data.shown_count ?? rows.length);
  const reviewNeeded = Number(data.review_needed_count ?? rows.filter((item) => item.access_state === "REVIEW_NEEDED").length);
  const inventoryState = String(data.inventory_state || (rows.length ? "AVAILABLE" : "UNAVAILABLE")).toUpperCase();
  const inventory = rows.length ? `<div class="inventory-list">${rows.map((item) => {
    const reportedCategories = Array.isArray(item.access_categories) && item.access_categories.length ? item.access_categories : null;
    const access = reportedCategories ? reportedCategories.map(applicationAccessLabel).join(" · ") : copy("applications.access.unavailable");
    const review = Array.isArray(item.review_reasons) ? item.review_reasons.map(applicationAccessLabel) : [];
    const technical = item.technical || {};
    const rawPermissions = [...(technical.manifest_permissions || []), ...(technical.local_overrides || [])];
    const detail = `<p>${esc(copy("applications.technical.identifier"))}: <code>${esc(technical.app_id || copy("ui.unavailable"))}</code></p><p>${esc(copy("applications.technical.scope"))}: ${esc(technical.scope || copy("ui.unavailable"))}</p><p>${esc(copy("applications.technical.source"))}: ${esc(technical.origin || copy("ui.unavailable"))} · ${esc(technical.version || copy("ui.unavailable"))}</p><p>${esc(copy("applications.technical.runtime"))}: ${esc(technical.runtime || copy("ui.unavailable"))}</p><p>${esc(copy("applications.technical.permissions"))}: ${rawPermissions.length ? rawPermissions.map(esc).join(" · ") : esc(copy("applications.technical.none"))}</p>`;
    const reviewCopy = review.length ? copy("applications.review.copy", {access: review.join(", ")}) : reportedCategories ? copy("applications.scoped.copy") : copy("applications.access.unavailableCopy");
    const needsReview = item.access_state === "REVIEW_NEEDED";
    const stateCopy = needsReview ? copy("state.reviewNeeded") : reportedCategories ? copy("state.scoped") : copy("state.unavailable");
    return `<article class="inventory-row application-inventory-row" data-view-key="${esc(`${technical.app_id || item.name}:${technical.scope || ""}`)}"><div><strong>${esc(item.name || copy("applications.unnamed"))}</strong><span>${esc(access)}</span><small>${esc(reviewCopy)}</small></div><span class="${needsReview ? "risk-label" : reportedCategories ? "safe-label" : "risk-label"}">${esc(stateCopy)}</span>${technicalDisclosure(copy("ui.technical"), "", detail)}</article>`;
  }).join("")}</div>` : emptyState(
    inventoryState === "PARTIAL" ? copy("applications.partial.title") : inventoryState === "UNAVAILABLE" ? copy("applications.unavailable.title") : copy("applications.empty.title"),
    inventoryState === "PARTIAL" ? copy("applications.partial.copy") : inventoryState === "UNAVAILABLE" ? copy("applications.unavailable.copy") : copy("applications.empty.copy"),
    "applications",
  );
  const softwareAction = actionButton(copy("applications.openSoftware"), copy("applications.openSoftware.detail"), "primary", "data-open-software", "applications");
  const countLabel = inventoryState === "PARTIAL" ? copy("applications.inventory.partialCount", {shown}) : copy("applications.inventory.count", {shown, total});
  const reviewCopy = inventoryState === "PARTIAL" ? copy("applications.inventory.partialReview", {count: reviewNeeded}) : copy("applications.inventory.review", {count: reviewNeeded});
  return `${pageHeader(copy("applications.eyebrow"), copy("applications.title"), copy("applications.copy"), actionButton(copy("ui.refresh"), copy("applications.refresh.detail"), "secondary", "data-refresh", "refresh") + softwareAction)}<div id="applications-action-status" class="action-status" role="status" aria-live="polite"></div><section class="plain-section inventory-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("applications.inventory.eyebrow"))}</div><h2>${esc(countLabel)}</h2><p>${esc(reviewCopy)}</p></div></div>${inventory}</section>${technicalDisclosure(copy("design.applications.runtime"), "", `<div class="two-column">${plainSection(copy("applications.isolation.eyebrow"), copy("applications.isolation.title"), data.overview || [], "applications")}${plainSection(copy("applications.integration.eyebrow"), copy("applications.integration.title"), data.portal || [], "shield")}</div>`)}`;
}function recoveryTime(value) {
  if (!value) return copy("backup.time.notRecorded");
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], {dateStyle: "medium", timeStyle: "short"});
}
function backupProblemCopy(problem) {
  const labels = {
    CHECK_PASSPHRASE: "backup.problem.passphrase", CHECK_DESTINATION: "backup.problem.destination",
    TRY_LATER: "backup.problem.later", SERVICE_UNAVAILABLE: "backup.problem.unavailable", TRY_AGAIN: "backup.problem.retry",
    DESTINATION_IN_HOME: "backup.configure.choose", DESTINATION_INVALID: "backup.problem.destination",
    DESTINATION_NOT_WRITABLE: "backup.problem.destination", DESTINATION_NOT_MOUNTED: "backup.configure.choose",
    DESTINATION_MOUNT_VALIDATION: "backup.problem.destination", DESTINATION_MOUNT_PROVIDER: "backup.problem.destination",
    DESTINATION_IDENTITY_MISSING: "backup.configure.choose", DESTINATION_CHANGED: "backup.problem.destination",
    REPOSITORY_MISMATCH: "backup.problem.retry", REPOSITORY_INACCESSIBLE: "backup.problem.retry",
  };
  return copy(labels[String(problem || "TRY_AGAIN").toUpperCase()] || "backup.problem.retry");
}
function recoveryQueueItem(command, data) {
  const recovery = data.recovery_v1 || {};
  const points = Array.isArray(recovery.points) ? recovery.points : [];
  const backup = data.backup || {};
  const operation = backup.operation || {};
  const operationFor = (kind) => String(operation.kind || "").toUpperCase() === kind ? {
    state: String(operation.state || "READY").toUpperCase(),
    detail: (() => {
      const operationState = String(operation.state || "READY").toUpperCase();
      const label = kind === "VERIFY" ? copy("backup.verify") : kind === "RESTORE" ? copy("backup.restore") : copy("backup.now");
      if (operationState === "FAILED") return backupProblemCopy(operation.problem);
      if (operationState === "COMPLETED") return copy("backup.operation.completed", {kind: label});
      if (operationState === "PREPARING" || operationState === "QUEUED") return copy("backup.operation.preparing", {kind: label});
      return copy("backup.operation.active", {kind: label});
    })(),
  } : null;
  if (command === "create_recovery_point") {
    if (recovery.ok === false) return {state: "BLOCKED", detail: copy("backup.recovery.unavailable")};
    return points.some((point) => point.status === "valid") ? {state: "COMPLETED", detail: copy("backup.recovery.available")} : {state: "READY", detail: copy("backup.recovery.ready")};
  }
  if (command === "cleanup_recovery_points") {
    if (recovery.ok === false) return {state: "BLOCKED", detail: copy("backup.recovery.unavailable")};
    return {state: "READY", detail: points.length > 3 ? copy("backup.recovery.cleanupReady") : copy("backup.recovery.cleanupIdle")};
  }
  if (command === "configure_backup") {
    if (backup.ok === false) return {state: "BLOCKED", detail: copy("backup.configure.unavailable")};
    if (backup.configured === true && backup.destination_available === true) return {state: "COMPLETED", detail: copy("backup.configure.configured")};
    if (backup.configured === true) return {state: "BLOCKED", detail: backupProblemCopy(backup.destination_problem)};
    return {state: "READY", detail: copy("backup.configure.choose")};
  }
  if (command === "backup_now") {
    const current = operationFor("BACKUP"); if (current) return current;
    if (backup.configured !== true) return {state: "BLOCKED", detail: copy("backup.configure.required")};
    if (backup.destination_available !== true) return {state: "BLOCKED", detail: backupProblemCopy(backup.destination_problem)};
    if (backup.last_backup_status === "SUCCESSFUL") return {state: "COMPLETED", detail: backup.last_retention_status === "FAILED" ? copy("backup.latest.retentionRetry") : copy("backup.latest.completed")};
    if (backup.last_backup_status === "FAILED") return {state: "FAILED", detail: backupProblemCopy(backup.last_backup_problem)};
    return {state: "READY", detail: copy("backup.latest.ready")};
  }
  const current = operationFor("VERIFY"); if (current) return current;
  if (backup.configured !== true || backup.destination_available !== true) return {state: "BLOCKED", detail: backup.configured === true ? backupProblemCopy(backup.destination_problem) : copy("backup.configure.required")};
  if (backup.last_check_status === "VERIFIED") return {state: "COMPLETED", detail: copy("backup.verify.passed")};
  if (backup.last_check_status === "FAILED") return {state: "FAILED", detail: backupProblemCopy(backup.last_check_problem)};
  return {state: "READY", detail: copy("backup.verify.ready")};
}
function recoveryQueueMarkup(data) {
  const commands = Object.keys(recoveryOperationLabels).filter((command) => ["RUNNING", "PREPARING", "QUEUED"].includes(String(recoveryQueueItem(command, data).state).toUpperCase()));
  if (!commands.length) return "";
  const rows = commands.map((command) => {
    const [labelKey, descriptionKey] = recoveryOperationLabels[command];
    const label = copy(labelKey); const description = copy(descriptionKey);
    const item = recoveryQueueItem(command, data);
    const state = String(item.state || "READY").toUpperCase();
    const stateTone = state === "COMPLETED" ? "positive" : state === "FAILED" ? "critical" : state === "RUNNING" ? "uncertain" : state === "BLOCKED" ? "unknown" : "review";
    const progress = ["RUNNING", "PREPARING", "QUEUED"].includes(state) ? `<div class="recovery-operation-progress" role="progressbar" aria-label="${esc(copy("backup.queue.progress", {name: label}))}"><span></span></div>` : "";
    return `<article class="recovery-operation-row state-${state.toLowerCase()}" aria-label="${esc(label)}: ${esc(state)}"><span class="recovery-operation-copy"><strong>${esc(label)}</strong><small>${esc(description)}</small><em>${esc(item.detail || "")}</em></span><span class="recovery-operation-state">${status(state, stateTone)}</span>${progress}</article>`;
  }).join("");
  return `<section class="recovery-operation-queue"><div class="section-heading"><div><div class="eyebrow">${esc(copy("backup.queue.eyebrow"))}</div><h2>${esc(copy("backup.queue.title"))}</h2></div><span class="section-meta">${esc(copy("backup.queue.operations", {count: commands.length}))}</span></div><div class="recovery-operation-list">${rows}</div></section>`;
}
function recoveryMarkup(data) {
  const recovery = data.recovery_v1 || {};
  const recoveryUnavailable = recovery.ok === false;
  const points = recoveryUnavailable ? [] : (recovery.points || []);
  const backup = data.backup || {};
  const backupUnavailable = backup.ok === false;
  const backupDestinationUnavailable = !backupUnavailable && backup.configured === true && backup.destination_available === false;
  const backupReady = !backupUnavailable && backup.configured === true && backup.destination_available === true;
  const latest = points[0];
  const pointRows = points.length
    ? points.map((point) => `<article class="recovery-point-row"><div><strong>${esc(point.reason === "pre-update" ? copy("backup.recovery.point.preUpdate") : copy("backup.recovery.point.manual"))}</strong><p>${esc(recoveryTime(point.created_at))} · ${esc(copy("backup.recovery.point.snapshots", {count: (point.snapshots || []).length}))}</p></div>${status(point.status === "valid" ? "AVAILABLE" : "INCOMPLETE", point.status === "valid" ? "positive" : "review")}</article>`).join("")
    : emptyState(recoveryUnavailable ? copy("backup.recovery.pointsUnavailable") : copy("backup.recovery.noPoints"), recoveryUnavailable ? copy("backup.recovery.unavailable") : copy("backup.recovery.createPrompt"), "recovery");
  const backupState = backupUnavailable ? "UNAVAILABLE" : !backup.configured ? "NOT CONFIGURED" : backupDestinationUnavailable ? "DESTINATION UNAVAILABLE" : backup.last_backup_status === "SUCCESSFUL" ? "SUCCESSFUL" : backup.last_backup_status === "FAILED" ? "FAILED" : "NOT RUN YET";
  const backupTone = backupUnavailable || !backup.configured || backupDestinationUnavailable ? "unknown" : backup.last_backup_status === "SUCCESSFUL" ? "positive" : backup.last_backup_status === "FAILED" ? "critical" : "review";
  const recoveryActionAttrs = recoveryUnavailable ? 'disabled aria-disabled="true"' : "data-recovery-create";
  const backupConfigureAttrs = backupUnavailable ? 'disabled aria-disabled="true"' : "data-backup-configure";
  const backupConfigureLabel = backup.configured === true ? copy("backup.configure.change") : copy("backup.configure.setup");
  const backupConfigureDetail = backup.configured === true ? copy("backup.configure.changeDetail") : copy("backup.configure.setupDetail");
  const backupCanStart = backupReady;
  const backupNowAttrs = backupCanStart ? "data-backup-now" : 'disabled aria-disabled="true"';
  const backupNowLabel = copy("backup.panel.now");
  const backupNowDetail = copy("backup.panel.nowDetail");
  const backupVerifyAttrs = backupReady ? "data-backup-verify" : 'disabled aria-disabled="true"';
  const backupRestoreAttrs = backupReady ? "data-backup-restore" : 'disabled aria-disabled="true"';
  const restorePanel = `<div id="recovery-restore-picker" class="recovery-restore-picker" hidden><div class="eyebrow">${esc(copy("backup.restore.eyebrow"))}</div><p id="recovery-restore-summary" class="section-meta"></p><p id="recovery-restore-count" class="section-meta"></p><div id="recovery-file-list" class="recovery-file-list"></div><div class="inline-actions">${actionButton(copy("backup.restore.selectedAction"), copy("backup.restore.selectedAction.detail"), "primary", "data-recovery-restore-confirm", "arrow")}<button class="text-button" data-recovery-restore-cancel>${esc(copy("ui.cancel"))}</button></div></div>`;
  const integrityLabel = backupUnavailable ? copy("backup.verify.unavailable") : backup.last_check_status === "VERIFIED" ? copy("backup.verify.verifiedAt", {time: recoveryTime(backup.last_check_at)}) : backup.last_check_status === "FAILED" ? copy("backup.verify.failed") : copy("backup.verify.notVerified");
  const backupDestination = backupUnavailable ? copy("backup.verify.unavailable") : backup.destination || copy("backup.panel.notConfigured");
  const backupActionStatus = backupUnavailable ? copy("backup.configure.unavailable") : !backup.configured ? copy("backup.status.choose") : backupDestinationUnavailable ? backupProblemCopy(backup.destination_problem) : backup.last_backup_status === "SUCCESSFUL" ? backup.last_retention_status === "FAILED" ? copy("backup.status.retentionRetry") : copy("backup.status.completed") : backup.last_backup_status === "FAILED" ? copy("backup.status.failed") : copy("backup.status.notRun");
  const scope = Array.isArray(backup.sources) && backup.sources.length ? backup.sources.map((source) => esc(source)).join(" · ") : copy("backup.panel.noScope");
  const retention = backup.retention ? copy("backup.panel.retention", {daily: backup.retention.daily || 0, weekly: backup.retention.weekly || 0}) : copy("backup.panel.retentionUnavailable");
  const cleanupAvailable = !recoveryUnavailable && points.length > 3;
  const cleanupControl = cleanupAvailable ? `<button class="text-button" data-recovery-cleanup>${esc(copy("backup.recovery.cleanup"))} ${icon("clean")}</button>` : "";
  return `${recoveryQueueMarkup(data)}<div class="recovery-workspaces"><section class="recovery-v1-panel"><div class="recovery-v1-heading"><div><div class="eyebrow">${esc(copy("backup.recovery.localEyebrow"))}</div><h2>${esc(copy("backup.recovery.title"))}</h2><p>${esc(copy("backup.recovery.copy"))}</p></div>${recoveryUnavailable ? status("UNAVAILABLE", "unknown") : latest ? status("AVAILABLE", "positive") : status("NOT CREATED", "review")}</div><div class="recovery-facts"><div><span>${esc(copy("backup.recovery.latest"))}</span><strong>${esc(recoveryUnavailable ? copy("backup.verify.unavailable") : latest ? recoveryTime(latest.created_at) : copy("backup.recovery.notCreated"))}</strong></div><div><span>${esc(copy("backup.recovery.retention"))}</span><strong>${esc(recoveryUnavailable ? copy("backup.verify.unavailable") : copy("backup.recovery.retentionValue"))}</strong></div><div><span>${esc(copy("backup.recovery.home"))}</span><strong>${esc(recoveryUnavailable ? copy("backup.verify.unavailable") : copy("backup.recovery.homeExcluded"))}</strong></div></div><div class="recovery-actions">${actionButton(copy("backup.recovery.create"), copy("backup.recovery.createDetail"), "primary", recoveryActionAttrs, "recovery")}${cleanupControl}</div><div id="recovery-point-status" class="action-status" role="status" aria-live="polite"></div><details class="technical-disclosure"><summary><span>${esc(copy("backup.recovery.availablePoints"))}</span><span class="section-meta">${esc(points.length)}</span></summary><div class="recovery-point-list">${pointRows}</div></details></section><section class="recovery-v1-panel"><div class="recovery-v1-heading"><div><div class="eyebrow">${esc(copy("backup.panel.eyebrow"))}</div><h2>${esc(copy("backup.panel.title"))}</h2><p>${esc(copy("backup.panel.copy"))}</p></div>${status(backupState, backupTone)}</div><div class="recovery-facts"><div><span>${esc(copy("backup.panel.destination"))}</span><strong>${esc(backupDestination)}</strong></div><div><span>${esc(copy("backup.panel.lastBackup"))}</span><strong>${esc(backupUnavailable ? copy("backup.verify.unavailable") : recoveryTime(backup.last_backup_at))}</strong></div><div><span>${esc(copy("backup.panel.integrity"))}</span><strong>${esc(integrityLabel)}</strong></div></div><div class="recovery-actions">${actionButton(backupConfigureLabel, backupConfigureDetail, backupReady ? "secondary" : "primary", backupConfigureAttrs, "folder")}${actionButton(backupNowLabel, backupNowDetail, backupReady ? "primary" : "secondary", backupNowAttrs, "export")}${actionButton(copy("backup.verify"), copy("backup.panel.verifyDetail"), "secondary", backupVerifyAttrs, "check")}${actionButton(copy("backup.restore"), copy("backup.panel.restoreDetail"), "secondary", backupRestoreAttrs, "file")}</div><div id="backup-action-status" class="action-status" role="status" aria-live="polite">${backupActionStatus}</div>${restorePanel}<details class="technical-disclosure"><summary><span>${esc(copy("backup.panel.scope"))}</span></summary><div class="technical-disclosure-content"><p>${scope} · ${esc(retention)} · ${esc(copy("backup.panel.noSystemFiles"))}</p></div></details></section></div>`;
}
function devicesMarkup(data) {
  const history = data.device_history || {};
  const summary = history.summary || {};
  const records = Array.isArray(summary.new_unknown) ? summary.new_unknown : [];
  const connected = Array.isArray(history.devices) ? history.devices.filter((item) => item.connected) : [];
  const deviceRows = connected.length ? connected.map((item) => `<article class="activity-row device-history-row"><span class="activity-icon">${icon("devices")}</span><div><strong>${esc(item.name || copy("devices.history.externalDevice"))}</strong><p>${esc(item.device_class || copy("devices.history.externalDevice"))} · ${esc(item.trusted ? copy("devices.history.known") : copy("devices.history.unknown"))}</p></div><time>${esc(item.last_seen || copy("ui.unknown"))}</time></article>`).join("") : emptyState(summary.source_state === "UNAVAILABLE" ? copy("devices.history.unavailable") : copy("devices.history.empty"), summary.source_state === "UNAVAILABLE" ? copy("devices.history.unavailableCopy") : copy("devices.history.emptyCopy"), "devices");
  const unknownRows = records.length ? records.map((item) => `<article class="activity-row device-history-row"><span class="activity-icon">${icon("warning")}</span><div><strong>${esc(item.name || copy("devices.history.unknownDevice"))}</strong><p>${esc(item.connected ? copy("devices.history.firstSeenCurrent", {time: item.first_seen || copy("ui.unknown")}) : copy("devices.history.firstSeenLast", {first: item.first_seen || copy("ui.unknown"), last: item.last_seen || copy("ui.unknown")}))}</p></div>${status(item.connected ? "REVIEW NEEDED" : copy("devices.history.recorded"), item.connected ? "review" : "muted", {canonical: item.connected})}</article>`).join("") : emptyState(copy("devices.history.noNew"), copy("devices.history.noNewCopy"), "devices");
  const usbRows = (data.usb || []).length ? data.usb.map((row) => statusRow(row)).join("") : emptyState(copy("devices.usb.unavailable"), copy("devices.usb.unavailableCopy"), "devices");
  return `${pageHeader(copy("devices.eyebrow"), copy("route.devices"), copy("devices.copy"), actionButton(copy("ui.refresh"), copy("devices.refresh.detail"), "secondary", "data-refresh", "refresh"))}<div class="action-status deviation-action-status" role="status" aria-live="polite"></div>${recoveryMarkup(data)}<div class="device-inventory"><section class="device-history-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("devices.history.connectedEyebrow"))}</div><h2>${esc(summary.source_state === "UNAVAILABLE" ? copy("state.unavailable") : copy("devices.history.connected", {count: summary.connected_external ?? 0}))}</h2></div></div>${deviceRows}</section><section class="device-history-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("devices.history.weekEyebrow"))}</div><h2>${esc(copy("devices.history.newUnknown"))}</h2></div><span class="section-meta">${esc(summary.source_state === "UNAVAILABLE" ? copy("state.unavailable") : summary.new_unknown_count ?? 0)}</span></div>${unknownRows}</section></div><div class="two-column"><section class="plain-section feature-section"><div class="feature-heading"><span class="feature-icon">${icon("devices")}</span><div><div class="eyebrow">${esc(copy("devices.usb.eyebrow"))}</div><h2>${esc(copy("devices.usb.title"))}</h2></div></div>${usbRows}</section><section class="plain-section feature-section"><div class="feature-heading"><span class="feature-icon">${icon("recovery")}</span><div><div class="eyebrow">${esc(copy("devices.recovery.eyebrow"))}</div><h2>${esc(copy("devices.recovery.title"))}</h2></div></div>${(data.recovery || []).length ? data.recovery.map((row) => statusRow(row, false, recoveryDeviationAction(row))).join("") : emptyState(copy("devices.recovery.unavailable"), copy("devices.recovery.unavailableCopy"), "recovery")}</section></div>`;
}
function evidenceMarkup(data) {
  const sections = data.sections || [];
  const rows = sections.flatMap((section) => section.rows || []);
  const findings = rows.filter((row) => ["REVIEW NEEDED", "ACTION REQUIRED", "UNAVAILABLE", "UNKNOWN"].includes(String(row.state || "").toUpperCase()) && row.accepted_deviation !== true);
  const protectedCount = rows.filter((row) => ["SECURE", "PROTECTED"].includes(row.state)).length;
  const resolution = findings.length ? findings.map(evidenceResolutionMarkup).join("") : emptyState(t("system.checks.noFindings"), t("system.checks.noFindings.copy"), "shield");
  const groups = sections.length ? sections.map((section) => {
    const domain = copy(section.domain || "evidence.domain.unknown");
    return `<details class="evidence-group"><summary><span><span class="eyebrow">${esc(domain)}</span><strong>${esc(copy("evidence.domainChecks", {domain}))}</strong></span><span class="section-meta">${esc(copy("evidence.checkCount", {count: section.count}))}</span></summary><div class="evidence-rows">${(section.rows || []).map(evidenceTechnicalMarkup).join("")}</div></details>`;
  }).join("") : emptyState(copy("evidence.none.title"), copy("evidence.none.copy"), "evidence");
  return `${pageHeader(t("system.checks.eyebrow"), t("system.checks.title"), t("system.checks.copy"), actionButton(t("ui.refresh"), copy("evidence.refresh.detail"), "secondary", "data-refresh", "refresh"))}<div class="action-status deviation-action-status" role="status" aria-live="polite"></div><section class="evidence-banner"><span class="feature-icon">${icon("evidence")}</span><div><strong>${esc(copy("design.checks.assessment"))}</strong><p>${esc(copy("evidence.checked", {time: localizedTime(data.generated_at)}))}</p></div></section><section class="evidence-resolution"><div class="section-heading"><div><div class="eyebrow">${esc(t("system.checks.resolve"))}</div><h2>${findings.length ? esc(t("system.checks.findings", {count: findings.length, suffix: findings.length === 1 ? "" : "s"})) : esc(t("system.checks.allClear"))}</h2><p>${esc(t("system.checks.resolve.copy"))}</p></div><div class="evidence-summary"><span><b>${esc(findings.length)}</b> ${esc(t("system.checks.toReview"))}</span><span><b>${esc(protectedCount)}</b> ${esc(t("system.checks.protected"))}</span></div></div><div class="evidence-resolution-list">${resolution}</div></section><details class="technical-disclosure evidence-all-checks"><summary><span>${esc(t("system.checks.all"))}</span><span class="section-meta">${esc(copy("evidence.checkCount", {count: rows.length}))}</span></summary>${technicalDisclosure(copy("evidence.policy"), "", `<code>${esc(data.policy_profile || copy("ui.unavailable"))}</code>`)}<div class="evidence-groups">${groups}</div></details>`;
}

function fileSecurityOperationMarkup(operation) {
  const state = String(operation?.state || "UNAVAILABLE").toUpperCase();
  const active = ["QUEUED", "SCANNING", "FINALIZING"].includes(state);
  const label = state === "SCANNING" ? copy(operation.mode === "SYSTEM" ? "file.scan.systemWorking" : "file.scan.selectionWorking") : state === "COMPLETED" ? copy("file.scan.completed") : stateLabel(state);
  const detail = active ? copy("file.scan.workingCopy")
    : state === "COMPLETED" ? Number(operation.detection_count || 0) > 0 ? copy("file.operation.detectedCopy") : copy("file.operation.cleanCopy")
      : state === "PARTIAL" ? copy("file.operation.partialCopy")
        : state === "CANCELLED" ? copy("file.operation.cancelledCopy")
          : state === "INTERRUPTED" ? copy("file.operation.interruptedCopy")
            : state === "FAILED" || state === "UNAVAILABLE" ? copy("file.operation.failedCopy")
              : copy("file.scan.reviewCopy");
  const cancel = active ? `<button class="text-button" data-file-scan-cancel="${esc(operation.operation_id)}">${esc(copy("file.operation.cancel"))} ${icon("clean")}</button>` : "";
  const scanKind = operation.mode === "SYSTEM" ? copy("file.operation.systemEyebrow") : operation.mode === "FOLDER" ? copy("file.operation.folderEyebrow") : copy("file.operation.fileEyebrow");
  const scope = operation.scope?.label || scanKind;
  const timestamp = active ? operation.started_at : operation.ended_at || operation.started_at;
  const whenLabel = active ? copy("file.operation.started") : copy("file.operation.completed");
  const operationTone = active ? "review" : state === "COMPLETED" ? "positive" : state === "PARTIAL" ? "review" : state === "CANCELLED" ? "muted" : "critical";
  const skipped = Number(operation.skipped_count || 0) > 0 ? `<span>${esc(copy("file.operation.skipped", {count: operation.skipped_count}))}</span>` : "";
  return `<article class="file-security-operation ${active ? "is-active" : ""}" data-file-operation="${esc(operation.operation_id || "")}"><div class="operation-heading"><div><div class="eyebrow">${esc(active ? copy("file.operation.currentEyebrow") : copy("file.operation.lastEyebrow"))}</div><h3>${esc(label)}</h3><p>${esc(detail)}</p><p class="section-meta"><b>${esc(copy("file.operation.scope"))}</b> ${esc(scope)} · <b>${esc(whenLabel)}</b> ${esc(recoveryTime(timestamp))}</p></div>${status(state, operationTone, {canonical:true})}</div>${active ? `<div class="progress-block indeterminate" role="progressbar" aria-label="${esc(label)}"><div class="progress-track"><span></span></div></div>` : ""}<div class="file-operation-counts"><span>${esc(copy("file.operation.inspected", {count: operation.files_inspected || 0}))}</span><span>${esc(copy("file.operation.detections", {count: operation.detection_count || 0}))}</span><span>${esc(copy("file.operation.errors", {count: operation.error_count || 0}))}</span>${skipped}</div>${cancel}</article>`;
}

function filesMarkup(data) {
  const loading = data.loading === true;
  const detections = Array.isArray(data.detections) ? data.detections : (data.quarantine || []);
  const clamavState = String(data.clamav?.status || "UNAVAILABLE").toUpperCase();
  const scanAvailable = !loading && data.state === "AVAILABLE" && clamavState === "CURRENT" && Boolean(data.clamav?.engine_version);
  const definitionAge = Number.isFinite(Number(data.clamav?.database_age_seconds)) ? `${Math.max(0, Math.floor(Number(data.clamav.database_age_seconds) / 86400))}d` : copy("ui.unavailable");
  const clamav = loading
    ? `<div class="fact-line"><div><span>${esc(copy("file.definitions"))}</span><strong>${esc(copy("file.reading"))}</strong></div><div><span>${esc(copy("file.lastUpdate"))}</span><strong>${esc(copy("file.checkingStatus"))}</strong></div></div>`
    : data.clamav
    ? `<div class="fact-line"><div><span>${esc(copy("file.definitions"))}</span><strong>${esc(data.clamav.status || copy("ui.unavailable"))}</strong></div><div><span>${esc(copy("file.lastUpdate"))}</span><strong>${esc(localizedTime(data.clamav.last_successful_update))}</strong></div></div>${technicalDisclosure(copy("file.scannerDetails"), "", `<p>${esc(copy("file.engineDatabase", {engine: data.clamav.engine_version || copy("ui.unavailable"), database: data.clamav.database_version || copy("ui.unavailable")}))}</p><p>${esc(copy("file.definitionAge", {age: definitionAge}))}</p><p>${esc(data.clamav.detail || "")}</p>`)}`
    : emptyState(copy("file.scannerUnavailable"), copy("file.scannerUnavailableCopy"), "shield");
  const renderDetection = (item) => {
    const state = String(item.state || "DETECTED").toUpperCase();
    const action = ["DETECTED", "QUARANTINE_FAILED"].includes(state)
      ? `<button class="text-button" data-file-quarantine="${esc(item.detection_id)}">${esc(copy("file.action.quarantine"))} ${icon("arrow")}</button>`
      : ["QUARANTINED", "RESTORE_FAILED"].includes(state)
        ? `<button class="text-button" data-file-restore="${esc(item.detection_id)}">${esc(copy("file.action.restore"))} ${icon("arrow")}</button><button class="text-button danger-text" data-file-delete="${esc(item.detection_id)}">${esc(copy("file.action.delete"))} ${icon("clean")}</button>`
        : state === "RESTORED"
          ? `<button class="text-button danger-text" data-file-delete="${esc(item.detection_id)}">${esc(copy("file.action.deleteCopy"))} ${icon("clean")}</button>`
        : state === "DELETE_FAILED"
          ? `<button class="text-button danger-text" data-file-delete="${esc(item.detection_id)}">${esc(copy("file.action.retryDelete"))} ${icon("clean")}</button>`
        : "";
    const durableDetail = state === "RESTORED" && item.restore_staging_path
      ? ` · ${copy("file.restore.stagedAt", {path: item.restore_staging_path})}`
      : state.endsWith("FAILED") ? ` · ${copy("file.action.notCompleted")}` : "";
    return `<article class="quarantine-row file-detection-row"><div><strong>${esc(item.detection_name || copy("file.detection.unnamed"))}</strong><p>${esc(item.original_path || copy("file.detection.pathUnavailable"))}</p><small>${esc(copy("file.detection.detectedAt", {time: localizedTime(item.detected_at)}))} · ${esc(item.scanner_version || "ClamAV")}${esc(durableDetail)}</small></div>${status(state, state === "DETECTED" || state === "QUARANTINED" ? "review" : state.endsWith("FAILED") ? "critical" : "muted", {canonical:true})}<div class="file-detection-actions">${action}</div></article>`;
  };
  const pendingDetections = detections.filter((item) => String(item.state || "DETECTED").toUpperCase() !== "DELETED");
  const resolvedDetections = detections.filter((item) => String(item.state || "").toUpperCase() === "DELETED");
  const detectionRows = pendingDetections.length ? pendingDetections.map(renderDetection).join("") : emptyState(copy("file.detections.none"), copy("file.detections.noneCopy"), "file");
  const active = data.active_scan || null;
  const latest = data.latest_scan || null;
  const operation = active || latest ? fileSecurityOperationMarkup(active || latest) : emptyState(copy("file.scan.none"), copy("file.scan.noneCopy"), "activity");
  const activity = (data.activity || []).filter((item) => /threat|scan|quarantine|restore|delete|safe open|sanit/i.test(`${item.title || ""} ${item.detail || ""}`));
  const safeOpen = `<div class="safe-open-controls"><input id="safe-open-path" type="text" placeholder="${esc(copy("file.safeOpen.placeholder"))}" aria-label="${esc(copy("file.safeOpen.pathLabel"))}">${actionButton(copy("file.safeOpen.choose"), copy("file.safeOpen.chooseDetail"), "secondary", "data-safe-open-pick", "folder")}${actionButton(copy("file.safeOpen.open"), copy("file.safeOpen.openDetail"), "primary", "data-safe-open", "lock")}</div><div class="workflow-feedback"><div id="safe-open-status" class="action-status" role="status" aria-live="polite">${esc(copy("file.safeOpen.noneSelected"))}</div><div class="inline-actions"><button class="text-button" data-provenance>${esc(copy("file.safeOpen.details"))} ${icon("arrow")}</button><button class="text-button" data-sanitize>${esc(copy("file.safeOpen.sanitize"))} ${icon("arrow")}</button></div><div id="provenance-status" class="action-status" role="status" aria-live="polite"></div></div>`;
  const protectionState = loading ? copy("file.protection.checking") : detections.some((item) => item.state === "DETECTED") ? copy("file.protection.review") : clamavState === "INITIALIZING" ? copy("file.protection.initializing") : clamavState === "UPDATING" ? copy("file.protection.updating") : !scanAvailable ? copy("file.protection.unavailable") : copy("file.protection.ready");
  const protectionCopy = loading ? copy("file.protection.checkingCopy") : detections.some((item) => item.state === "DETECTED") ? copy("file.protection.reviewCopy") : clamavState === "INITIALIZING" ? copy("file.protection.initializingCopy") : clamavState === "UPDATING" ? copy("file.protection.updatingCopy") : !scanAvailable ? (data.state === "UNAVAILABLE" ? copy("file.protection.unavailableState") : copy("file.protection.updateRequired")) : copy("file.protection.readyCopy");
  const scanAttrs = scanAvailable ? "" : 'disabled aria-disabled="true"';
  const unavailableHint = scanAvailable ? "" : `<p class="action-status" role="status">${esc(copy("file.protection.disabledHint"))}</p>`;
  const scanSurface = `<section class="plain-section file-scan-surface"><div class="section-heading"><div><div class="eyebrow">${esc(copy("file.scan.eyebrow"))}</div><h2>${esc(copy("file.scan.title"))}</h2></div></div><div class="file-scan-actions">${actionButton(copy("files.scanFile"), copy("file.scan.fileDetail"), "primary", `${scanAttrs} data-file-scan-file`, "file")}${actionButton(copy("files.scanFolder"), copy("file.scan.folderDetail"), "secondary", `${scanAttrs} data-file-scan-folder`, "folder")}${actionButton(copy("files.scanSystem"), copy("file.scan.systemDetail"), "secondary", `${scanAttrs} data-file-scan-system`, "shield")}</div><div id="file-security-action-status" class="action-status" role="status" aria-live="polite">${esc(fileSecurityState.feedback)}</div>${unavailableHint}<div id="file-security-operation">${operation}</div></section>`;
  return `${pageHeader(copy("file.eyebrow"), copy("file.title"), copy("file.copy"), actionButton(copy("ui.refresh"), copy("file.refresh.detail"), "secondary", "data-refresh", "refresh"))}<section class="file-security-hero"><div><div class="eyebrow">${esc(copy("file.protection.eyebrow"))}</div><h2>${esc(protectionState)}</h2><p>${esc(protectionCopy)}</p></div><div class="file-security-definitions">${clamav}</div></section>${active ? scanSurface : ""}<section class="plain-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("file.detections.eyebrow"))}</div><h2>${esc(copy("file.detections.title"))}</h2></div><span class="section-meta">${esc(pendingDetections.length)}</span></div><div class="file-detection-list">${detectionRows}</div>${resolvedDetections.length ? technicalDisclosure(copy("design.files.resolved"), resolvedDetections.length, resolvedDetections.map(renderDetection).join("")) : ""}</section>${active ? "" : scanSurface}${technicalDisclosure(copy("file.tools.title"), "", `<div class="workflow-step"><div><div class="eyebrow">${esc(copy("file.tools.eyebrow"))}</div><h2>${esc(copy("file.tools.heading"))}</h2><p>${esc(copy("file.tools.copy"))}</p></div>${safeOpen}</div>`)}${technicalDisclosure(copy("file.activity.title"), activity.length, activity.length ? `<div class="activity-list">${activity.map(activityMarkup).join("")}</div>` : emptyState(copy("file.activity.none"), copy("file.activity.noneCopy"), "activity"))}`;
}

function privacyMarkup(data) {
  const activity = data.activity || [];
  const local = (data.local || []).map((row) => statusRow(row, true)).join("") || emptyState(copy("privacy.local.unavailable"), copy("privacy.local.unavailableCopy"), "privacy");
  const profileFacts = [data.identity, data.firewall, data.vpn, data.public_ip].filter(Boolean).map((row) => statusRow(row, true)).join("");
  const disclosures = (data.disclosures || []).map((item) => technicalDisclosure(item.component || copy("privacy.disclosure.service"), item.state || "", `<dl><div><dt>${esc(copy("privacy.disclosure.purpose"))}</dt><dd>${esc(item.purpose || copy("privacy.disclosure.notSupplied"))}</dd></div><div><dt>${esc(copy("privacy.disclosure.endpoints"))}</dt><dd>${esc(item.endpoints || copy("privacy.disclosure.none"))}</dd></div><div><dt>${esc(copy("privacy.disclosure.trigger"))}</dt><dd>${esc(item.trigger || copy("privacy.disclosure.notSupplied"))}</dd></div><div><dt>${esc(copy("privacy.disclosure.data"))}</dt><dd>${esc(item.data_disclosed || copy("privacy.disclosure.notSupplied"))}</dd></div><div><dt>${esc(copy("privacy.disclosure.retention"))}</dt><dd>${esc(item.retention || copy("privacy.disclosure.notSupplied"))}</dd></div>${item.disable_route ? `<div><dt>${esc(copy("privacy.disclosure.disable"))}</dt><dd>${esc(item.disable_route)}</dd></div>` : ""}</dl>`)).join("");
  const historyLabel = copy("privacy.history.summary", {count: activity.length, max: data.max_activity_items || 0, days: data.retention_days || 0});
  const profile = String(data.profile?.value || "UNKNOWN").toLowerCase();
  const profileKey = `privacy.profile.${profile}`;
  const profileLabel = copy(profileKey) === profileKey ? copy("state.unknown") : copy(profileKey);
  const normalizedProfile = profile.toUpperCase();
  const profilePending = privacyState.profilePending || "";
  const profileBusy = Boolean(profilePending);
  const localBusy = Boolean(privacyState.localActionPending);
  const actionBusy = profileBusy || localBusy;
  const profileButton = (value, labelKey, detailKey, glyph) => `<button class="profile-choice" data-profile="${value}" aria-pressed="${value.toUpperCase() === normalizedProfile}"${actionBusy ? ' disabled aria-disabled="true"' : ''}><span class="profile-choice-heading"><span class="action-label">${esc(copy(labelKey))}</span>${value.toUpperCase() === normalizedProfile ? `<small>${esc(copy("design.privacy.current"))}</small>` : ""}</span><span class="profile-choice-copy">${esc(copy(`design.privacy.${value.toLowerCase()}`))}</span></button>`;
  return `${pageHeader(copy("privacy.eyebrow"), copy("nav.privacy"), "", actionButton(copy("ui.refresh"), copy("privacy.refresh.detail"), "secondary", "data-refresh", "refresh"))}<section class="plain-section privacy-profile" data-privacy-profile-state data-profile-current="${esc(normalizedProfile)}" data-profile-pending="${esc(profilePending)}" aria-busy="${profileBusy ? "true" : "false"}"><div class="section-heading"><div><div class="eyebrow">${esc(copy("privacy.profile.eyebrow"))}</div><h2>${esc(copy("design.privacy.choose"))}</h2><p>${esc(copy("design.privacy.scope"))}</p></div></div><div class="profile-commands">${profileButton("Standard", "privacy.profile.standard", "privacy.profile.standardDetail", "network")}${profileButton("Private", "privacy.profile.private", "privacy.profile.privateDetail", "privacy")}${profileButton("Travel", "privacy.profile.travel", "privacy.profile.travelDetail", "travel")}</div><div id="profile-action-status" class="action-status" role="status" aria-live="polite">${esc(privacyState.feedbackScope === "profile" ? privacyState.feedback : "")}</div><div class="privacy-observed"><h3>${esc(copy("design.privacy.measured"))}</h3><div class="profile-facts">${profileFacts}</div></div></section><section class="privacy-contract"><div><div class="eyebrow">${esc(copy("privacy.local.eyebrow"))}</div><h2>${esc(copy("privacy.local.title"))}</h2><p>${esc(copy("privacy.local.copy"))}</p></div>${technicalDisclosure(copy("design.privacy.localDetails"), "", local)}<aside><div class="eyebrow">${esc(copy("privacy.history.eyebrow"))}</div><p>${esc(historyLabel)}</p><div id="action-status" data-privacy-action-status class="action-status" role="status" aria-live="polite">${esc(privacyState.feedbackScope === "local" ? privacyState.feedback : "")}</div><div class="action-stack">${actionButton(copy("privacy.export"), copy("privacy.export.detail"), "primary", `data-action="export"${actionBusy ? " disabled aria-disabled=\"true\"" : ""}`, "export")}${actionButton(copy("privacy.clear"), copy("privacy.clear.detail"), "secondary", `data-action="clear"${actionBusy ? " disabled aria-disabled=\"true\"" : ""}`, "clean")}</div></aside></section><section class="plain-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("privacy.disclosure.eyebrow"))}</div><h2>${esc(copy("privacy.disclosure.title"))}</h2></div></div>${disclosures || emptyState(copy("privacy.disclosure.empty"), copy("privacy.disclosure.emptyCopy"), "privacy")}</section>`;
}

function updateProviderAvailability(data) {
  const states = Object.values(data?.providers || {}).map((item) => String(item?.state || "UNKNOWN").toUpperCase());
  const transactionStates = Array.isArray(data?.transaction?.provider_results)
    ? data.transaction.provider_results.map((item) => String(item?.state || "UNKNOWN").toUpperCase()).filter((state) => ["DEGRADED", "UNAVAILABLE"].includes(state))
    : [];
  states.push(...transactionStates);
  const unavailable = states.filter((state) => state === "UNAVAILABLE").length;
  const degraded = states.filter((state) => state === "DEGRADED").length;
  const available = states.filter((state) => ["AVAILABLE", "CHECKING"].includes(state)).length;
  if (!states.length || unavailable === states.length) return "UNAVAILABLE";
  if (degraded || unavailable) return "DEGRADED";
  return available ? "AVAILABLE" : "UNAVAILABLE";
}

function updateTransactionHasProviderFailure(data) {
  return Array.isArray(data?.transaction?.provider_results)
    && data.transaction.provider_results.some((item) => ["DEGRADED", "UNAVAILABLE"].includes(String(item?.state || "").toUpperCase()));
}

function updatePresentation(data) {
  const transaction = data?.transaction || {};
  const phase = String(transaction.phase || "IDLE").toUpperCase();
  const records = Array.isArray(data?.records) ? data.records : [];
  const available = records.filter((item) => item?.update_available === true);
  const driverIssues = records.filter((item) => item?.metadata?.driver_support === true && item?.metadata?.resolution === "UNRESOLVED");
  const snapshotRefreshing = data?.snapshot_refreshing === true;
  const providerState = updateProviderAvailability(data);
  const transactionProviderFailure = updateTransactionHasProviderFailure(data);
  let state = phase;
  // This is the single precedence rule for the Updates surface. A live check
  // or transaction is current work; availability then outranks old terminals.
  if (snapshotRefreshing) state = "CHECKING";
  else if (UPDATE_ACTIVE_PHASES.includes(phase)) state = phase;
  else if (phase === "READY_TO_RESTART") state = "READY_TO_RESTART";
  else if (phase === "FAILED" || transaction.error) state = "FAILED";
  else if (transactionProviderFailure) state = "DEGRADED";
  else if (available.length) state = phase === "RESOLVED" ? "RESOLVED" : "AVAILABLE";
  else if (phase === "COMPLETE") state = "COMPLETE";
  else if (phase === "CANCELLED") state = "CANCELLED";
  else if (["DEGRADED", "UNAVAILABLE"].includes(providerState)) state = providerState;
  else if (phase === "IDLE") state = "CURRENT";
  const presentation = UPDATE_PHASE_PRESENTATION[state] || UPDATE_PHASE_PRESENTATION.IDLE;
  const action = state === "FAILED" && transaction.restart_required === "REQUIRED"
    ? "restart"
    : presentation.action;
  return {
    ...presentation,
    action,
    phase,
    state,
    available,
    availableCount: available.length,
    driverIssues,
    providerState,
    snapshotRefreshing,
    transactionActive: UPDATE_ACTIVE_PHASES.includes(phase),
    terminal: UPDATE_TERMINAL_PHASES.includes(phase) || ["CURRENT", "AVAILABLE", "DEGRADED", "UNAVAILABLE"].includes(state),
    progressKey: snapshotRefreshing ? "updates.phase.checking" : presentation.stateKey,
  };
}

function overviewActivity(overview, digest) {
  // An empty authoritative digest is a valid result, not a request for old history.
  return Array.isArray(digest.recent_activity)
    ? digest.recent_activity.map((item) => ({...item, detail: item.summary}))
    : (overview.activity || []);
}

function updateHistoryMarkup(items) {
  const ordered = [...items].sort((a, b) => (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0));
  const row = (item) => `<article class="activity-row update-history-row" data-update-history-row><span class="activity-icon">${icon("updates")}</span><div><strong>${esc(item.name || item.identity || copy("updates.history.unnamed"))}</strong><p>${esc(updateHistoryVersionLine(item))} · ${esc(copy(updateHistoryResultKey(item.result)))}</p><small>${esc(item.provider || copy("updates.item.system"))}${item.source ? ` · ${esc(item.source)}` : ""}</small></div><time>${esc(localizedTime(item.timestamp, copy("ui.unknown")))}</time></article>`;
  return ordered.slice(0, 5).map(row).join("")
    + (ordered.length > 5 ? technicalDisclosure(copy("updates.history.older"), ordered.length - 5, ordered.slice(5).map(row).join("")) : "");
}

function updateHistoryResultKey(result) {
  const normalized = String(result || "UNKNOWN").toUpperCase();
  return normalized === "SUCCESS" ? "updates.history.result.success" : normalized === "FAILURE" ? "updates.history.result.failure" : normalized === "CANCELLED" ? "updates.history.result.cancelled" : "updates.history.result.unknown";
}

function updateHistoryVersionLine(item) {
  const previous = item?.previous_version;
  const next = item?.new_version;
  if (previous && next) return copy("updates.history.versions", {previous, next});
  if (next) return copy("updates.history.resultOnly", {next});
  if (previous) return copy("updates.history.previousOnly", {previous});
  return copy("updates.history.versionsUnavailable");
}

function updatesMarkup(data) {
  const transaction = data.transaction || {};
  const presentation = updatePresentation(data);
  updatePhase = presentation.phase;
  const {available, driverIssues, snapshotRefreshing} = presentation;
  updateListState.limit = Math.max(UPDATE_PAGE_SIZE, Math.min(updateListState.limit, Math.max(available.length, UPDATE_PAGE_SIZE)));
  const visibleAvailable = available.slice(0, updateListState.limit);
  const heroState = copy(presentation.stateKey);
  const heroMessage = presentation.state === "FAILED" && transaction.error
    ? transaction.error
    : presentation.state === "READY_TO_RESTART" && transaction.recovery_point_status === "VALID"
      ? copy("updates.message.restartSafe")
      : presentation.transactionActive && transaction.current_item
        ? transaction.current_item
        : copy(presentation.messageKey);
  const action = presentation.action === "none" ? actionButton(copy("updates.action.checking"), copy("updates.action.checkingDetail"), "secondary", 'disabled aria-disabled="true"', "updates")
    : presentation.action === "apply" ? actionButton(copy("updates.action.all"), copy("updates.action.allDetail"), "primary", "data-update-apply", "updates")
      : presentation.action === "restart" ? actionButton(copy("updates.restart"), copy("updates.action.restartDetail"), "primary", "data-update-restart", "updates")
        : presentation.action === "cancel-or-none" && transaction.cancellable === true ? actionButton(copy("ui.cancel"), copy("updates.action.cancelDetail"), "secondary", "data-update-cancel", "clean")
          : presentation.action === "cancel-or-none" ? `<span>${esc(copy("updates.message.notCancellable"))}</span>`
            : actionButton(copy("updates.check"), copy("updates.action.checkDetail"), "secondary", "data-update-resolve", "updates");
  const hasProgress = Number.isFinite(Number(transaction.progress));
  const progress = presentation.progress ? `<div class="progress-block ${hasProgress && presentation.transactionActive ? "" : "indeterminate"}" role="progressbar" aria-label="${esc(copy(presentation.progressKey))}" aria-valuemin="0" aria-valuemax="100"${hasProgress && presentation.transactionActive ? ` aria-valuenow="${Math.max(0, Math.min(100, Number(transaction.progress)))}"` : ""}><div class="progress-track"><span${hasProgress && presentation.transactionActive ? ` style="width:${Math.max(0, Math.min(100, Number(transaction.progress)))}%"` : ""}></span></div><p role="status" aria-live="polite">${esc(copy(presentation.progressKey))}</p></div>` : "";
  const providerRows = Object.entries(data.providers || {}).map(([name, item]) => statusRow({label:name, value:item.state || "UNKNOWN", tone:item.state, detail:item.reason || copy("updates.provider.noDetails")}, true)).join("");
  const providerResultRows = Array.isArray(transaction.provider_results) ? transaction.provider_results.map((item) => {
    const state = String(item?.state || "UNKNOWN").toUpperCase();
    const detail = [item?.reason, item?.detail].filter(Boolean).join(" ") || copy("updates.provider.noDetails");
    return statusRow({label:`${item?.provider || copy("updates.item.system")} · last operation`, value:state, tone:state === "SUCCESS" ? "positive" : state === "DEGRADED" || state === "UNAVAILABLE" ? "review" : "muted", detail}, true);
  }).join("") : "";
  const updateRows = visibleAvailable.map((item) => {
    const driver = item?.metadata?.driver_support === true;
    const packageName = item?.metadata?.package_name || copy("ui.unknown");
    const body = driver
      ? copy("updates.driver.required", {package: packageName})
      : copy("updates.item.versions", {current: item.current_version || copy("ui.unknown"), available: item.available_version || copy("ui.unknown"), restart: item.reboot_required === true ? copy("updates.item.restart") : ""});
    return `<article class="update-row"><div><span class="eyebrow">${esc(driver ? copy("updates.driver.eyebrow") : `${item.category || copy("updates.item.unnamed")} · ${item.provider || copy("updates.item.system")}`)}</span><h3>${esc(item.name || copy("updates.item.unnamed"))}</h3></div>${status("AVAILABLE", "review", {canonical:true})}<p>${esc(body)}</p></article>`;
  }).join("");
  const driverIssueRows = driverIssues.map((item) => `<article class="update-row"><div><span class="eyebrow">${esc(copy("updates.driver.reviewEyebrow"))}</span><h3>${esc(item.name || copy("updates.item.unnamed"))}</h3></div>${status("REVIEW", "review", {canonical:true})}<p>${esc(copy("updates.driver.unresolved"))}</p></article>`).join("");
  const history = updateHistoryMarkup(data.history || []);
  const availableSection = available.length
    ? `<section class="update-manifest"><div class="section-heading"><div><div class="eyebrow">${esc(copy("updates.available.eyebrow"))}</div><h2>${esc(copy("updates.available.count", {count: available.length}))}</h2></div><span class="section-count">${String(available.length).padStart(2, "0")}</span></div>${updateRows}${visibleAvailable.length < available.length ? `<div class="update-list-more">${actionButton(copy("updates.available.more", {count: Math.min(UPDATE_PAGE_SIZE, available.length - visibleAvailable.length)}), copy("updates.available.moreDetail"), "secondary", "data-updates-show-more", "arrow")}</div>` : ""}</section>`
    : "";
  const driverIssueSection = driverIssues.length
    ? `<section class="update-manifest"><div class="section-heading"><div><div class="eyebrow">${esc(copy("updates.driver.eyebrow"))}</div><h2>${esc(copy("updates.driver.unresolvedCount", {count: driverIssues.length}))}</h2></div><span class="section-count">${String(driverIssues.length).padStart(2, "0")}</span></div>${driverIssueRows}</section>`
    : "";
  const sources = (providerRows || providerResultRows) ? `${providerRows}${providerResultRows}` : emptyState(copy("updates.sources.empty"), copy("updates.sources.emptyCopy"), "updates");
  const diagnostic = transaction.details && ["FAILED", "DEGRADED"].includes(presentation.state)
    ? `<details class="technical-disclosure update-diagnostic"><summary>${esc(copy("updates.diagnostic.title"))}</summary><p>${esc(transaction.details)}</p></details>`
    : "";
  return `${pageHeader(copy("updates.eyebrow"), copy("nav.updates"), "", actionButton(copy("ui.refresh"), copy("updates.refresh.detail"), "secondary", "data-updates-refresh", "refresh"))}<section class="transaction-field" data-update-state="${esc(presentation.state)}" data-update-available-count="${available.length}"><div><div class="eyebrow">${esc(copy("updates.status.eyebrow"))}</div><h2>${esc(heroState)}</h2><p data-update-status role="status" aria-live="polite">${esc(heroMessage)}</p>${progress}${diagnostic}</div><aside>${action}<span>${esc(copy("updates.available.short", {count: available.length}))}</span></aside></section>${availableSection}${driverIssueSection}${technicalDisclosure(copy("updates.sources.title"), Object.keys(data.providers || {}).length, sources)}<section class="plain-section journal-section"><div class="section-heading"><div><div class="eyebrow">${esc(copy("updates.history.eyebrow"))}</div><h2>${esc(copy("updates.history.title"))}</h2></div></div>${history || emptyState(copy("updates.history.empty"), copy("updates.history.emptyCopy"), "activity")}</section>`;
}

function contextNavigation(page) {
  const systemPages = ["system", "files", "applications", "devices", "evidence"];
  if (systemPages.includes(page)) {
    const items = [["evidence", "route.evidence"], ["files", "system.files"], ["applications", "system.apps"], ["devices", "system.devices"]];
    return `<nav class="context-navigation" aria-label="${esc(t("system.title"))}">${items.map(([id, key]) => `<button class="${page === id ? "active" : ""}" data-page="${id}" aria-current="${page === id ? "page" : "false"}">${esc(t(key))}</button>`).join("")}</nav>`;
  }
  if (["network", "activity", "threats"].includes(page)) {
    const items = [["network", "network.protection"], ["activity", "network.activity"], ["threats", "network.threats"]];
    return `<nav class="context-navigation" aria-label="${esc(t("nav.network"))}">${items.map(([id, key]) => `<button class="${page === id ? "active" : ""}" data-page="${id}" aria-current="${page === id ? "page" : "false"}">${esc(t(key))}</button>`).join("")}</nav>`;
  }
  return "";
}
function renderContent(page, data) {
  const route = normalizePage(page);
  let content;
  if (route === "overview") content = overviewMarkup(data.overview || data, data.security_digest || {});
  else if (route === "network") content = networkProtectionMarkup(data);
  else if (route === "applications") content = applicationsMarkup(data);
  else if (route === "devices") content = devicesMarkup(data);
  else if (route === "evidence") content = evidenceMarkup(data);
  else if (route === "files") content = filesMarkup(data);
  else if (route === "privacy") content = privacyMarkup(data);
  else if (route === "updates") content = updatesMarkup(data);
  else if (route === "activity") content = networkActivityMarkup(data);
  else if (route === "threats") content = threatProtectionMarkup(data);
  else content = overviewMarkup(data);
  return `${contextNavigation(route)}${content}`;
}

function getPageData(page) {
  const key = page;
  const existing = pageDataRequests.get(key);
  if (existing) return existing;
  const initialOverview = page === "overview" && !window.__greywardStartupOverviewRequested;
  if (initialOverview) {
    window.__greywardStartupOverviewRequested = true;
    startupMarkOnce("initial_overview_request_start");
  }
  const request = page === "activity"
    ? invokeBounded("get_network_activity", {sinceSequence: 0, limit: 256}, 12000)
    : page === "overview"
      ? invokeBounded("get_overview", undefined, 9000)
      : invokeBounded(page === "files" ? "get_filesecurity" : page === "network" ? "get_network_protection" : page === "threats" ? "get_threat_protection" : `get_${page}`, undefined, 12000);
  pageDataRequests.set(key, request);
  if (initialOverview) {
    request.then(
      () => startupMarkOnce("initial_overview_request_complete"),
      () => startupMarkOnce("initial_overview_request_failed"),
    );
  }
  request.finally(() => {
    if (pageDataRequests.get(key) === request) pageDataRequests.delete(key);
  }).catch(() => {});
  return request;
}
async function refreshUpdates() {
  if (currentPage !== "updates" || document.hidden || updateRequestBusy) return;
  updateRequestBusy = true;
  try {
    const data = await invokeBounded("get_updates", undefined, 12000);
    if (currentPage !== "updates" || document.hidden) return;
    pageCache.set("updates", {data, loadedAt: Date.now()});
    const frame = app.querySelector(".content-frame");
    if (frame) {
      const viewState = captureViewState();
      frame.innerHTML = renderContent("updates", data);
      bindContent();
      restoreViewState(viewState);
    }
    if (!updatePresentation(data).busy) stopUpdatePolling();
  } catch (_) {
    // Keep the last authoritative update state visible while a transient
    // provider read is unavailable. The next bounded poll retries it.
  } finally {
    updateRequestBusy = false;
  }
}
function startUpdatePolling() {
  if (updatePoll || document.hidden) return;
  updatePoll = window.setInterval(refreshUpdates, 1500);
}
function stopUpdatePolling() {
  if (updatePoll) window.clearInterval(updatePoll);
  updatePoll = null;
}
function pageLoading(page) { const labels = {overview:"loading.overview", system:"loading.system", network:"loading.system", privacy:"loading.privacy", updates:"loading.updates", files:"loading.status", applications:"loading.status", devices:"loading.status", evidence:"loading.status", activity:"loading.status", threats:"network.threats"}; return shell(loadingState(copy(labels[page] || "loading.status")), {busy:true}); }
function pageFailure(error) { return shell(pageHeader(copy("error.eyebrow"), t("ui.unavailable"), t("ui.stillWorks")) + errorState(t("ui.retry"), actionError(error, copy("error.view"))), {live:copy("state.unavailable")}); }

function provenanceSummary(value) {
  if (!value || typeof value !== "object") return String(value || copy("file.context.unavailable"));
  const source = value.source?.state || "UNKNOWN";
  const scan = Array.isArray(value.scan) ? value.scan[0]?.state : value.scan?.state;
  const signature = value.signature?.state || "UNKNOWN";
  return copy("file.provenance.summary", {source, scan: scan || "UNKNOWN", signature});
}
function contextMarkup(data) {
  return `<div class="file-context-window">${pageHeader(copy("file.context.eyebrow"), data.file_name || copy("file.context.selected"), copy("file.context.copy"), actionButton(copy("file.context.back"), copy("file.context.backDetail"), "secondary", "data-file-context-back", "shield"))}<section class="context-grid"><div class="context-row"><span>${esc(copy("file.context.path"))}</span><strong>${esc(data.path || copy("file.context.unavailable"))}</strong></div><div class="context-row"><span>${esc(copy("file.context.source"))}</span><strong>${esc(provenanceSummary(data.provenance))}</strong></div></section></div>`;
}

async function loadPage(page = currentPage, options = {}) {
  const destination = normalizePage(page);
  if (destination !== currentPage) deviationState.feedback = "";
  if (!["network", "threats"].includes(destination)) networkActionState.feedback = "";
  if (destination !== "privacy" && !privacyState.profilePending && !privacyState.localActionPending) { privacyState.feedback = ""; privacyState.exportPath = ""; }
  if (destination !== "activity") cancelNetworkHistoryLoad();
  if (destination !== "files") stopFileSecurityPolling();
  const preserveScroll = destination === currentPage;
  let scrollPosition = preserveScroll ? readPageScrollPosition() : null;
  currentPage = pages.includes(destination) ? destination : "overview";
  const request = ++requestSequence;
  if (updatePoll) { window.clearInterval(updatePoll); updatePoll = null; }
  if (options.force === true) {
    pageCache.delete(currentPage);
    pageDataRequests.delete(currentPage);
  }
  const cached = pageCache.get(currentPage);
  const cachedData = cached?.data;
  const initialCachedData = cachedData;
  const canReuseCachedPage = options.force !== true && PAGE_CACHE_REUSE_ROUTES.has(currentPage) && Boolean(cachedData) && (Date.now() - cached.loadedAt) < PAGE_CACHE_TTL_MS;
  const refreshInPlace = preserveScroll && Boolean(app.querySelector(".app-shell .content-frame")) && !canReuseCachedPage;
  if (canReuseCachedPage && preserveScroll) {
    const activeFileOperation = app.querySelector("[data-file-operation]");
    if (currentPage === "files" && activeFileOperation?.classList.contains("is-active")) startFileSecurityPolling();
    return;
  }
  const refreshContext = refreshInPlace ? captureViewState() : null;
  if (refreshInPlace) {
    setRefreshBusy(true);
  } else {
    const initialContent = initialCachedData
      ? renderContent(currentPage, initialCachedData)
      : currentPage === "files"
        ? filesMarkup({loading: true, state: "LOADING", detections: [], activity: []})
        : null;
    app.innerHTML = initialContent ? shell(initialContent, {busy: !canReuseCachedPage}) : pageLoading(currentPage);
    if (!window.__greywardStartupShellRendered) {
      window.__greywardStartupShellRendered = true;
      startupMarkOnce("first_shell_dom");
      requestAnimationFrame(() => startupMarkOnce("first_shell_frame"));
    }
    applyPageScroll(scrollPosition);
    bind();
  }
  if (canReuseCachedPage) return;
  if (initialCachedData && !refreshInPlace) setRefreshBusy(true);
  try {
    const data = await getPageData(currentPage);
    if (request !== requestSequence) return;
    pageCache.set(currentPage, {data, loadedAt: Date.now()});
    if (refreshInPlace) {
      scrollPosition = readPageScrollPosition();
      const viewState = captureViewState();
      viewState.focus ||= refreshContext?.focus;
      app.querySelector(".content-frame").innerHTML = renderContent(currentPage, data);
      restoreViewState(viewState);
      setRefreshBusy(false);
    } else {
      app.innerHTML = shell(renderContent(currentPage, data));
      if (currentPage === "overview") {
        startupMarkOnce("first_authoritative_overview_dom");
        requestAnimationFrame(() => startupMarkOnce("first_authoritative_overview_frame"));
      }
    }
    applyPageScroll(scrollPosition);
    if (refreshInPlace) bindContent();
    else bind();
    if (currentPage === "overview" && !fileContextDismissed) {
        invokeBounded("get_file_context", undefined, 5000).then((context) => {
        if (request !== requestSequence || !context) return;
        if (refreshInPlace) {
          app.querySelector(".content-frame").innerHTML = contextMarkup(context);
        } else {
          app.innerHTML = shell(contextMarkup(context));
        }
        applyPageScroll(scrollPosition);
        if (refreshInPlace) bindContent();
        else bind();
      }).catch(() => {});
    }
    if (currentPage === "updates" && updatePresentation(data).busy) startUpdatePolling();
    if (currentPage === "activity" && networkActivityState.mode === "live") updatePoll = window.setInterval(refreshNetworkActivity, 2000);
  } catch (error) {
    if (request !== requestSequence) return;
    if (refreshInPlace) {
      setRefreshBusy(false);
      setStatus("[data-live-status]", actionError(error, copy("feedback.refresh")));
    } else {
      app.innerHTML = pageFailure(error);
      applyPageScroll(scrollPosition);
      bind();
    }
  }
}

function setRefreshBusy(busy) {
  const shellElement = app.querySelector(".app-shell");
  if (!shellElement) return;
  shellElement.setAttribute("aria-busy", busy ? "true" : "false");
  const refreshButton = app.querySelector("[data-refresh], [data-updates-refresh]");
  if (busy) beginButton(refreshButton, copy("ui.refreshing"));
  else endButton(refreshButton);
}

function readPageScrollPosition() {
  const scrollingElement = document.scrollingElement || document.documentElement;
  return {
    left: window.scrollX || scrollingElement.scrollLeft || 0,
    top: window.scrollY || scrollingElement.scrollTop || 0,
  };
}

function applyPageScroll(position) {
  if (!position) {
    resetPageScroll();
    return;
  }
  window.requestAnimationFrame(() => {
    window.scrollTo({ left: position.left, top: position.top, behavior: "auto" });
    const scrollingElement = document.scrollingElement || document.documentElement;
    scrollingElement.scrollLeft = position.left;
    scrollingElement.scrollTop = position.top;
  });
}

function resetPageScroll() {
  window.requestAnimationFrame(() => {
    window.scrollTo({ top: 0, behavior: "auto" });
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  });
}

function bind() {
  try {
    app.querySelectorAll(".nav-item").forEach((element) => element.addEventListener("click", () => loadPage(element.dataset.page)));
    bindContent();
    if (!window.__greywardStartupInteractive) {
      window.__greywardStartupInteractive = true;
      startupMarkOnce("interactive_bind");
      requestAnimationFrame(() => startupMarkOnce("first_interactive_frame"));
    }
  } catch (error) {
    // A broken optional control must not strand the whole page on its loading
    // shell. Data loading and the remaining navigation stay usable.
    console.error("GREYWARD Security Center control binding failed", error);
  }
}
function bindContent() {
  app.querySelectorAll("[data-page]:not(.nav-item)").forEach((element) => element.addEventListener("click", () => loadPage(element.dataset.page)));
  app.querySelector("[data-file-context-back]")?.addEventListener("click", () => { fileContextDismissed = true; loadPage("overview"); });
  app.querySelector("[data-retry]")?.addEventListener("click", () => loadPage(currentPage, {force: true}));
  app.querySelector("[data-refresh]")?.addEventListener("click", () => currentPage === "activity" ? (networkActivityState.mode === "history" ? loadNetworkHistory() : refreshNetworkActivity()) : loadPage(currentPage, {force: true}));
  app.querySelector("[data-network-probe]")?.addEventListener("click", (event) => probeNetwork(event.currentTarget));
  app.querySelector("[data-updates-refresh]")?.addEventListener("click", () => loadPage("updates", {force: true}));
  app.querySelector("[data-update-resolve]")?.addEventListener("click", (event) => runUpdateAction("resolve_system_update", event.currentTarget, "CHECKING"));
  app.querySelector("[data-update-apply]")?.addEventListener("click", (event) => runUpdateAction("apply_system_update", event.currentTarget, "RESOLVING"));
  app.querySelector("[data-update-restart]")?.addEventListener("click", (event) => runUpdateAction("restart_apply_update", event.currentTarget, "RESTARTING"));
  app.querySelector("[data-update-cancel]")?.addEventListener("click", (event) => runUpdateAction("cancel_update", event.currentTarget, "CANCELLED"));
  app.querySelector("[data-updates-show-more]")?.addEventListener("click", () => { updateListState.limit += UPDATE_PAGE_SIZE; loadPage("updates", {force: true}); });
  app.querySelectorAll("[data-zone]").forEach((button) => button.addEventListener("click", () => changeZone(button.dataset.zone)));
  app.querySelectorAll("[data-network-set]").forEach((button) => button.addEventListener("click", () => setNetworkRule(button)));
  app.querySelectorAll("[data-threat-exception]").forEach((button) => button.addEventListener("click", () => setThreatException(button)));
  app.querySelectorAll("[data-threat-toggle]").forEach((button) => button.addEventListener("click", () => setThreatProtectionEnabled(button)));
  app.querySelectorAll("[data-network-remove]").forEach((button) => button.addEventListener("click", () => removeNetworkRule(button)));
  app.querySelectorAll("[data-deviation-id]").forEach((button) => button.addEventListener("click", () => runDeviation(button)));
  app.querySelectorAll("[data-profile]").forEach((button) => button.addEventListener("click", () => changeProfile(button.dataset.profile, button)));
  app.querySelector("[data-secure-dns-retry]")?.addEventListener("click", retrySecureDns);
  app.querySelector("[data-secure-dns-mode]")?.addEventListener("change", (event) => changeSecureDnsMode(event.currentTarget.value));
  app.querySelector("[data-recovery-create]")?.addEventListener("click", (event) => runRecoveryAction("create_recovery_point", event.currentTarget, copy("backup.action.createWorking"), "#recovery-point-status", copy("backup.action.createName")));
  app.querySelector("[data-recovery-cleanup]")?.addEventListener("click", (event) => runRecoveryAction("cleanup_recovery_points", event.currentTarget, copy("backup.action.cleanupWorking"), "#recovery-point-status", copy("backup.action.cleanupName")));
  app.querySelector("[data-backup-configure]")?.addEventListener("click", (event) => runRecoveryAction("configure_backup", event.currentTarget, copy("backup.action.chooseWorking"), "#backup-action-status", copy("backup.action.configurationName"), 900000));
  app.querySelector("[data-backup-now]")?.addEventListener("click", (event) => runRecoveryAction("backup_now", event.currentTarget, copy("backup.action.backupWorking"), "#backup-action-status", copy("backup.action.backupName"), 7200000));
  app.querySelector("[data-backup-verify]")?.addEventListener("click", (event) => runRecoveryAction("verify_backup", event.currentTarget, copy("backup.action.verifying"), "#backup-action-status", copy("backup.action.verificationName"), 14400000));
  app.querySelector("[data-backup-restore]")?.addEventListener("click", showBackupFiles);
  app.querySelector("[data-recovery-restore-confirm]")?.addEventListener("click", restoreSelectedFiles);
  app.querySelector("[data-recovery-restore-cancel]")?.addEventListener("click", () => resetRestorePicker());
  app.querySelector("[data-safe-open]")?.addEventListener("click", safeOpen);
  app.querySelector("[data-open-software]")?.addEventListener("click", (event) => launchSoftware(event.currentTarget));
  app.querySelector("[data-safe-open-pick]")?.addEventListener("click", pickSafeOpen);
  app.querySelector("[data-provenance]")?.addEventListener("click", showProvenance);
  app.querySelector("[data-sanitize]")?.addEventListener("click", createSanitizedCopy);
  app.querySelector("[data-file-scan-file]")?.addEventListener("click", () => pickAndStartFileSecurityScan("FILE", false));
  app.querySelector("[data-file-scan-folder]")?.addEventListener("click", () => pickAndStartFileSecurityScan("FOLDER", true));
  app.querySelector("[data-file-scan-system]")?.addEventListener("click", () => startFileSecurityScan("SYSTEM", null));
  bindFileSecurityOperation();
  app.querySelectorAll("[data-file-quarantine]").forEach((button) => button.addEventListener("click", () => quarantineFileSecurityDetection(button)));
  app.querySelectorAll("[data-file-restore]").forEach((button) => button.addEventListener("click", () => restoreFileSecurityDetection(button)));
  app.querySelectorAll("[data-file-delete]").forEach((button) => button.addEventListener("click", () => deleteFileSecurityDetection(button)));
  const activeFileOperation = app.querySelector("[data-file-operation]");
  if (currentPage === "files") {
    fileSecurityState.operationId = activeFileOperation?.dataset.fileOperation || null;
    if (activeFileOperation?.classList.contains("is-active")) startFileSecurityPolling();
    else stopFileSecurityPolling();
  }
  app.querySelectorAll("[data-action]").forEach((button) => button.addEventListener("click", () => runPrivacyAction(button.dataset.action === "export" ? "export_posture" : "clear_history", button)));
  bindNetworkActivityContent();
}
function bindFileSecurityOperation() {
  const bindOnce = (element, handler) => {
    if (!element || element.dataset.fileSecurityBound === "true") return;
    element.dataset.fileSecurityBound = "true";
    element.addEventListener("click", handler);
  };
  bindOnce(app.querySelector("[data-file-scan-cancel]"), (event) => cancelFileSecurityScan(event.currentTarget));
  bindOnce(app.querySelector("[data-file-scan-status-retry]"), () => refreshFileSecurityOperation());
}
async function runRecoveryAction(command, button, label, selector, name, timeout = 120000) {
  beginButton(button, label); setStatus(selector, copy("backup.operation.working", {name}));
  try {
    const result = await invokeBounded(command, undefined, timeout);
    if (result?.ok === false && !result.cancelled) {
      const error = new Error(result.error || result.message || `${name} failed.`);
      error.problem = result.problem;
      throw error;
    }
    setStatus(selector, result?.cancelled ? copy("feedback.cancelled") : copy("feedback.completed", {name}));
    if (currentPage === "devices") window.setTimeout(() => { if (currentPage === "devices") loadPage("devices", {force: true}); }, 300);
  } catch (error) {
    setStatus(selector, error.problem ? backupProblemCopy(error.problem) : actionError(error, name));
  } finally { endButton(button); }
}
function syncRestoreSelectionLimit() {
  const inputs = [...app.querySelectorAll("#recovery-file-list input")];
  const selected = inputs.filter((input) => input.checked);
  const limit = Number(app.querySelector("#recovery-restore-picker")?.dataset.selectionLimit || 100);
  inputs.forEach((input) => { input.disabled = !input.checked && selected.length >= limit; });
  const count = app.querySelector("#recovery-restore-count");
  if (count) count.textContent = copy("backup.restore.selected", {count: selected.length, limit});
}
function resetRestorePicker() {
  const panel = app.querySelector("#recovery-restore-picker");
  const list = app.querySelector("#recovery-file-list");
  const summary = app.querySelector("#recovery-restore-summary");
  const count = app.querySelector("#recovery-restore-count");
  if (panel) { panel.hidden = true; delete panel.dataset.selectionLimit; }
  if (list) list.replaceChildren();
  if (summary) summary.textContent = "";
  if (count) count.textContent = "";
}
async function showBackupFiles(event) {
  const button = event.currentTarget; beginButton(button, copy("backup.restore.loading")); setStatus("#backup-action-status", copy("backup.restore.reading"));
  try {
    const result = await invokeBounded("list_backup_files", undefined, 120000);
    const candidates = (Array.isArray(result?.candidates) ? result.candidates : (result?.files || []).map((path) => ({path, kind: "UNKNOWN"})))
      .map((candidate) => typeof candidate === "string" ? {path: candidate, kind: "UNKNOWN"} : candidate)
      .filter((candidate) => candidate && typeof candidate.path === "string" && candidate.path.length);
    const panel = app.querySelector("#recovery-restore-picker"); const list = app.querySelector("#recovery-file-list");
    if (!candidates.length) { resetRestorePicker(); setStatus("#backup-action-status", copy("backup.restore.empty")); return; }
    list.innerHTML = candidates.map((candidate) => {
      const kind = String(candidate.kind || "UNKNOWN").toUpperCase();
      const kindKey = kind === "DIRECTORY" ? "backup.restore.directory" : kind === "FILE" ? "backup.restore.file" : "backup.restore.unknown";
      return `<label class="recovery-file-option"><input type="checkbox" value="${esc(candidate.path)}"><span><strong>${esc(candidate.path)}</strong><small>${esc(copy(kindKey))}</small></span></label>`;
    }).join("");
    panel.dataset.selectionLimit = String(result?.selection_limit || 100);
    const visible = Number(result?.shown_count ?? candidates.length); const total = Number(result?.available_count ?? candidates.length);
    const summary = app.querySelector("#recovery-restore-summary");
    if (summary) summary.textContent = copy("backup.restore.available", {visible, total});
    list.querySelectorAll("input").forEach((input) => input.addEventListener("change", syncRestoreSelectionLimit));
    panel.hidden = false; syncRestoreSelectionLimit(); setStatus("#backup-action-status", visible < total ? copy("backup.restore.limitedCandidates", {shown: visible, total}) : copy("backup.restore.choose"));
  } catch (error) { setStatus("#backup-action-status", actionError(error, copy("backup.restore.listAction"))); }
  finally { endButton(button); }
}
async function restoreSelectedFiles(event) {
  const button = event.currentTarget; const paths = [...app.querySelectorAll("#recovery-file-list input:checked")].map((input) => input.value);
  const limit = Number(app.querySelector("#recovery-restore-picker")?.dataset.selectionLimit || 100);
  if (!paths.length) { setStatus("#backup-action-status", copy("backup.restore.required")); return; }
  if (paths.length > limit) { setStatus("#backup-action-status", copy("backup.restore.limit", {limit})); return; }
  beginButton(button, copy("backup.restore.staging")); setStatus("#backup-action-status", copy("backup.restore.stagingCopy"));
  try { const result = await invokeBounded("restore_backup_files", {paths}, 7200000); if (result?.ok === false) { const error = new Error(result.error || "Restore failed."); error.problem = result.problem; throw error; } resetRestorePicker(); setStatus("#backup-action-status", copy("backup.restore.staged", {path: result.staging_path || copy("backup.restore.defaultFolder")})); } catch (error) { setStatus("#backup-action-status", error.problem ? backupProblemCopy(error.problem) : actionError(error, copy("backup.restore.action"))); } finally { endButton(button); }
}
function setStatus(selector, message) { const text = String(message || ""); const element = app.querySelector(selector); if (element) element.textContent = text; const live = app.querySelector("[data-live-status]"); if (live && live !== element) live.textContent = element ? "" : text; }
function setDeviationFeedback(message) { deviationState.feedback = String(message || ""); setStatus(".deviation-action-status", deviationState.feedback); }
function setFileSecurityFeedback(message) {
  fileSecurityState.feedback = String(message || "");
  setStatus("#file-security-action-status", fileSecurityState.feedback);
}
function actionError(error, fallback) {
  const raw = String(error?.message || error || "").trim().replace(/\s+/g, " ");
  const message = raw.toLowerCase();
  const problem = raw.match(/^\[([A-Z_]+)\]/)?.[1];
  if (problem) return backupProblemCopy(problem);
  if (message.includes("does not support") || message.includes("no compatible") || message.includes("file handler")) return raw;
  if (message.includes("timed out")) return copy("feedback.timeout", {name: fallback});
  if (message.includes("controlling terminal")) return copy("feedback.authorizationSession", {name: fallback});
  if (message.includes("authentication agent") || message.includes("textual authentication")) return copy("feedback.authorizationAgent", {name: fallback});
  if (message.includes("wrong password") || message.includes("incorrect password") || message.includes("invalid password") || message.includes("no key found")) return copy("feedback.passphrase", {name: fallback});
  if (message.includes("outside the home") || message.includes("not an available directory") || message.includes("not writable") || message.includes("not mounted") || message.includes("mount could not be validated") || message.includes("findmnt is unavailable") || message.includes("mount identity") || message.includes("mount has changed")) return copy("backup.problem.destination");
  if (message.includes("configured restic repository")) return copy("feedback.repository", {name: fallback});
  if (message.includes("denied") || message.includes("refused")) return copy("feedback.access", {name: fallback});
  if (message.includes("unavailable")) return copy("feedback.service", {name: fallback});
  if (message.includes("destination")) return copy("feedback.destination", {name: fallback});
  if (message.includes("repository") || message.includes("restic")) return copy("feedback.repository", {name: fallback});
  return copy("feedback.retry", {name: fallback});
}
function beginButton(button, label) { if (!button) return; if (button.classList.contains("is-busy")) return; button.dataset.originalContent = button.innerHTML; button.disabled = true; button.setAttribute("aria-busy", "true"); button.classList.add("is-busy"); const iconSlot = button.querySelector(".action-icon"); if (iconSlot) iconSlot.innerHTML = '<span class="button-spinner" aria-hidden="true"></span>'; const labelSlot = button.querySelector(".action-label"); if (labelSlot) labelSlot.textContent = label; else button.textContent = label; }
function endButton(button) { if (!button || !button.classList.contains("is-busy")) return; if (button.dataset.originalContent) button.innerHTML = button.dataset.originalContent; delete button.dataset.originalContent; button.disabled = false; button.removeAttribute("aria-busy"); button.classList.remove("is-busy"); }
async function runUpdateAction(command, button, phase) { const buttons = [...app.querySelectorAll(".action-button")]; buttons.forEach((item) => { item.disabled = true; }); const pending = UPDATE_PHASE_PRESENTATION[phase] || UPDATE_PHASE_PRESENTATION.CHECKING; beginButton(button, copy(pending.stateKey)); setStatus("[data-update-status]", copy(pending.messageKey)); try { await invokeBounded(command, undefined, 15000); pageCache.delete("updates"); await loadPage("updates"); } catch (error) { setStatus("[data-update-status]", actionError(error, copy("feedback.update"))); buttons.forEach((item) => { item.disabled = false; }); endButton(button); } }
async function probeNetwork(button) { beginButton(button, copy("network.feedback.testing")); setStatus("#network-action-status", copy("network.feedback.probing")); try { const result = await invokeBounded("get_network_protection", undefined, 9000); result.probe_feedback = copy("network.feedback.probeComplete"); pageCache.set("network", {data: result, loadedAt: Date.now()}); const frame = app.querySelector(".content-frame"); if (frame && currentPage === "network") { frame.innerHTML = renderContent("network", result); bindContent(); } } catch (error) { setStatus("#network-action-status", actionError(error, copy("network.feedback.probeAction"))); endButton(button); } }
async function changeZone(target) { const buttons = [...app.querySelectorAll("[data-zone]")]; const button = buttons.find((item) => item.dataset.zone === target); buttons.forEach((item) => { item.disabled = true; }); beginButton(button, target === "trusted" ? copy("network.zone.trusting") : copy("network.zone.restoring")); setStatus("#network-action-status, #action-status", copy("network.zone.changing")); try { const network = await invokeBounded("get_network", undefined, 9000); if (!network.interface) throw new Error("No active connection is available."); const result = await invokeBounded("set_network_trust_zone", {interface: network.interface, target}, 15000); if (!result.ok) throw new Error(result.message || "The network zone could not be changed."); setStatus("#network-action-status, #action-status", copy("network.zone.updated")); await loadPage("network", {force: true}); } catch (error) { setStatus("#network-action-status, #action-status", actionError(error, copy("network.zone.action"))); buttons.forEach((item) => { item.disabled = false; }); endButton(button); } }
async function setNetworkRule(button) { const buttons = [...app.querySelectorAll("[data-network-set], [data-network-remove]")]; buttons.forEach((item) => { item.disabled = true; }); beginButton(button, copy("network.rule.saving")); const destination = {}; if (!button.dataset.networkDnsBypass && button.dataset.networkHost) destination.host = button.dataset.networkHost; if (!button.dataset.networkDnsBypass && button.dataset.networkIp) destination.ip = button.dataset.networkIp; if (button.dataset.networkPort) destination.port = Number(button.dataset.networkPort); const payload = {application: button.dataset.application, action: button.dataset.networkAction, duration: "always"}; if (Object.keys(destination).length) payload.destination = destination; setStatus("#network-action-status", button.dataset.networkDnsBypass ? copy("network.rule.savingDnsBypass") : copy(Object.keys(destination).length ? "network.rule.savingDestination" : "network.rule.saving")); try { const result = await invokeBounded("network_set_rule", {payload}, 15000); if (!result.ok) throw new Error(result.detail || "The network rule was refused."); networkActionState.feedback = copy(button.dataset.networkDnsBypass ? "network.rule.savedDnsBypass" : "network.rule.saved"); setStatus("#network-action-status", networkActionState.feedback); await loadPage("network", {force: true}); } catch (error) { setStatus("#network-action-status", actionError(error, copy("network.rule.action"))); buttons.forEach((item) => { item.disabled = false; }); endButton(button); } }
async function removeNetworkRule(button) { const buttons = [...app.querySelectorAll("[data-network-set], [data-network-remove]")]; buttons.forEach((item) => { item.disabled = true; }); beginButton(button, copy("network.rule.removing")); setStatus("#network-action-status", copy("network.rule.removing")); try { const result = await invokeBounded("network_remove_rule", {ruleId: button.dataset.ruleId}, 15000); if (!result.ok) throw new Error(result.detail || "The network rule could not be removed."); networkActionState.feedback = currentPage === "threats" ? copy("network.threats.revoked") : copy("network.rule.removed"); setStatus("#network-action-status", networkActionState.feedback); await loadPage(currentPage === "threats" ? "threats" : "network", {force: true}); } catch (error) { setStatus("#network-action-status", actionError(error, copy("network.rule.removeAction"))); buttons.forEach((item) => { item.disabled = false; }); endButton(button); } }
async function setThreatException(button) { const buttons = [...app.querySelectorAll("[data-threat-exception], [data-network-remove]")]; buttons.forEach((item) => { item.disabled = true; }); beginButton(button, copy("network.threats.allow")); const payload = {application: button.dataset.application, action: "allow", duration: "always", destination: {ip: button.dataset.threatIp, port: Number(button.dataset.threatPort)}}; setStatus("#network-action-status", copy("network.threats.action")); try { const result = await invokeBounded("network_set_threat_exception", {payload}, 15000); if (!result.ok) throw new Error(result.detail || "The threat exception was refused."); networkActionState.feedback = copy("network.threats.saved"); focusedThreatEventId = ""; await loadPage("threats", {force: true}); } catch (error) { setStatus("#network-action-status", actionError(error, copy("network.threats.action"))); buttons.forEach((item) => { item.disabled = false; }); endButton(button); } }
async function setThreatProtectionEnabled(button) { const enabled = button.textContent.includes(copy("network.threats.enable")); beginButton(button, enabled ? copy("network.threats.enable") : copy("network.threats.disable")); try { const result = await invokeBounded("set_threat_protection_enabled", {enabled}, 12000); if (!result.ok) throw new Error(result.detail || "The threat setting was refused."); networkActionState.feedback = enabled ? copy("network.threats.enabled") : copy("network.threats.disabled"); await loadPage("threats", {force: true}); } catch (error) { setStatus("#network-action-status", actionError(error, copy("network.threats.action"))); endButton(button); } }
function privacyActionError(error, fallback) { const raw = String(error?.message || error || "").trim().replace(/\s+/g, " "); return raw ? `${fallback}: ${raw}` : fallback; }
function setPrivacyProfilePendingDom(profile) { const surface = app.querySelector("[data-privacy-profile-state]"); if (!surface) return; surface.dataset.profilePending = profile || ""; surface.setAttribute("aria-busy", profile ? "true" : "false"); }
async function changeProfile(profile, button) {
  const target = String(profile || "").trim().toUpperCase();
  if (privacyState.profilePending || !["STANDARD", "PRIVATE", "TRAVEL"].includes(target)) return;
  privacyState.profilePending = target;
  privacyState.feedbackScope = "profile";
  privacyState.feedback = copy("privacy.feedback.changing");
  setPrivacyProfilePendingDom(target);
  pageCache.delete("privacy");
  app.querySelectorAll("[data-profile]").forEach((control) => { control.disabled = true; control.setAttribute("aria-disabled", "true"); });
  beginButton(button, copy("privacy.feedback.applying"));
  setStatus("#profile-action-status", privacyState.feedback);
  try {
    const result = await invokeBounded("set_privacy_profile", {profile: target}, 15000);
    const confirmed = String(result?.profile || "").trim().toUpperCase();
    if (result?.ok !== true || confirmed !== target) throw new Error(result?.message || copy("privacy.feedback.changeAction"));
    privacyState.feedback = copy("privacy.feedback.updated");
    privacyState.profilePending = null;
    if (currentPage === "privacy") await loadPage("privacy", {force: true});
  } catch (error) {
    privacyState.profilePending = null;
    privacyState.feedback = privacyActionError(error, copy("privacy.feedback.changeAction"));
    pageCache.delete("privacy");
    if (currentPage === "privacy") await loadPage("privacy", {force: true});
  } finally {
    if (privacyState.profilePending === null) endButton(button);
  }
}
async function changeSecureDnsMode(mode) { const control = app.querySelector("[data-secure-dns-mode]"); if (control) control.disabled = true; setStatus("#network-action-status", copy("network.dns.saving")); try { const result = await invokeBounded("set_secure_dns_mode", {mode}, 12000); if (!result.ok) throw new Error(result.detail || "DNS mode was refused."); await loadPage("network", {force: true}); } catch (error) { if (control) control.disabled = false; setStatus("#network-action-status", actionError(error, copy("network.dns.changeAction"))); } }
async function retrySecureDns() { const button = app.querySelector("[data-secure-dns-retry]"); beginButton(button, copy("network.dns.retrying")); setStatus("#network-action-status", copy("network.dns.retrying")); try { const result = await invokeBounded("retry_secure_dns", undefined, 12000); if (!result.ok) throw new Error(result.detail || "Secure DNS retry failed."); await loadPage("network", {force: true}); } catch (error) { setStatus("#network-action-status", actionError(error, copy("network.dns.retryAction"))); endButton(button); } }
async function launchSoftware(button) {
  beginButton(button, copy("applications.feedback.opening"));
  try {
    const result = await invokeBounded("open_software", undefined, 8000);
    if (result?.ok === false) throw new Error(result.message || "Software could not be opened.");
    setStatus("#applications-action-status", copy("applications.feedback.opened"));
    endButton(button);
  } catch (error) {
    endButton(button);
    setStatus("#applications-action-status", actionError(error, copy("applications.openSoftware")));
  }
}
async function runPrivacyAction(command, button) {
  if (privacyState.localActionPending || privacyState.profilePending) return;
  if (command === "clear_history" && !await confirmAction(copy("privacy.clear"), copy("privacy.clear.confirm"), copy("privacy.clear"), true)) return;
  const exportAction = command === "export_posture";
  privacyState.localActionPending = true;
  privacyState.feedbackScope = "local";
  privacyState.feedback = copy(exportAction ? "privacy.local.exporting" : "privacy.local.clearing");
  pageCache.delete("privacy");
  app.querySelectorAll("[data-action]").forEach((control) => { control.disabled = true; control.setAttribute("aria-disabled", "true"); });
  beginButton(button, copy(exportAction ? "privacy.local.exportingShort" : "privacy.local.clearingShort"));
  setStatus("#action-status", privacyState.feedback);
  try {
    const result = await invokeBounded(command, undefined, 12000);
    if (result?.ok !== true) throw new Error(result?.message || "The local data action failed.");
    if (exportAction) {
      const path = String(result.path || "").trim();
      if (!path) throw new Error("The export completed without a returned destination.");
      privacyState.exportPath = path;
      privacyState.feedback = copy("privacy.local.exported", {path});
      setStatus("#action-status", privacyState.feedback);
    } else {
      privacyState.feedback = copy("privacy.local.updated");
      await loadPage("privacy", {force: true});
    }
  } catch (error) {
    privacyState.feedback = privacyActionError(error, copy(exportAction ? "privacy.local.exportAction" : "privacy.local.clearAction"));
    setStatus("#action-status", privacyState.feedback);
  } finally {
    privacyState.localActionPending = false;
    endButton(button);
    if (currentPage === "privacy" && exportAction) setStatus("#action-status", privacyState.feedback);
  }
}
async function runDeviation(button) { const accepted = button.dataset.deviationAccepted === "true"; const pageBeforeAction = currentPage; const workingCopy = copy(accepted ? "evidence.deviation.recording" : "evidence.deviation.removing"); beginButton(button, workingCopy); setDeviationFeedback(workingCopy); try { const updatedOverview = await invokeBounded("set_deviation", {checkId: button.dataset.deviationId, accepted}, 12000); pageCache.delete("system"); pageCache.delete("devices"); pageCache.delete("evidence"); if (updatedOverview?.posture && Array.isArray(updatedOverview.domains)) pageCache.set("overview", {data: updatedOverview, loadedAt: Date.now()}); else pageCache.delete("overview"); await loadPage(pageBeforeAction); setDeviationFeedback(copy(accepted ? "evidence.deviation.recorded" : "evidence.deviation.removed")); } catch (error) { endButton(button); setDeviationFeedback(actionError(error, copy("evidence.deviation.action"))); } }
async function pickSafeOpen() { const button = app.querySelector("[data-safe-open-pick]"); beginButton(button, copy("file.safeOpen.choose")); try { const result = await invokeBounded("pick_safe_open_file", undefined, 300000); if (result) { app.querySelector("#safe-open-path").value = result; setStatus("#safe-open-status", copy("file.feedback.selected")); } else { setStatus("#safe-open-status", copy("file.safeOpen.noneSelected")); } } catch (error) { setStatus("#safe-open-status", actionError(error, copy("file.selection.action"))); } finally { endButton(button); } }
function beginFileContextAction(button, label) {
  if (fileContextActionPending) return false;
  fileContextActionPending = true;
  app.querySelectorAll("[data-safe-open], [data-provenance], [data-sanitize]").forEach((control) => { control.disabled = true; });
  beginButton(button, label);
  return true;
}
function endFileContextAction(button) {
  fileContextActionPending = false;
  app.querySelectorAll("[data-safe-open], [data-provenance], [data-sanitize]").forEach((control) => { control.disabled = false; });
  endButton(button);
}
async function safeOpen() { const input = app.querySelector("#safe-open-path"); const button = app.querySelector("[data-safe-open]"); const path = input?.value.trim(); if (!path) { setStatus("#safe-open-status", copy("file.feedback.chooseFirst")); return; } if (!beginFileContextAction(button, copy("file.feedback.opening"))) return; setStatus("#safe-open-status", copy("file.feedback.openingCopy")); try { const result = await invokeBounded("safe_open", {path}, 15000); if (!result.ok) throw new Error(result.detail || "Restricted view could not start."); setStatus("#safe-open-status", copy("file.feedback.opened")); } catch (error) { setStatus("#safe-open-status", actionError(error, copy("file.safeOpen.action"))); } finally { endFileContextAction(button); } }
async function showProvenance() { const path = app.querySelector("#safe-open-path")?.value.trim(); const button = app.querySelector("[data-provenance]"); if (!path) { setStatus("#provenance-status", copy("file.feedback.chooseFirst")); return; } if (!beginFileContextAction(button, copy("file.feedback.reading"))) return; setStatus("#provenance-status", copy("file.feedback.readingCopy")); try { const result = await invokeBounded("get_provenance", {path}, 12000); setStatus("#provenance-status", `${provenanceSummary(result)}. ${result.limitation || copy("file.feedback.evidenceLimit")}`); } catch (error) { setStatus("#provenance-status", actionError(error, copy("file.information.action"))); } finally { endFileContextAction(button); } }
async function createSanitizedCopy() { const path = app.querySelector("#safe-open-path")?.value.trim(); const button = app.querySelector("[data-sanitize]"); if (!path) { setStatus("#provenance-status", copy("file.feedback.chooseFirst")); return; } if (!beginFileContextAction(button, copy("file.feedback.creating"))) return; setStatus("#provenance-status", copy("file.feedback.creatingCopy")); try { const result = await invokeBounded("sanitize_copy", {path}, 15000); if (!result.ok) throw new Error(result.detail || "Sanitization was refused."); setStatus("#provenance-status", copy("file.feedback.sanitized", {path: result.output || copy("file.feedback.localOutput")})); } catch (error) { setStatus("#provenance-status", actionError(error, copy("file.sanitize.action"))); } finally { endFileContextAction(button); } }

async function startFileSecurityScan(mode, path) {
  if (mode === "SYSTEM" && !await confirmAction(copy("files.scanSystem"), copy("file.scan.confirm"), copy("files.scanSystem"))) return;
  try {
    const result = await invokeBounded("start_file_security_scan", {mode, paths: path ? [path] : []}, 15000);
    if (!result?.operation_id) throw new Error(result?.detail || "The scan could not start.");
    fileSecurityState.operationId = result.operation_id;
    setFileSecurityFeedback(copy("file.feedback.scanStarted"));
    startFileSecurityPolling();
    await refreshFileSecurityOperation();
  } catch (error) {
    setFileSecurityFeedback(actionError(error, copy("file.scan.action")));
  }
}
async function pickAndStartFileSecurityScan(mode, directory) {
  try {
    const path = await invokeBounded("pick_file_security_source", {directory}, 300000);
    if (path) await startFileSecurityScan(mode, path);
  } catch (error) {
    setFileSecurityFeedback(actionError(error, copy("file.selection.action")));
  }
}
async function refreshFileSecurityOperation() {
  if (!fileSecurityState.operationId || fileSecurityState.requestBusy) return;
  fileSecurityState.requestBusy = true;
  try {
    const result = await invokeBounded("get_file_security_scan_status", {operationId: fileSecurityState.operationId}, 10000);
    const operation = app.querySelector("#file-security-operation");
    if (operation) { operation.innerHTML = fileSecurityOperationMarkup(result); bindFileSecurityOperation(); }
    const state = String(result?.state || "").toUpperCase();
    if (!["QUEUED", "SCANNING", "FINALIZING"].includes(state)) {
      stopFileSecurityPolling();
      window.setTimeout(() => { if (currentPage === "files") loadPage("files", {force: true}); }, 250);
    } else {
      // Scan progress is asynchronous and can be slow. Back off while it is
      // active so the status D-Bus call does not compete with the scan itself.
      fileSecurityState.pollDelayMs = Math.min(fileSecurityState.pollDelayMs + 500, 3000);
      scheduleFileSecurityPolling();
    }
  } catch (error) {
    const operation = app.querySelector("#file-security-operation");
    stopFileSecurityPolling();
    setFileSecurityFeedback(copy("file.scan.statusUnavailableCopy"));
    if (operation) { operation.innerHTML = `${emptyState(copy("file.scan.statusUnavailable"), copy("file.scan.statusUnavailableCopy"), "warning")}${actionButton(copy("file.scan.retryStatus"), copy("file.scan.retryStatusDetail"), "secondary", "data-file-scan-status-retry", "refresh")}`; bindFileSecurityOperation(); }
  } finally {
    fileSecurityState.requestBusy = false;
  }
}
function startFileSecurityPolling() {
  if (fileSecurityState.polling) return;
  fileSecurityState.pollDelayMs = 900;
  refreshFileSecurityOperation();
}
function scheduleFileSecurityPolling() {
  if (fileSecurityState.polling || !fileSecurityState.operationId || document.hidden) return;
  fileSecurityState.polling = window.setTimeout(() => {
    fileSecurityState.polling = null;
    refreshFileSecurityOperation();
  }, fileSecurityState.pollDelayMs);
}
function stopFileSecurityPolling() {
  if (fileSecurityState.polling) window.clearTimeout(fileSecurityState.polling);
  fileSecurityState.polling = null;
}
async function cancelFileSecurityScan(button) {
  beginButton(button, copy("file.scan.cancelling"));
  try {
    const result = await invokeBounded("cancel_file_security_scan", {operationId: button.dataset.fileScanCancel}, 10000);
    if (String(result?.state || "").toUpperCase() === "UNAVAILABLE") throw new Error(result.detail || "Scan cancellation is unavailable.");
    setFileSecurityFeedback(copy("file.feedback.cancelRequested"));
    await refreshFileSecurityOperation();
  } catch (error) {
    setFileSecurityFeedback(actionError(error, copy("file.scan.cancellation")));
    endButton(button);
  }
}
async function quarantineFileSecurityDetection(button) {
  beginButton(button, copy("file.quarantine.moving"));
  try {
    const result = await invokeBounded("quarantine_file_security_detection", {detectionId: button.dataset.fileQuarantine}, 30000);
    if (result?.state === "QUARANTINE_FAILED") throw new Error(result.detail || "Quarantine failed.");
    setFileSecurityFeedback(copy("file.feedback.quarantined"));
    await loadPage("files", {force: true});
  } catch (error) {
    setFileSecurityFeedback(actionError(error, copy("file.quarantine.action")));
    endButton(button);
  }
}
async function restoreFileSecurityDetection(button) {
  if (!await confirmAction(copy("file.action.restore"), copy("file.restore.confirm"), copy("file.action.restore"))) return;
  beginButton(button, copy("file.restore.working"));
  try {
    const result = await invokeBounded("restore_file_security_detection", {detectionId: button.dataset.fileRestore, destination: null}, 30000);
    if (result?.state === "RESTORE_FAILED") throw new Error(result.detail || "Restore failed.");
    setFileSecurityFeedback(copy("file.feedback.restored", {path: result?.staging_path || result?.restore_staging_path || copy("ui.unavailable")}));
    await loadPage("files", {force: true});
  } catch (error) {
    setFileSecurityFeedback(actionError(error, copy("file.restore.action")));
    endButton(button);
  }
}
async function deleteFileSecurityDetection(button) {
  if (!await confirmAction(copy("file.action.delete"), copy("file.delete.confirm"), copy("file.action.delete"), true)) return;
  beginButton(button, copy("file.delete.working"));
  try {
    const result = await invokeBounded("delete_file_security_detection", {detectionId: button.dataset.fileDelete}, 30000);
    if (result?.state === "DELETE_FAILED") throw new Error(result.detail || "Permanent deletion failed.");
    setFileSecurityFeedback(copy("file.feedback.deleted"));
    await loadPage("files", {force: true});
  } catch (error) {
    setFileSecurityFeedback(actionError(error, copy("file.delete.action")));
    endButton(button);
  }
}

let navigationRequestBusy = false;
let navigationPoll = null;
async function consumeNavigationRequest() {
  if (document.hidden || navigationRequestBusy || !window.__TAURI_INTERNALS__?.invoke) return;
  navigationRequestBusy = true;
  try {
    const raw = await invokeBounded("consume_navigation_request", undefined, 2500);
    const [requestedPage, eventId] = String(raw || "").split("|", 2);
    const page = normalizePage(requestedPage);
    if (page && pages.includes(page)) {
      focusedThreatEventId = page === "threats" ? String(eventId || "") : "";
      await loadPage(page, {force: page === "threats"});
    }
  } catch (_) {
    // Navigation is an optional shell affordance; the current page remains usable.
  } finally {
    navigationRequestBusy = false;
  }
}
function stopNavigationPolling() {
  if (navigationPoll) window.clearInterval(navigationPoll);
  navigationPoll = null;
}
function startNavigationPolling() {
  if (navigationPoll || document.hidden) return;
  // This is only a compatibility fallback for the file-backed launcher
  // handoff; normal in-app navigation and state changes use events.
  navigationPoll = window.setInterval(consumeNavigationRequest, 1500);
}
function handleVisibilityChange() {
  if (document.hidden) {
    stopNavigationPolling();
    if (updatePoll) { window.clearInterval(updatePoll); updatePoll = null; }
    stopFileSecurityPolling();
    return;
  }
  startNavigationPolling();
  if (currentPage === "activity") {
    if (networkActivityState.mode === "live") refreshNetworkActivity();
    else loadNetworkHistory();
  } else {
    loadPage(currentPage);
  }
}
function bindStateEvents() {
  if (eventsBound || !window.__TAURI__?.event?.listen) return;
  eventsBound = true;
  window.__TAURI__.event.listen("security-state-changed", () => { if (!document.hidden && currentPage !== "updates") { if (currentPage === "privacy" && (privacyState.profilePending || privacyState.localActionPending)) return; currentPage === "activity" ? refreshNetworkActivity() : loadPage(currentPage, {force: true}); } });
  window.__TAURI__.event.listen("security-navigation", ({payload}) => {
    const [requestedPage, eventId] = String(payload || "").split("|", 2);
    const page = normalizePage(requestedPage);
    if (pages.includes(page)) {
      focusedThreatEventId = page === "threats" ? String(eventId || "") : "";
      loadPage(page, {force: page === "threats"});
    }
  });
}
bindStateEvents();
document.addEventListener("visibilitychange", handleVisibilityChange);
startupMarkOnce("frontend_bootstrap_complete");
const startupParameters = new URLSearchParams(window.location.search);
focusedThreatEventId = startupParameters.get("event") || "";
loadPage(startupParameters.get("page") || "overview");
consumeNavigationRequest();
startNavigationPolling();


// Native dialog top-layer provides modal focus containment and Escape handling.
// Kept outside #app so background reads cannot discard a pending decision.
function confirmAction(title, description, confirmLabel, destructive = false) {
  if (document.querySelector(".confirmation-dialog")) return Promise.resolve(false);
  const trigger = document.activeElement;
  const dialog = document.createElement("dialog");
  dialog.className = "confirmation-dialog";
  dialog.setAttribute("aria-labelledby", "confirmation-title");
  dialog.setAttribute("aria-describedby", "confirmation-description");
  dialog.innerHTML = `<form method="dialog"><div class="dialog-symbol ${destructive ? "is-destructive" : ""}">${icon(destructive ? "clean" : "file")}</div><h2 id="confirmation-title">${esc(title)}</h2><p id="confirmation-description">${esc(description)}</p><div class="dialog-actions"><button class="action-button secondary" value="cancel" autofocus>${esc(copy("ui.cancel"))}</button><button class="action-button ${destructive ? "destructive" : "primary"}" value="confirm">${esc(confirmLabel)}</button></div></form>`;
  document.body.append(dialog);
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      const accepted = dialog.returnValue === "confirm";
      dialog.remove();
      if (trigger?.isConnected) trigger.focus({preventScroll: true});
      resolve(accepted);
    }, {once: true});
    dialog.showModal();
  });
}
function viewControlKey(element) {
  if (!element) return null;
  if (element.id) return `#${CSS.escape(element.id)}`;
  const attribute = [...element.attributes].find((item) => item.name.startsWith("data-"));
  return attribute ? `${element.localName}[${attribute.name}="${CSS.escape(attribute.value)}"]` : null;
}
function disclosureKey(element) {
  const summary = element.querySelector(":scope > summary");
  const label = summary?.querySelector("span")?.textContent?.trim() || summary?.textContent?.trim() || "";
  const owner = element.closest("[data-view-key]")?.dataset.viewKey || element.closest("article")?.querySelector("strong")?.textContent?.trim() || "";
  return `${owner}::${label}`;
}
function captureViewState() {
  const frame = app.querySelector(".content-frame");
  const active = document.activeElement;
  return {
    open: [...(frame?.querySelectorAll("details[open]") || [])].map(disclosureKey),
    focus: frame?.contains(active) ? viewControlKey(active) : null,
    summary: frame?.contains(active) && active.localName === "summary" ? disclosureKey(active.parentElement) : null,
  };
}
function restoreViewState(state) {
  const frame = app.querySelector(".content-frame");
  if (!frame || !state) return;
  for (const details of frame.querySelectorAll("details")) {
    if (state.open.includes(disclosureKey(details))) details.open = true;
    if (!document.querySelector("dialog[open]") && state.summary === disclosureKey(details)) details.querySelector("summary")?.focus({preventScroll: true});
  }
  if (state.focus && !document.querySelector("dialog[open]")) frame.querySelector(state.focus)?.focus({preventScroll: true});
}
