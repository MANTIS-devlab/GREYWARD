(() => {
  "use strict";
  const categories = ["APPLICATION_SECURITY", "FILE_SECURITY", "DEVICES", "RECOVERY", "UPDATE", "LOCAL_ACTIVITY", "SYSTEM_ACTIVITY"];
  const destinations = {APPLICATION_SECURITY: "applications", FILE_SECURITY: "files", DEVICES: "devices", RECOVERY: "recovery", UPDATE: "updates", LOCAL_ACTIVITY: "privacy"};
  function create({request, copy, esc, icon, time, context = async () => ({}), identityMark, behavioral}) {
    let category = "", cursor = null, severity="", severitySort=false;
    const filters = () => ({scope: "SECURITY", limit: 60, ...(category && category!=="SYSTEM_ACTIVITY" ? {category} : {}), ...(cursor ? {cursor} : {})});
    function select(value) { category = categories.includes(value) ? value : ""; cursor = null; behavioral?.reset("SYSTEM"); behavioral?.reset("ALL"); }
    function older(value) { cursor = typeof value === "string" ? value : null; }
    function reset() { cursor = null; behavioral?.reset("SYSTEM"); behavioral?.reset("ALL"); }
    async function read() {
      const [data, labels, observation] = await Promise.all([
        category==="SYSTEM_ACTIVITY" ? Promise.resolve({events:[],source_state:{state:"NOT_REQUESTED"}}) : request("query_telemetry", {filters: filters()}, 12000),
        context().catch(() => ({})),
        behavioral && (!category || category==="SYSTEM_ACTIVITY") ? behavioral.read(category==="SYSTEM_ACTIVITY"?"SYSTEM":"ALL",{...(!category&&!severity&&!behavioral.focus()?{min_score:1}:{}),...(severity?{classification:severity}:{}),sort:severitySort?"severity":"time"}) : null,
      ]);
      return {...data, presentation_context: labels, behavioral_snapshot: observation};
    }
    function row(event, labels = {}) {
      const domain = categories.includes(event.category) ? event.category : "OTHER";
      const authoritativeBlock = event.event_type === "SENSITIVE_ACCESS_BLOCKED"
        && event.outcome === "DENIED" && event.decision === "DENIED" && event.source === "root-kernel-selinux-audit"
        && event.quality?.confidence === "KERNEL_DECISION" && ["AVAILABLE", "PARTIAL"].includes(event.quality?.source_state);
      const details = event.details || {};
      const observed = authoritativeBlock && details.observed_process?.source === "KERNEL_AUDIT"
        && Number.isSafeInteger(details.observed_process.pid) && details.observed_process.pid > 0
        && /^[A-Za-z0-9._+\-]{1,128}$/.test(details.observed_process.executable_name || "") ? details.observed_process : null;
      const reference = /^[a-z_]+_[a-f0-9]{64}$/.test(event.application || "");
      const named = event.application && !reference ? event.application : labels.applications?.[event.application];
      const actor = named || observed?.executable_name || copy(authoritativeBlock ? "history.actor.unknown" : "history.actor.system");
      const actorKind = named ? "history.actor.application" : observed ? "history.actor.process" : authoritativeBlock ? "history.actor.unrecorded" : "history.actor.operation";
      const resources = Array.isArray(details.resource_refs) ? details.resource_refs.slice(0, 8) : [];
      const resourceNames = resources.map(ref => labels.resources?.[ref] || copy("history.resource.unnamed"));
      const titleKey = `guard.event.${event.event_type}`;
      const local = event.source === "security-center/presentation" && event.event_type === "LOCAL_ACTION" ? details.local : null;
      const actionKey = `history.action.${event.action}`;
      const title = event.event_type === "SENSITIVE_ACCESS_BLOCKED" && !authoritativeBlock ? copy("guard.event.sensitiveUnconfirmed")
        : authoritativeBlock ? copy(actionKey) : local?.title || (copy(titleKey) !== titleKey ? copy(titleKey) : copy(`history.category.${domain}`));
      const outcome = authoritativeBlock ? "blocked" : ({SUCCESS:"completed", COMPLETED:"completed", FAILURE:"failed", FAILED:"failed", STARTED:"started", CANCELLED:"cancelled"}[event.outcome] || "unknown");
      const reason = authoritativeBlock ? copy("history.reason.denied")
        : event.source === "root-broker-operation-readback" && details.verified_readback === true && event.outcome === "COMPLETED" ? copy("history.reason.policyVerified")
        : local ? (Array.isArray(local.detail_parts) ? local.detail_parts.filter(v => typeof v === "string").slice(0, 2).join(" ") : copy("history.reason.local"))
        : copy("history.reason.unrecorded");
      const glyph = observed ? /^(python[0-9.]*|bash|sh|node|perl|ruby)$/.test(observed.executable_name) ? "script" : "terminal"
        : ({APPLICATION_SECURITY:"shield",FILE_SECURITY:"files",DEVICES:"devices",RECOVERY:"recovery",UPDATE:"updates",LOCAL_ACTIVITY:"privacy"}[domain] || "history");
      const mark = named && identityMark ? identityMark("application", named) : icon(glyph);
      const destination = labels.links === false ? null : authoritativeBlock || resources.length ? "protected-data" : destinations[event.category];
      const behavioral = globalThis.GREYWARD_BEHAVIORAL?.badge(event.behavioral || (authoritativeBlock ? {classification:'POLICY_BLOCKED',score:null,confidence:'HIGH'} : null)) || '';
      const fact = (label, value) => value == null ? "" : `<div><dt>${esc(copy(label))}</dt><dd>${esc(value)}</dd></div>`;
      return `<article class="history-event" data-history-event="${esc(event.event_id || "")}"><span class="history-marker" aria-hidden="true">${mark}</span><div class="history-event-copy"><div class="history-actor"><strong>${esc(actor)}</strong><span>${esc(copy(actorKind))}</span></div><h3>${esc(title)}</h3>${resourceNames.length ? `<p class="history-resource">${icon("folder")} ${esc(resourceNames.join(" · "))}</p>` : ""}<p class="history-reason">${esc(reason)}</p><details class="technical-disclosure"><summary>${esc(copy("history.details"))}</summary><dl>${fact("history.record", event.event_type || copy("ui.unknown"))}${fact("history.source", event.source || copy("ui.unknown"))}${fact("history.outcome", event.outcome || "UNKNOWN")}${fact("history.action", event.action)}${fact("history.decision", event.decision)}${observed ? fact("history.process", `${observed.executable_name} · PID ${observed.pid}`) + fact("history.attribution", copy("history.process.limit")) : authoritativeBlock ? fact("history.attribution", copy("history.process.missing")) : ""}${fact("applications.technical.identifier", event.application)}${resources.length ? fact("history.resource.reference", resources.join(" · ")) + fact("history.resource.labels", copy("history.resource.current")) : ""}${fact("history.revision", details.policy_revision)}${fact("history.failure", details.failure)}${fact("history.when", time(event.occurred_at, copy("ui.unknown")))}${details.audit_truncated ? fact("history.collection", copy("history.collection.partial")) : ""}</dl></details></div><div class="history-event-end">${behavioral}<span class="history-decision ${outcome}">${authoritativeBlock ? icon("lock") : ""}${esc(copy(`guard.outcome.${outcome}`))}</span><time>${esc(time(event.occurred_at, copy("ui.unknown")))}</time>${destination ? `<button class="text-button" data-page="${destination}">${esc(copy(authoritativeBlock ? "history.review.resource" : "history.open"))} ${icon("arrow")}</button>` : ""}</div></article>`;
    }
    function markup(data) {
      const available = data?.source_state?.state === "AVAILABLE";
      const events = available && Array.isArray(data.events) ? data.events.filter(event => event.category !== "NETWORK") : [];
      const observed=data?.behavioral_snapshot;
      const system=Array.isArray(observed?.events)?observed.events:[];
      const grade=e=>e.behavioral?.classification || (e.event_type==='SENSITIVE_ACCESS_BLOCKED'&&e.source==='root-kernel-selinux-audit'&&e.outcome==='DENIED'&&e.decision==='DENIED'&&e.quality?.confidence==='KERNEL_DECISION'&&['AVAILABLE','PARTIAL'].includes(e.quality?.source_state)?'POLICY_BLOCKED':'UNKNOWN');
      const rows=[...events.filter(e=>!severity||grade(e)===severity).map(e=>({at:e.occurred_at,score:e.behavioral?.score??-1,html:row(e,data.presentation_context)})),...system.map(e=>({at:e.occurred_at,score:e.score??-1,html:behavioral.historyRow(e,observed)}))];
      rows.sort((a,b)=>severitySort?b.score-a.score:Date.parse(b.at||0)-Date.parse(a.at||0));
      const assessmentFilters=behavioral?`<div class="behavioral-filters"><label>Assessment <select data-history-severity><option value="">All classifications</option>${Object.entries(globalThis.GREYWARD_BEHAVIORAL.names).map(([v,n])=>`<option value="${v}" ${severity===v?'selected':''}>${esc(n)}</option>`).join('')}</select></label><button class="text-button" data-history-score-sort>Sort: ${severitySort?'severity':'time'}</button></div>`:'';
      const empty = `<div class="empty-state"><span class="empty-icon">${icon("history")}</span><div><strong>${esc(copy(available || (observed && ["ACTIVE","DEGRADED"].includes(observed.sensor?.state)) ? "history.empty" : "history.unavailable"))}</strong><p>${esc(copy(available || (observed && ["ACTIVE","DEGRADED"].includes(observed.sensor?.state)) ? "history.empty.copy" : "history.unavailable.copy"))}</p></div></div>`;
      return `<section class="history-workspace"><div class="history-toolbar"><label for="history-category">${esc(copy("history.filter"))}<select id="history-category" data-history-category><option value="">${esc(copy("history.all"))}</option>${categories.map(value => `<option value="${value}"${category === value ? " selected" : ""}>${esc(copy(`history.category.${value}`))}</option>`).join("")}</select></label><span>${esc(copy("history.retention"))}</span>${assessmentFilters}</div>${observed?behavioral.status(observed,category==="SYSTEM_ACTIVITY"?"SYSTEM":"ALL"):""}<div class="history-events">${rows.length ? rows.slice(0,120).map(e=>e.html).join("") : empty}</div><div class="history-pagination">${cursor ? `<button class="text-button" data-history-latest>${esc(copy("history.latest"))}</button>` : ""}${available && data.next_cursor ? `<button class="action-button secondary" data-history-older="${esc(data.next_cursor)}">${esc(copy("history.older"))} ${icon("arrow")}</button>` : ""}</div></section><aside class="history-context"><span class="ui-icon">${icon("network")}</span><div><strong>${esc(copy("history.network"))}</strong><p>${esc(copy("history.network.copy"))}</p></div><button class="text-button" data-page="activity">${esc(copy("network.activity.title"))} ${icon("arrow")}</button></aside>`;
    }
    function assess(value){severity=globalThis.GREYWARD_BEHAVIORAL?.names[value]?value:"";reset();}
    function sortScore(){severitySort=!severitySort;reset();}
    return Object.freeze({read, select, older, reset, markup, filters, row, assess, sortScore});
  }
  globalThis.GREYWARD_SECURITY_HISTORY = Object.freeze({create});
})();
