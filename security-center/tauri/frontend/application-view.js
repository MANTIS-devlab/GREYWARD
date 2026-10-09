// Shared presentation for Application Guard and Protected Data. Receipts,
// authorization and policy changes remain in the existing typed controller.
(() => {
  const categories = ["CREDENTIALS", "CLOUD", "DEVELOPMENT", "BROWSER_SESSION", "CUSTOM"];
  const resourceGlyphs = Object.freeze({CREDENTIALS: "key", CLOUD: "cloud", DEVELOPMENT: "script", BROWSER_SESSION: "browser", CUSTOM: "folder"});
  const providerGlyphs = Object.freeze({RPM: "package", FLATPAK: "applications", APP_IMAGE: "package", SCRIPT: "script", MANUAL: "file"});
  const coverageKeys = ["graphical_session", "user_manager", "direct_exec", "services_and_scheduled_jobs",
    "enrolled_remote_sessions", "protected_resource_labels"];
  function protection(snapshot) {
    const profile = snapshot?.effective_profile;
    const verified = snapshot?.health === "AVAILABLE" && ["PROTECTED", "ISOLATED", "TRUSTED"].includes(profile)
      && snapshot.requested_profile === profile && coverageKeys.every(key => snapshot.coverage?.[key] === true)
      && Number.isSafeInteger(snapshot.policy_revision) && snapshot.policy_revision > 0
      && Number.isFinite(snapshot.evidence_age_ms) && snapshot.evidence_age_ms >= 0 && snapshot.evidence_age_ms <= 30000
      && (profile !== "TRUSTED" || snapshot.reviewed_exception === true)
      && (profile !== "ISOLATED" || ["private_home", "filesystem_scope", "namespaces", "landlock", "seccomp", "network_denied"].every(key => snapshot.isolation?.[key] === true)
        && (!snapshot.isolation.display_required || snapshot.isolation.private_display === true));
    return {verified, state: verified ? profile : ["UNAVAILABLE", "DEGRADED", "UNKNOWN"].includes(snapshot?.health) ? snapshot.health : "UNKNOWN"};
  }
  function create({esc, copy, icon, live, time, eventRow}) {
    function overviewPosture(posture, data) {
      if (!["PROTECTED", "SECURE"].includes(posture.state)
          || protection(live(data?.coverage)?.protection).verified) return posture;
      return {...posture, state: "REVIEW NEEDED", tone: "review",
        message_key: "guard.overview.incomplete", care_key: "guard.overview.care"};
    }
    function overviewDomains(domains, data) {
      const value = protection(live(data?.coverage)?.protection);
      return domains.map(domain => domain.name_key === "evidence.domain.applications"
        && ["PROTECTED", "SECURE"].includes(domain.state) && !value.verified
        ? {...domain, state: value.state, tone: "unavailable", context_key: "guard.overview.incomplete", destination: "applications"}
        : domain);
    }
    const label = state => copy(`guard.health.${state}`);
    const badge = (state, verified = false) => `<span class="guard-badge${verified ? " is-verified" : ""}" data-state="${esc(state)}">${esc(label(state))}</span>`;
    function summary(data) {
      const snapshot = live(data?.coverage)?.protection;
      const connected = !!snapshot || !!live(data?.envelope);
      const connection = connected ? "connected" : data?.coverage || data?.envelope ? "unavailable" : "reading";
      const value = protection(snapshot);
      if (!snapshot && data?.coverage?.source_state?.state === "UNAVAILABLE") value.state = "UNAVAILABLE";
      return `<article class="guard-hero"><span class="guard-emblem" aria-hidden="true">${icon("shield")}</span><div class="guard-hero-main"><div class="eyebrow">${esc(copy("guard.protection"))}</div><h2>${esc(copy(`guard.session.${value.state}`))}</h2><p>${esc(copy(value.verified ? "guard.verified" : `guard.session.copy.${value.state}`))}</p><p class="guard-limits">${esc(copy("guard.portal.unverified"))}</p><p class="guard-connection" data-guard-connection="${connection}">${esc(copy(`guard.connection.${connection}`))}</p></div>${badge(value.state, value.verified)}<div class="guard-hero-foot"><span>${icon("lock")} ${esc(copy("guard.scope.data"))}</span><span>${icon("applications")} ${esc(copy("guard.scope.tools"))}</span><span>${icon("activity")} ${esc(copy("guard.scope.activity"))}</span></div></article>`;
    }
    function overviewSummary(data) {
      const value = protection(live(data?.coverage)?.protection);
      return `<article class="overview-protection"><span class="guard-item-icon" aria-hidden="true">${icon("lock")}</span><div><strong>${esc(copy(`guard.session.${value.state}`))}</strong><p>${esc(copy(value.verified ? "guard.verified" : `guard.session.copy.${value.state}`))}</p></div>${badge(value.state, value.verified)}<button class="text-button" data-page="protected-data">${esc(copy("guard.resources.title"))} ${icon("arrow")}</button></article>`;
    }
    function grantRows(grants, applications = [], resources = []) {
      return grants.map(grant => {
        const identity = applications.find(item => item.record?.identity?.installation_ref === grant.installation_ref)?.record.identity;
        const names = (grant.resources || []).map(ref => resources.find(item => item.resource_ref === ref)?.label).filter(Boolean);
        return `<article class="guard-grant-row"><span class="guard-item-icon" aria-hidden="true">${icon("key")}</span><div><strong>${esc(identity?.display_name || copy("guard.reviewedTool"))}</strong><p>${esc(names.join(", ") || copy("guard.selectedResources"))}</p><small>${esc(copy("guard.grant.recorded"))}</small></div><button class="text-button" data-guard-revoke="${esc(grant.grant_ref)}">${esc(copy("guard.revoke"))}</button></article>`;
      }).join("") || `<p class="guard-empty-inline">${esc(copy("guard.noGrants"))}</p>`;
    }
    function itemRow(item, kind) {
      const resource = kind === "resources", identity = item.record?.identity;
      const reference = resource ? item.resource_ref : identity?.installation_ref;
      if (!reference) return "";
      const title = resource ? item.label : identity.display_name || copy("guard.unnamedApplication");
      const state = resource ? {state: ["PROTECTED", "NOT_PRESENT", "UNAVAILABLE", "DEGRADED", "UNKNOWN"].includes(item.coverage) ? item.coverage : "UNKNOWN", verified: item.coverage === "PROTECTED"} : protection(item.protection);
      const subtitle = resource ? copy(`guard.category.${item.category}`) : `${copy(`guard.provider.${identity.provider}`)} · ${copy(`guard.provenance.${identity.provenance.state}`)}`;
      return `<article class="guard-item" data-view-key="${esc(reference)}" data-guard-search="${esc(`${title} ${subtitle}`.toLocaleLowerCase())}"><span class="guard-item-icon" aria-hidden="true">${icon(resource ? resourceGlyphs[item.category] || "folder" : providerGlyphs[identity.provider] || "applications")}</span><div class="guard-item-copy"><h3>${esc(title)}</h3><p>${esc(subtitle)}</p></div>${badge(state.state, state.verified)}<button class="text-button" data-guard-detail="${esc(reference)}" data-guard-kind="${kind}" aria-label="${esc(copy("guard.openDetails", {name: title}))}">${esc(copy("guard.details"))} ${icon("arrow")}</button></article>`;
    }
    function inventory(data, kind, {resourceLabel = "", resourceCategory = "CUSTOM", query = ""} = {}) {
      const resource = kind === "resources", projection = live(data?.envelope);
      const items = projection?.[kind] || [], grants = data?.grants?.grants || [];
      const canChange = !!projection && data?.grants?.capabilities?.policy_changes === true;
      const canIsolate = !!projection && data?.grants?.capabilities?.isolation === true;
      const changesUnavailable = resource && !!projection && data?.grants?.capabilities?.policy_changes === false;
      const controls = resource && canChange ? `<details class="guard-add"><summary>${icon("folder")} ${esc(copy("guard.addResource"))}</summary><p>${esc(copy("guard.addResource.copy"))}</p><form id="guard-register-form" class="guard-register-form"><label for="guard-resource-label">${esc(copy("guard.resourceLabel"))}<input id="guard-resource-label" value="${esc(resourceLabel)}" maxlength="128" required autocomplete="off" placeholder="${esc(copy("guard.resourceLabel.placeholder"))}"></label><label for="guard-resource-category">${esc(copy("guard.resourceCategory"))}<select id="guard-resource-category">${categories.map(category => `<option value="${category}"${category === resourceCategory ? " selected" : ""}>${esc(copy(`guard.category.${category}`))}</option>`).join("")}</select></label><button class="action-button secondary" type="submit">${esc(copy("guard.register"))} ${icon("arrow")}</button></form></details>`
        : !resource && canIsolate ? `<aside class="guard-isolation"><span class="guard-item-icon" aria-hidden="true">${icon("isolation")}</span><div><h3>${esc(copy("guard.isolation.title"))}</h3><p>${esc(copy("guard.isolation.copy"))}</p></div><button class="action-button secondary" data-guard-run>${esc(copy("guard.run"))} ${icon("arrow")}</button></aside>`
        : changesUnavailable ? `<aside class="guard-isolation guard-setup"><span class="guard-item-icon" aria-hidden="true">${icon("lock")}</span><div><h3>${esc(copy("guard.setup.title"))}</h3><p>${esc(copy("guard.setup.copy"))}${canIsolate ? ` ${esc(copy("guard.setup.isolation"))}` : ""}</p></div>${canIsolate ? `<button class="action-button secondary" data-page="applications">${esc(copy("guard.setup.applications"))} ${icon("arrow")}</button>` : ""}</aside>` : "";
      const list = resource ? categories.map(category => {
        const members = items.filter(item => item.category === category);
        if (!members.length) return "";
        return `<section class="guard-category"><div class="section-heading"><h3>${esc(copy(`guard.category.${category}`))}</h3><span class="section-meta">${esc(members.length)}</span></div>${members.map(item => itemRow(item, kind)).join("")}</section>`;
      }).join("") : items.map(item => itemRow(item, kind)).join("");
      const empty = `<div class="guard-empty"><span class="guard-item-icon" aria-hidden="true">${icon(resource ? "folder" : "applications")}</span><h3>${esc(copy(projection ? "guard.empty" : "guard.unavailable"))}</h3><p>${esc(copy(projection ? "guard.empty.copy" : "guard.unavailable.copy"))}</p></div>`;
      return `${summary(data)}${controls}<section class="guard-workspace"><div class="section-heading"><div><div class="eyebrow">${esc(copy(resource ? "guard.catalogue" : "guard.inventory"))}</div><h2>${esc(copy(resource ? "guard.registeredResources" : "guard.registeredApplications"))}</h2></div>${items.length ? `<label class="guard-search">${icon("search")}<span class="sr-only">${esc(copy("guard.search"))}</span><input type="search" data-guard-search-input value="${esc(query)}" placeholder="${esc(copy("guard.search"))}" autocomplete="off"></label>` : ""}</div><div class="guard-items">${list || empty}</div><p class="guard-no-results" hidden role="status">${esc(copy("guard.noResults"))}</p>${projection?.next_cursor ? `<button class="text-button" data-guard-more="${kind}">${esc(copy("guard.more"))}</button>` : ""}</section>${data?.grants ? `<details class="guard-access"${grants.length ? " open" : ""}><summary><span>${esc(copy("guard.grants"))}</span><span class="section-meta">${esc(grants.length)}</span></summary><p>${esc(copy("guard.grants.copy"))}</p>${grantRows(grants, resource ? [] : items, resource ? items : [])}</details>` : ""}<section id="guard-detail" aria-live="polite" hidden></section><div id="guard-action-status" class="action-status" role="status" aria-live="polite"></div>`;
    }
    function detail(item, kind, grants, canChange) {
      const identity = item.record?.identity, resource = kind === "resources";
      const title = item.label || identity?.display_name || copy("guard.unnamedApplication");
      const state = resource ? {state: item.coverage || "UNKNOWN", verified: item.coverage === "PROTECTED"} : protection(item.protection);
      const subtitle = resource ? copy(`guard.category.${item.category}`) : `${copy(`guard.provider.${identity?.provider}`)} · ${copy(`guard.provenance.${identity?.provenance.state}`)}`;
      const facts = resource ? copy("guard.resource.scope") : copy("guard.permissions.copy");
      return `<article class="guard-detail" tabindex="-1"><header><div><div class="eyebrow">${esc(copy(resource ? "guard.resources.title" : "guard.protection"))}</div><h2>${esc(title)}</h2><p>${esc(subtitle)}</p></div><button class="text-button" data-guard-close aria-label="${esc(copy("guard.closeDetails"))}">${esc(copy("guard.close"))}</button></header><div class="guard-detail-state">${badge(state.state, state.verified)}<p>${esc(copy(resource ? state.verified ? "guard.resource.verified" : "guard.resource.unverified" : state.verified ? "guard.verified" : "guard.unverified"))}</p></div><section><h3>${esc(copy("guard.permissions"))}</h3><p>${esc(facts)}</p>${!resource ? `<button class="text-button" data-page="network">${esc(copy("guard.network.link"))} ${icon("arrow")}</button>` : ""}</section><section><div class="section-heading"><h3>${esc(copy("guard.grants"))}</h3>${resource && canChange ? `<button class="action-button secondary" data-guard-grant="${esc(item.resource_ref)}">${esc(copy("guard.reviewGrant"))}</button>` : ""}</div><p>${esc(copy("guard.grants.copy"))}</p>${resource ? `<p>${esc(copy("guard.grant.supported"))}</p>` : ""}${grantRows(grants, identity ? [item] : [], resource ? [item] : [])}</section><div id="guard-detail-events" aria-live="polite"></div><details class="technical-disclosure"><summary>${esc(copy("ui.technical"))}</summary><pre>${esc(JSON.stringify(item, null, 2))}</pre></details></article>`;
    }
    function events(history) {
      const events = Array.isArray(history?.events) ? history.events : null;
      const outcomes = {COMPLETED: "completed", SUCCESS: "completed", BLOCKED: "blocked", DENIED: "blocked", FAILED: "failed", CANCELLED: "cancelled"};
      return `<section class="guard-timeline"><div class="section-heading"><div><div class="eyebrow">${esc(copy("guard.scope.activity"))}</div><h3>${esc(copy("guard.activity"))}</h3></div></div>${events ? events.slice(0, 100).map(event => {
        if (eventRow) return eventRow(event, history.presentation_context);
        const sensitive = event.event_type === "SENSITIVE_ACCESS_BLOCKED";
        const confirmedDenial = sensitive && event.source === "root-kernel-selinux-audit"
          && event.outcome === "DENIED" && event.decision === "DENIED"
          && event.quality?.confidence === "KERNEL_DECISION"
          && ["AVAILABLE", "PARTIAL"].includes(event.quality?.source_state);
        const key = sensitive && !confirmedDenial ? "guard.event.sensitiveUnconfirmed" : `guard.event.${event.event_type}`;
        const title = copy(key) === key ? copy("guard.event.other") : copy(key);
        const outcome = sensitive && !confirmedDenial ? "unknown" : outcomes[event.outcome] || "unknown";
        return `<article class="guard-event"><span class="guard-event-marker" aria-hidden="true">${icon(confirmedDenial ? "lock" : "activity")}</span><div><strong>${esc(title)}</strong><p>${esc(copy(`guard.outcome.${outcome}`))}</p></div><time>${esc(time(event.occurred_at, copy("ui.unknown")))}</time><details class="technical-disclosure"><summary>${esc(copy("ui.technical"))}</summary><pre>${esc(JSON.stringify({source:event.source,quality:event.quality,details:event.details},null,2))}</pre></details></article>`;
      }).join("") || `<p class="guard-empty-inline">${esc(copy("guard.activity.empty"))}</p>` : `<p>${esc(copy("guard.unavailable.copy"))}</p>`}</section>`;
    }
    return Object.freeze({summary, inventory, detail, events, overviewPosture, overviewDomains, overviewSummary});
  }
  window.GREYWARD_APPLICATION_VIEW = Object.freeze({create, protection});
})();
