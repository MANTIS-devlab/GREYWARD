/* Network rule presentation. All normalization, authorization and writes stay
   behind the existing typed Security Context boundary. */
(() => {
  const en = {
    title: "Network rules", intro: "Choose what applications can reach and which incoming connections this computer accepts.",
    applications: "Applications", incoming: "Incoming access", new: "New rule", search: "Search rules", refresh: "Refresh",
    empty: "No rules here yet", emptyCopy: "Create a rule, or start from a connection in Network Activity.",
    unavailable: "Rule service unavailable", unavailableCopy: "Your existing security services continue independently. No rule has been assumed active.",
    name: "Rule name", executable: "Executable path", executableHint: "Matches this executable, including code and extensions it runs. Individual Flatpak and script identities are not yet supported.",
    action: "Action", allow: "Allow", deny: "Block", lifetime: "Duration", permanent: "Permanent", boot: "Until reboot", "15m": "15 minutes", "1h": "One hour",
    destinations: "Destinations", destinationHint: "Leave empty for any destination. Separate entries with commas: example.org, *.example.org, 203.0.113.4, 2001:db8::/32.",
    advanced: "Advanced options", protocols: "Protocol", both: "TCP and UDP", anyProtocol: "Any IP protocol", ports: "Ports", portsHint: "Empty means any port. For example: 443, 8000-8010.",
    family: "Address family", any: "IPv4 and IPv6", scope: "Applies to", user: "My account", system: "All users", zone: "Firewall zone", service: "Service", customPorts: "Custom ports", source: "Source address or subnet", sourceHint: "Empty means any source in the selected zone.",
    description: "Note", review: "Review changes", apply: "Authenticate and apply", cancel: "Cancel", edit: "Edit", duplicate: "Duplicate", disable: "Disable", enable: "Enable", remove: "Delete", up: "Move earlier", down: "Move later",
    reviewTitle: "Review network changes", reviewCopy: "These changes are not applied yet. Authentication confirms this exact transaction.",
    saving: "Waiting for protected authentication…", saved: "Policy saved for future matching connections. Existing connections may remain open.",
    previewError: "The change could not be reviewed.", applyError: "The change was not applied.", loading: "Reading current rules…", import: "Import", export: "Export", importHint: "Import adds reviewed rules; it does not replace your existing policy.",
    exportTitle: "Export network rules", exportCopy: "This export contains all rules for the selected provider and their network scopes. Review it before sharing.",
    selected: "Selected rules", enabled: "Enabled", disabled: "Disabled", all: "All states", next: "Next", previous: "Previous", total: "rules", owner: "GREYWARD", currentPage: "Export this page", close: "Close",
    savedState: "Saved", loadedState: "Loaded by engine", observedState: "Observed matching", expiredState: "Expired", disabledState: "Disabled", unavailableState: "Unavailable",
    nativeScope: "Executable scope", wholeSystem: "System-wide incoming access", allowNotice: "Allow does not block other destinations. Managed DNS and threat restrictions still apply.",
    revokeNotice: "Deleting or disabling a rule changes future decisions; it does not recover data or necessarily close established connections.",
    noEdit: "An active administrator session is required to change rules.", sameEngine: "OpenSnitch controls application connections. firewalld controls incoming access.",
    summary: "Rule summary", importError: "Choose a valid GREYWARD network-rule export of at most 1 MiB.", pending: "Saved is not the same as observed enforcement.",
    external: "Existing firewalld configuration", readOnly: "Managed elsewhere · read only", runtime: "Runtime", permanentPlane: "Permanent configuration", limited: "This provider disclosure is limited to 128 entries.", serviceDefined: "Service-defined ports and protocols", active: "Active rules", matches: "Observed decisions", lastUsed: "Last observed", undo: "Undo last change", anyDestination: "Any destination", anySource: "Any source", exportAll: "Export rules",
  };
  const fr = {
    title: "Règles réseau", intro: "Choisissez les destinations accessibles aux applications et les connexions entrantes acceptées par cet ordinateur.",
    applications: "Applications", incoming: "Accès entrant", new: "Nouvelle règle", search: "Rechercher des règles", refresh: "Actualiser",
    empty: "Aucune règle pour le moment", emptyCopy: "Créez une règle ou partez d’une connexion dans l’activité réseau.",
    unavailable: "Service de règles indisponible", unavailableCopy: "Les services de sécurité continuent indépendamment. Aucune règle n’est supposée active.",
    name: "Nom de la règle", executable: "Chemin de l’exécutable", executableHint: "Cible cet exécutable, y compris le code et les extensions qu’il lance. Les identités Flatpak et de scripts individuelles ne sont pas encore prises en charge.",
    action: "Action", allow: "Autoriser", deny: "Bloquer", lifetime: "Durée", permanent: "Permanente", boot: "Jusqu’au redémarrage", "15m": "15 minutes", "1h": "Une heure",
    destinations: "Destinations", destinationHint: "Vide : toute destination. Séparez par des virgules : example.org, *.example.org, 203.0.113.4, 2001:db8::/32.",
    advanced: "Options avancées", protocols: "Protocole", both: "TCP et UDP", anyProtocol: "Tout protocole IP", ports: "Ports", portsHint: "Vide : tout port. Exemple : 443, 8000-8010.",
    family: "Famille d’adresses", any: "IPv4 et IPv6", scope: "S’applique à", user: "Mon compte", system: "Tous les utilisateurs", zone: "Zone du pare-feu", service: "Service", customPorts: "Ports personnalisés", source: "Adresse ou sous-réseau source", sourceHint: "Vide : toute source dans la zone sélectionnée.",
    description: "Note", review: "Examiner les changements", apply: "S’authentifier et appliquer", cancel: "Annuler", edit: "Modifier", duplicate: "Dupliquer", disable: "Désactiver", enable: "Activer", remove: "Supprimer", up: "Placer avant", down: "Placer après",
    reviewTitle: "Examiner les changements réseau", reviewCopy: "Rien n’est encore appliqué. L’authentification confirme cette transaction précise.",
    saving: "En attente de l’authentification protégée…", saved: "Politique enregistrée pour les prochaines connexions correspondantes. Les connexions existantes peuvent rester ouvertes.",
    previewError: "Impossible d’examiner le changement.", applyError: "Le changement n’a pas été appliqué.", loading: "Lecture des règles actuelles…", import: "Importer", export: "Exporter", importHint: "L’import ajoute des règles après examen ; il ne remplace pas votre politique.",
    exportTitle: "Exporter les règles réseau", exportCopy: "Cet export contient toutes les règles du fournisseur sélectionné et leur portée réseau. Examinez-le avant de le partager.",
    selected: "Règles sélectionnées", enabled: "Activée", disabled: "Désactivée", all: "Tous les états", next: "Suivante", previous: "Précédente", total: "règles", owner: "GREYWARD", currentPage: "Exporter cette page", close: "Fermer",
    savedState: "Enregistrée", loadedState: "Chargée par le moteur", observedState: "Correspondance observée", expiredState: "Expirée", disabledState: "Désactivée", unavailableState: "Indisponible",
    nativeScope: "Portée de l’exécutable", wholeSystem: "Accès entrant pour le système", allowNotice: "Autoriser ne bloque pas les autres destinations. Les restrictions DNS et contre les menaces restent applicables.",
    revokeNotice: "Supprimer ou désactiver une règle modifie les décisions futures ; cela ne récupère pas les données et ne ferme pas nécessairement les connexions existantes.",
    noEdit: "Une session administrateur active est nécessaire pour modifier les règles.", sameEngine: "OpenSnitch contrôle les connexions des applications. firewalld contrôle l’accès entrant.",
    summary: "Résumé de la règle", importError: "Choisissez un export GREYWARD valide de 1 Mio maximum.", pending: "Enregistrée ne signifie pas que l’application effective a été observée.",
    external: "Configuration firewalld existante", readOnly: "Gestion externe · lecture seule", runtime: "Active à l’exécution", permanentPlane: "Configuration permanente", limited: "Cette vue du fournisseur est limitée à 128 entrées.", serviceDefined: "Ports et protocoles du service", active: "Règles actives", matches: "Décisions observées", lastUsed: "Dernière observation", undo: "Annuler le dernier changement", anyDestination: "Toute destination", anySource: "Toute source", exportAll: "Exporter les règles",
  };
  const catalogs = Object.fromEntries(Object.entries({en, fr}).map(([locale, catalog]) => [locale,
    Object.fromEntries(Object.entries(catalog).map(([key, value]) => [`network.rules.${key}`, value]))]));
  function destinations(value) {
    return String(value || "").split(/[,\n]/).map(v => v.trim()).filter(Boolean).map(value => ({
      kind: value.startsWith("*.") ? "domain" : value.includes("/") ? "network" : value.includes(":") || /^\d+(\.\d+){3}$/.test(value) ? "ip" : "host",
      value: value.startsWith("*.") ? value.slice(2) : value,
    }));
  }
  function portsText(value) { if (typeof value === "string") return value; return (value || []).map(([a, b]) => a === b ? String(a) : `${a}-${b}`).join(", "); }
  function destinationText(value) { return (value || []).map(d => (d.kind === "domain" ? "*." : "") + d.value).join(", "); }
  function create({request, esc, icon, identity, t}) {
    const state = {provider: "application", data: null, draft: null, editing: null, preview: null, busy: false, error: "", feedback: "", search: "", filter: "", offset: 0, selected: new Set(), exportText: "", undo: null};
    let root = null, searchTimer = null, loadSequence = 0, previewSequence = 0;
    const c = key => t(`network.rules.${key}`);
    const call = async (method, payload, timeout = 15000) => {
      const result = await request(`network_rules_${method}`, {payload}, timeout);
      if (result?.ok !== true) throw new Error(result?.detail || c("unavailable"));
      return result;
    };
    async function load() {
      const sequence = ++loadSequence;
      try {
        const data = await call("list", {provider: state.provider, offset: state.offset, search: state.search, state: state.filter});
        if (sequence !== loadSequence) return state.data;
        state.data = data;
        state.error = "";
      } catch (error) { if (sequence === loadSequence) { state.data = null; state.error = String(error.message); } }
      return state.data;
    }
    function fresh(values = {}) {
      previewSequence++;
      state.draft = {provider: state.provider, name: "", path: "", action: "deny", scope: "user", lifetime: "permanent", enabled: true,
        protocols: ["tcp", "udp"], ports: [], family: "any", destinations: [], zone: state.data?.catalog?.zones?.includes("public") ? "public" : state.data?.catalog?.zones?.[0] || "", service: "", source: "", description: "", ...values};
      state.editing = null; state.preview = null; state.error = "";
    }
    const options = (values, selected) => values.map(([value, label]) => `<option value="${esc(value)}"${value === selected ? " selected" : ""}>${esc(label)}</option>`).join("");
    const field = (name, label, value, hint = "", type = "text") => `<label class="network-rule-field"><span>${esc(c(label))}</span><input name="${name}" type="${type}" value="${esc(value ?? "")}" maxlength="${name === "path" ? 4096 : 500}"${name === "path" ? ' list="network-executable-options"' : ""}>${hint ? `<small>${esc(c(hint))}</small>` : ""}</label>`;
    const select = (name, label, values, selected) => `<label class="network-rule-field"><span>${esc(c(label))}</span><select name="${name}">${options(values, selected)}</select></label>`;
    function summary(rule) {
      if (!rule) return "";
      const target = rule.provider === "incoming" ? `${rule.service || portsText(rule.ports)} · ${rule.zone}` : rule.path;
      const destination = rule.provider === "incoming" ? rule.source : destinationText(rule.destinations);
      return `${c(rule.action || "edit")} · ${target || rule.name || c("executable")} · ${destination || c(rule.provider === "incoming" ? "anySource" : "anyDestination")} · ${rule.service ? c("serviceDefined") : `${(rule.protocols || []).join("/").toUpperCase()} ${portsText(rule.ports)}`} · ${c(rule.lifetime || "permanent")}`;
    }
    function editor() {
      const d = state.draft;
      if (!d) return "";
      const incoming = state.provider === "incoming";
      return `<aside class="network-rule-editor"><div class="section-heading"><h2>${esc(c(state.editing ? "edit" : "new"))}</h2><button type="button" class="text-button" data-rule-close${state.busy ? " disabled" : ""}>${esc(c("close"))}</button></div><form data-rule-form><fieldset${state.busy ? " disabled" : ""}>
        ${field("name", "name", d.name)}
        ${incoming ? select("zone", "zone", (state.data?.catalog?.zones || []).map(z => [z, z]), d.zone) + select("service", "service", [["", c("customPorts")], ...(state.data?.catalog?.services || []).map(s => [s, s])], d.service) + field("source", "source", d.source, "sourceHint") : field("path", "executable", d.path, "executableHint") + `<datalist id="network-executable-options">${(state.data?.applications || []).map(a => `<option value="${esc(a.path)}">${esc(a.name)}</option>`).join("")}</datalist>` + field("destinations", "destinations", destinationText(d.destinations), "destinationHint")}
        <div class="network-rule-field-pair">${select("action", "action", [["deny", c("deny")], ["allow", c("allow")]], d.action)}${select("lifetime", "lifetime", ["permanent", "boot", "15m", "1h"].map(v => [v, c(v)]), d.lifetime)}</div>
        <details class="network-rule-advanced"><summary>${esc(c("advanced"))}</summary>
          ${select("protocol", "protocols", [["both", c("both")], ["tcp", "TCP"], ["udp", "UDP"], ...(!incoming ? [["any", c("anyProtocol")]] : [])], d.protocols?.includes("any") ? "any" : d.protocols?.length === 2 ? "both" : d.protocols?.[0])}
          ${field("ports", "ports", portsText(d.ports), "portsHint")}
          ${select("family", "family", [["any", c("any")], ["ipv4", "IPv4"], ["ipv6", "IPv6"]], d.family)}
          ${!incoming ? select("scope", "scope", [["user", c("user")], ["system", c("system")]], d.scope) : ""}${field("description", "description", d.description)}
        </details><div class="network-rule-summary"><span class="eyebrow">${esc(c("summary"))}</span><output data-rule-summary>${esc(summary(d))}</output></div>
        <p class="network-rule-note">${esc(c(incoming ? "wholeSystem" : "allowNotice"))}</p>
        <button class="primary" type="submit"${state.busy || !state.data?.capabilities?.edit ? " disabled" : ""}>${esc(c("review"))} ${icon("arrow")}</button>
      </fieldset></form></aside>`;
    }
    function review() {
      if (!state.preview) return "";
      return `<section class="network-rule-review" role="region" aria-label="${esc(c("reviewTitle"))}"><h2>${esc(c("reviewTitle"))}</h2><p>${esc(c("reviewCopy"))}</p><div class="network-rule-change-list">${state.preview.changes.map(change => `<article><strong>${esc(change.operation)} · ${esc(change.rule.name)}</strong><p>${esc(summary(change.rule))}</p></article>`).join("")}</div>${state.preview.warnings.map(w => `<p class="network-rule-warning">${esc(w)}</p>`).join("")}<div class="network-rule-actions"><button class="primary" data-rule-apply${state.busy ? " disabled" : ""}>${esc(c(state.busy ? "saving" : "apply"))}</button><button class="secondary" data-rule-cancel>${esc(c("cancel"))}</button></div></section>`;
    }
    function markup() {
      const data = state.data;
      const rows = data?.rules || [];
      const rowsMarkup = rows.map(rule => {
        const label = ({SAVED: "savedState", LOADED: "loadedState", OBSERVED: "observedState", EXPIRED: "expiredState", DISABLED: "disabledState", UNAVAILABLE: "unavailableState"})[rule.state] || "savedState";
        return `<article class="network-rule-card" data-rule-id="${esc(rule.id)}"><input type="checkbox" data-rule-select="${esc(rule.id)}" aria-label="${esc(rule.name)}"${state.selected.has(rule.id) ? " checked" : ""}>
          <span class="guard-item-icon" aria-hidden="true">${state.provider === "application" ? identity("application", [rule.path, rule.name]) : icon("network")}</span>
          <div class="network-rule-identity"><strong>${esc(rule.name)}</strong><p>${esc(summary(rule))}</p><small>${esc(c(state.provider === "application" ? "nativeScope" : "wholeSystem"))} · ${esc(rule.scope === "user" ? `${c("user")} (${rule.uid})` : c("system"))}${rule.observed ? ` · ${esc(c("matches"))}: ${esc(rule.observed.decisions)} · ${esc(c("lastUsed"))}: ${esc(rule.observed.last_seen || "—")}` : ""}</small></div>
          <span class="network-rule-state state-${esc(rule.state.toLowerCase())}">${esc(c(label))}</span>
          <details class="network-rule-menu"><summary aria-label="${esc(c("edit"))}">•••</summary><div>${["edit", "duplicate", rule.enabled ? "disable" : "enable", "up", "down", "remove"].map(action => `<button type="button" data-rule-action="${action}" data-id="${esc(rule.id)}"${!data.capabilities?.edit ? " disabled" : ""}>${esc(c(action))}</button>`).join("")}</div></details></article>`;
      }).join("");
      return `<section class="network-rules-product" data-network-rules><header class="network-rules-header"><div><div class="eyebrow">${esc(t("nav.network"))}</div><h1>${esc(c("title"))}</h1><p>${esc(c("intro"))}</p></div><button class="primary" data-rule-new${!data?.capabilities?.edit ? " disabled" : ""}>${icon("plus")} ${esc(c("new"))}</button></header>
        <div class="network-rules-tabs" role="group" aria-label="${esc(c("title"))}">${["application", "incoming"].map(provider => `<button data-rule-provider="${provider}" aria-pressed="${state.provider === provider}" class="${state.provider === provider ? "active" : ""}">${esc(c(provider === "application" ? "applications" : "incoming"))}</button>`).join("")}</div>
        <p class="network-rule-note">${esc(c("sameEngine"))}</p>
        <div class="network-rules-toolbar"><input data-rule-search aria-label="${esc(c("search"))}" placeholder="${esc(c("search"))}" value="${esc(state.search)}"><select data-rule-filter aria-label="${esc(c("all"))}">${options([["", c("all")], ["ACTIVE", c("active")], ["DISABLED", c("disabledState")], ["EXPIRED", c("expiredState")]], state.filter)}</select><button class="secondary" data-rule-refresh>${icon("refresh")} ${esc(c("refresh"))}</button><button class="secondary" data-rule-import${!data?.capabilities?.edit ? " disabled" : ""}>${esc(c("import"))}</button><input type="file" accept="application/json,.json" data-rule-import-file hidden><button class="secondary" data-rule-export${!rows.length ? " disabled" : ""}>${esc(c("export"))}</button></div>
        <div role="status" aria-live="polite" class="network-rule-feedback">${esc(state.busy ? c("saving") : state.error || state.feedback || data?.detail || "")}${state.undo && !state.busy ? `<button class="text-button" data-rule-undo>${esc(c("undo"))}</button>` : ""}</div>
        ${state.preview ? review() : ""}<div class="network-rules-layout${state.draft ? " has-editor" : ""}"><div><div class="network-rule-bulk"${state.selected.size ? "" : " hidden"}><span>${state.selected.size} ${esc(c("selected"))}</span>${["enable", "disable", "remove"].map(a => `<button class="text-button" data-rule-bulk="${a}">${esc(c(a))}</button>`).join("")}</div>
          ${!data ? `<div class="empty-state"><h2>${esc(c("unavailable"))}</h2><p>${esc(c("unavailableCopy"))}</p></div>` : rows.length ? rowsMarkup : `<div class="empty-state"><h2>${esc(c("empty"))}</h2><p>${esc(c("emptyCopy"))}</p></div>`}
          <footer class="network-rule-pagination"><span>${data?.total || 0} ${esc(c("total"))}</span><button class="text-button" data-rule-page="previous"${!state.offset ? " disabled" : ""}>${esc(c("previous"))}</button><button class="text-button" data-rule-page="next"${data?.next_offset == null ? " disabled" : ""}>${esc(c("next"))}</button></footer><p class="network-rule-note">${esc(c("revokeNotice"))}</p></div>${editor()}</div>
        ${state.provider === "incoming" && data?.external?.rules?.length ? `<details class="technical-disclosure"><summary>${esc(c("external"))} (${data.external.rules.length})</summary><p class="network-rule-note">${esc(c("readOnly"))}</p>${data.external.rules.map(r => `<article class="network-rule-external"><strong>${esc(r.zone)} · ${esc(r.kind)}</strong><p>${esc(r.value)}</p><small>${esc([r.runtime ? c("runtime") : "", r.permanent ? c("permanentPlane") : ""].filter(Boolean).join(" / "))}</small></article>`).join("")}${data.external.truncated ? `<p>${esc(c("limited"))}</p>` : ""}</details>` : ""}
        ${state.exportText ? `<section class="network-rule-export"><h2>${esc(c("exportTitle"))}</h2><p>${esc(c("exportCopy"))}</p><textarea readonly aria-label="${esc(c("exportTitle"))}">${esc(state.exportText)}</textarea><a class="secondary" data-rule-download download="greyward-network-rules.json">${esc(c("exportAll"))}</a><button class="text-button" data-rule-export-close>${esc(c("close"))}</button></section>` : ""}</section>`;
    }
    function draw() {
      if (!root?.isConnected) return;
      const focused = root.querySelector(":focus");
      const focusSelector = focused?.hasAttribute("data-rule-search") ? "[data-rule-search]"
        : focused?.dataset?.ruleSelect ? `[data-rule-select="${focused.dataset.ruleSelect}"]`
        : focused?.name ? `[name="${focused.name}"]` : null;
      const selection = focused?.selectionStart == null ? null : [focused.selectionStart, focused.selectionEnd];
      const parent = root.parentElement;
      root.outerHTML = markup(); root = parent.querySelector("[data-network-rules]"); bind(root);
      if (focusSelector) {
        const next = root.querySelector(focusSelector); next?.focus();
        if (selection && next?.setSelectionRange) next.setSelectionRange(...selection);
      }
    }
    async function reload() { await load(); state.selected.clear(); draw(); }
    async function exportDocument() {
      const rows = []; let offset = 0; const revision = state.data.revision;
      do {
        const page = await call("list", {provider: state.provider, offset});
        if (page.revision !== revision || !Array.isArray(page.rules) || rows.length + page.rules.length > 1024) throw new Error(c("previewError"));
        rows.push(...page.rules);
        if (page.next_offset != null && (!Number.isInteger(page.next_offset) || page.next_offset <= offset || page.next_offset > 1024)) throw new Error(c("previewError"));
        offset = page.next_offset;
      } while (offset != null);
      return {schema: "greyward.network.rules-export/v1", provider: state.provider,
        rules: rows.map(({state, owner, position, observed, ...rule}) => rule)};
    }
    function readForm() {
      const form = root?.querySelector("[data-rule-form]");
      if (!form) return state.draft;
      const values = Object.fromEntries(new FormData(form));
      const d = {...state.draft, ...values};
      d.protocols = values.protocol === "both" ? ["tcp", "udp"] : [values.protocol]; delete d.protocol;
      if (d.provider === "incoming" && d.service) d.protocols = ["tcp", "udp"];
      d.ports = d.service ? "" : values.ports || ""; d.destinations = destinations(values.destinations);
      state.draft = d;
      return d;
    }
    async function preview(commands, extra = {}) {
      const sequence = ++previewSequence;
      try {
        state.error = "";
        const reviewed = await call("preview", {provider: state.provider, revision: state.data.revision, commands, ...extra});
        if (sequence !== previewSequence) {
          await call("cancel", {transaction: reviewed.transaction});
          return;
        }
        state.preview = reviewed;
      } catch (error) { if (sequence === previewSequence) state.error = error.message || c("previewError"); }
      draw();
    }
    function action(command, rule) {
      if (command === "edit" || command === "duplicate") {
        fresh({...rule, ports: rule.ports.map(p => [...p]), destinations: (rule.destinations || []).map(d => ({...d}))});
        if (command === "edit") state.editing = rule.id; else { delete state.draft.id; state.draft.name += " (copy)"; }
        draw(); root.querySelector('[name="name"]')?.focus(); return;
      }
      const operation = command === "remove" ? "delete" : ["up", "down"].includes(command) ? "move" : "enable";
      const payload = {operation, id: rule.id};
      if (operation === "enable") payload.enabled = command === "enable";
      if (operation === "move") payload.position = rule.position + (command === "up" ? -1 : 1);
      preview([payload]);
    }
    async function apply() {
      if (!state.preview || state.busy) return;
      const transaction = state.preview.transaction;
      state.busy = true; state.error = ""; draw();
      try {
        const result = await call("apply", {transaction}, 130000);
        state.undo = result.undo || null;
        state.preview = null; state.draft = null; state.editing = null; state.feedback = c("saved");
        await load(); state.selected.clear();
      } catch (error) { state.error = error.message || c("applyError"); state.preview = null; }
      finally { state.busy = false; draw(); }
    }
    async function cancel() {
      previewSequence++;
      const transaction = state.preview?.transaction;
      if (transaction) { try { await call("cancel", {transaction}); } catch (error) { state.error = error.message; } }
      state.preview = null; draw();
    }
    function bind(element) {
      root = element;
      if (!root) { clearTimeout(searchTimer); return; }
      if (state.busy) root.querySelectorAll("button,input,select,textarea").forEach(element => { if (!element.hasAttribute("data-rule-cancel")) element.disabled = true; });
      root.querySelector("[data-rule-new]")?.addEventListener("click", () => { fresh(); draw(); root.querySelector('[name="name"]')?.focus(); });
      root.querySelector("[data-rule-close]")?.addEventListener("click", async () => { await cancel(); state.draft = null; draw(); });
      root.querySelectorAll("[data-rule-provider]").forEach(b => b.addEventListener("click", async () => { if (state.busy) return; await cancel(); state.provider = b.dataset.ruleProvider; state.offset = 0; state.draft = null; await reload(); }));
      root.querySelector("[data-rule-refresh]")?.addEventListener("click", reload);
      root.querySelector("[data-rule-filter]")?.addEventListener("change", async event => { state.filter = event.target.value; state.offset = 0; await reload(); });
      root.querySelector("[data-rule-search]")?.addEventListener("input", event => { state.search = event.target.value; clearTimeout(searchTimer); searchTimer = setTimeout(() => { state.offset = 0; reload(); }, 300); });
      root.querySelectorAll("[data-rule-select]").forEach(b => b.addEventListener("change", () => { b.checked ? state.selected.add(b.dataset.ruleSelect) : state.selected.delete(b.dataset.ruleSelect); draw(); }));
      root.querySelectorAll("[data-rule-action]").forEach(b => b.addEventListener("click", () => action(b.dataset.ruleAction, state.data.rules.find(r => r.id === b.dataset.id))));
      root.querySelectorAll("[data-rule-bulk]").forEach(b => b.addEventListener("click", () => preview([...state.selected].map(id => ({id, operation: b.dataset.ruleBulk === "remove" ? "delete" : "enable", ...(b.dataset.ruleBulk === "remove" ? {} : {enabled: b.dataset.ruleBulk === "enable"})})))));
      root.querySelector("[data-rule-form]")?.addEventListener("submit", event => { event.preventDefault(); const rule = readForm(); preview([{operation: rule.dns_exception ? "dns_exception" : "upsert", ...(state.editing ? {id: state.editing} : {}), rule}]); });
      root.querySelector("[data-rule-form]")?.addEventListener("input", () => {
        previewSequence++;
        if (state.preview) {
          const transaction = state.preview.transaction;
          state.preview = null; root.querySelector(".network-rule-review")?.remove();
          call("cancel", {transaction}).catch(error => { state.error = error.message; });
        }
        const d = readForm(); root.querySelector("[data-rule-summary]").textContent = summary(d);
      });
      root.querySelector("[data-rule-apply]")?.addEventListener("click", apply);
      root.querySelector("[data-rule-undo]")?.addEventListener("click", () => preview(undefined, {undo: state.undo}));
      root.querySelector("[data-rule-cancel]")?.addEventListener("click", cancel);
      root.querySelectorAll("[data-rule-page]").forEach(b => b.addEventListener("click", async () => { state.offset = b.dataset.rulePage === "next" ? state.data.next_offset : Math.max(0, state.offset - 100); await reload(); }));
      root.querySelector("[data-rule-import]")?.addEventListener("click", () => root.querySelector("[data-rule-import-file]").click());
      root.querySelector("[data-rule-import-file]")?.addEventListener("change", async event => {
        try {
          const file = event.target.files[0]; if (!file || file.size > 1048576) throw new Error(c("importError"));
          const value = JSON.parse(await file.text());
          if (value.schema !== "greyward.network.rules-export/v1" || value.provider !== state.provider || !Array.isArray(value.rules)) throw new Error(c("importError"));
          await preview(value.rules.map(rule => ({operation: rule.dns_exception ? "dns_exception" : "upsert", rule})));
        } catch (error) { state.error = error.message; draw(); }
      });
      root.querySelector("[data-rule-export]")?.addEventListener("click", async () => {
        try {
          state.exportText = JSON.stringify(await exportDocument(), null, 2);
        } catch (error) { state.error = error.message; }
        draw();
      });
      root.querySelector("[data-rule-export-close]")?.addEventListener("click", () => { state.exportText = ""; draw(); });
      const download = root.querySelector("[data-rule-download]");
      if (download) download.addEventListener("click", () => { const url = URL.createObjectURL(new Blob([state.exportText], {type: "application/json"})); download.href = url; setTimeout(() => URL.revokeObjectURL(url), 1000); });
    }
    return {load, markup, bind, exportDocument,
      reviewCommands: async commands => { state.provider = "application"; await load(); await preview(commands); },
      begin: values => { state.provider = "application"; fresh(values); }, state};
  }
  globalThis.GREYWARD_NETWORK_RULES = Object.freeze({create, copy: catalogs, destinations, portsText});
})();
