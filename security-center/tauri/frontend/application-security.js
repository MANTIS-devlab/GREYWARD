// Route-scoped reads and opaque reviews. Root authorization/enforcement stay in
// the broker; neither a preview nor an accepted submission is a success result.
(() => {
  const schema = "greyward.application-security/v1";
  const unavailable = () => ({schema, source_state: {state: "UNAVAILABLE"}, projection: null});
  const kinds = Object.freeze({
    applications: {command: "list_application_security_applications", list: "applications", revision: "inventory_revision"},
    resources: {command: "list_application_security_resources", list: "resources", revision: "policy_revision"},
  });
  function create({request, now = () => Date.now(), pause = ms => new Promise(resolve => setTimeout(resolve, ms)),
    schedule = (callback, ms) => setTimeout(callback, ms), unschedule = timer => clearTimeout(timer)}) {
    let detailSequence = 0;
    const reviews = new Map();
    let mutation = false;
    const launches = new Map();
    function live(envelope) {
      if (envelope?.schema !== schema || envelope.source_state?.state !== "AVAILABLE" || !envelope.projection) return null;
      const observed = Date.parse(envelope.observed_at), expires = Date.parse(envelope.fresh_until);
      const current = now();
      return Number.isFinite(observed) && Number.isFinite(expires) && observed <= current + 1000
        && expires >= current && expires - observed <= 5000 ? envelope.projection : null;
    }
    async function read(command, args) {
      try { return await request(command, args, 8000); }
      catch (_) { return unavailable(); }
    }
    async function load(kind) {
      const provider = kinds[kind];
      if (!provider) throw new RangeError("Unknown Application Security route");
      const [coverage, envelope, grants] = await Promise.all([
        read("get_application_security_coverage"),
        read(provider.command, {query: {limit: 100, revision: null, after: null}}),
        request("list_application_security_grants", undefined, 8000).catch(() => null),
      ]);
      return {coverage, envelope, grants};
    }
    async function more(kind, current) {
      const provider = kinds[kind], previous = live(current?.envelope);
      if (!provider || !previous?.next_cursor) throw new Error("Refresh required");
      const envelope = await read(provider.command, {query: {limit: 100,
        revision: previous[provider.revision], after: previous.next_cursor}});
      const next = live(envelope);
      if (!next || !live(current.envelope) || next[provider.revision] !== previous[provider.revision]) throw new Error("Refresh required");
      return {...current, envelope: {...envelope,
        fresh_until: new Date(Math.min(Date.parse(current.envelope.fresh_until), Date.parse(envelope.fresh_until))).toISOString(), projection: {...next,
        [provider.list]: [...previous[provider.list], ...next[provider.list]]}}};
    }
    async function detail(kind, reference) {
      const sequence = ++detailSequence;
      const resource = kind === "resources";
      if (!kinds[kind] || !new RegExp(`^${resource ? "resource" : "installation"}_[0-9a-f]{64}$`).test(reference)) {
        throw new RangeError("Invalid Application Security reference");
      }
      const envelope = await read(resource ? "get_application_security_resource" : "get_application_security_application",
        resource ? {resourceRef: reference} : {installationRef: reference});
      return sequence === detailSequence ? {reference, projection: live(envelope)} : null;
    }
    const cancelDetail = () => { ++detailSequence; };
    async function review(kind, args) {
      const commands = {registration: "pick_application_security_resource", grant: "pick_application_security_grant", revocation: "pick_application_security_revocation"};
      if (!commands[kind]) throw new RangeError("Invalid review kind");
      const value = await request(commands[kind], args, 300000);
      if (value == null) return null;
      const summary = value.kind === "GRANT" ? value.preview?.review : value.preview;
      if (value.kind !== kind.toUpperCase() || !/^operation_[0-9a-f]{64}$/.test(summary?.operation_ref)
          || (kind === "grant" && value.preview?.tool_profile !== "openssh-key-inspection/v1")
          || !Number.isSafeInteger(summary.expires_after_ms) || summary.expires_after_ms <= 1000 || summary.expires_after_ms > 120000) {
        throw new Error("Invalid or expired review");
      }
      // Reserve a transport margin; the broker independently enforces its lease.
      const ticket = Object.freeze({value, operationRef: summary.operation_ref, expires: now() + summary.expires_after_ms - 1000});
      reviews.set(ticket.operationRef, ticket);
      return ticket;
    }
    function validResult(result, reference) {
      const outcomes = ["PENDING", "RUNNING", "CANCEL_REQUESTED", "VERIFYING", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"];
      if (result?.operation_ref !== reference || !outcomes.includes(result.outcome)
          || typeof result.verified_readback !== "boolean"
          || (result.outcome === "COMPLETED" && (!result.verified_readback || !Number.isSafeInteger(result.committed_revision) || result.committed_revision <= 0 || result.failure != null))
          || (result.verified_readback && result.outcome !== "COMPLETED")) throw new Error("Invalid operation readback");
      return result;
    }
    async function cancel(ticket) {
      if (reviews.get(ticket?.operationRef) !== ticket) throw new Error("Review owner changed");
      const result = validResult(await request("cancel_application_security_operation", {operationRef: ticket.operationRef}, 8000), ticket.operationRef);
      if (result.outcome !== "CANCELLED") throw new Error("Cancellation not confirmed");
      reviews.delete(ticket.operationRef);
      return result;
    }
    async function apply(ticket, progress = () => {}) {
      if (mutation || reviews.get(ticket?.operationRef) !== ticket || now() >= ticket.expires) throw new Error("Refresh and review again");
      mutation = true;
      reviews.delete(ticket.operationRef);
      const deadline = now() + 110000;
      try {
        let result = validResult(await request("apply_application_security_policy", {operationRef: ticket.operationRef}, 8000), ticket.operationRef);
        for (;;) {
          progress(result);
          if (["COMPLETED", "FAILED", "CANCELLED", "EXPIRED"].includes(result.outcome)) return result;
          if (now() >= deadline) throw new Error("Outcome not confirmed; refresh before another change");
          await pause(300);
          result = validResult(await request("get_application_security_operation", {operationRef: ticket.operationRef}, 8000), ticket.operationRef);
        }
      } finally { mutation = false; }
    }
    async function prepareLaunch() {
      const value = await request("pick_application_security_launch", undefined, 300000);
      if (value == null) return null;
      if (value.schema !== schema || !/^launch_[0-9a-f]{64}$/.test(value.launch_ref)
          || value.requested_profile !== "ISOLATED" || value.enforcement_health !== "UNKNOWN"
          || value.private_display_requested !== true || !Number.isSafeInteger(value.expires_after_ms)
          || value.expires_after_ms <= 1000 || value.expires_after_ms > 90000) throw new Error("Invalid launch preparation");
      const ticket = Object.freeze({value, expires: now() + value.expires_after_ms - 1000});
      launches.set(value.launch_ref, ticket);
      return ticket;
    }
    async function startLaunch(ticket) {
      if (launches.get(ticket?.value?.launch_ref) !== ticket || now() >= ticket.expires) throw new Error("Launch review expired");
      launches.delete(ticket.value.launch_ref);
      const result = await request("start_application_security_launch", {launchRef: ticket.value.launch_ref}, 8000);
      if (result?.schema !== schema || result.launch_ref !== ticket.value.launch_ref || result.state !== "LAUNCHED"
          || result.isolation_established !== true || result.private_display !== true || result.enforcement_health !== "UNKNOWN") throw new Error("Isolation not confirmed");
      return result;
    }
    function discardLaunch(ticket) { if (launches.get(ticket?.value?.launch_ref) === ticket) launches.delete(ticket.value.launch_ref); }
    async function events(application) {
      const filters = {category: "APPLICATION_SECURITY", limit: 100};
      if (application) {
        if (!/^installation_[0-9a-f]{64}$/.test(application)) throw new RangeError("Invalid application filter");
        filters.application = application;
      }
      try { return await request("query_telemetry", {filters}, 8000); }
      catch (_) { return null; }
    }
    const coverage = () => read("get_application_security_coverage");
    function presentationKey(value) {
      // Evidence age changes on every read. Its validity still matters, but
      // the exact millisecond count is not displayed and must not replace DOM.
      const projection = envelope => {
        const data = live(envelope);
        return data && JSON.parse(JSON.stringify(data, (key, item) => key === "evidence_age_ms"
          ? Number.isFinite(item) && item >= 0 && item <= 30000 : item));
      };
      return JSON.stringify([value?.coverage?.source_state, projection(value?.coverage),
        value?.envelope?.source_state, projection(value?.envelope), value?.grants]);
    }
    // Renew visible views from the real provider, never by extending a cached
    // evidence lease. Only one read runs at a time; leaving/hiding the route
    // stops renewal and ignores a late response. No mutation is retried here.
    function watch(kind, changed, visible = () => true) {
      if (kind !== "coverage" && !kinds[kind]) throw new RangeError("Unknown Application Security route");
      let stopped = false, timer;
      const refresh = async () => {
        if (stopped) return;
        const started = now();
        let delay = 1000;
        try {
          // The broker's policy worker may be waiting for owner authentication.
          // Keep background inventory reads off its queue while the reviewed
          // operation is active; the operation endpoint remains independently
          // readable. Cached evidence still expires at its original deadline.
          if (visible() && !mutation && reviews.size === 0) {
            const value = kind === "coverage" ? {coverage: await coverage()} : await load(kind);
            if (!stopped && visible()) changed(value);
            const deadlines = [value.coverage, value.envelope].filter(item => live(item))
              .map(item => Date.parse(item.fresh_until));
            if (deadlines.length) {
              // Reserve the measured complete-read cost and one second of
              // transport margin before the earliest real provider deadline.
              // Do not renew the cached lease or overlap provider requests.
              delay = Math.max(250, Math.min(3000, Math.min(...deadlines) - now() - (now() - started) - 1000));
            }
          }
        } finally { if (!stopped) timer = schedule(refresh, delay); }
      };
      timer = schedule(refresh, 1000);
      return () => { stopped = true; unschedule(timer); };
    }
    return Object.freeze({load, more, detail, cancelDetail, live, coverage, presentationKey, watch, review, cancel, apply, prepareLaunch, startLaunch, discardLaunch, events});
  }
  window.GREYWARD_APPLICATION_SECURITY = Object.freeze({create});
})();
