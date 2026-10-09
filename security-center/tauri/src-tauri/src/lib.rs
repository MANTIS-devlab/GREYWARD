use chrono::Utc;
mod window_chrome;
use dbus::blocking::Connection;
use greyward_security_backends::{
    ActivityCategory, ActivityItem, ActivitySeverity, ApplicationPageQuery, CoreCollection,
    FlatpakAvailability, MAX_APPLICATION_READ_BYTES, ProtectedResourcePageQuery, TrustZone,
    change_active_trust_zone, choose_overall_posture, clear_activity, collect_core_collection,
    collect_core_snapshot, collect_device_snapshot, collect_flatpak_facts, collect_network_facts,
    collect_portal_facts, decode_application_coverage, decode_application_detail,
    decode_application_page, decode_protected_resource_lookup, decode_protected_resource_page,
    evidence_domain_key, evidence_domain_route, evidence_presentation, external_service_manifest,
    load_activity, load_opensnitch_context_summary, read_actual_state, record_activity,
    resolve_flatpak_access, set_accepted_deviation, write_safe_export,
};
use greyward_security_domain::{
    AccessGrant, ApplicationCoverage, ApplicationInventoryPage, ApplicationLookup,
    ApplicationReadEnvelope, ClamAvStatus, OperationResult, PostureState, ProtectedResourceLookup,
    ProtectedResourcePage, Requiredness, SecurityReference, WorkflowPreview,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Mutex, OnceLock},
};
use tauri::Manager;

const FAST_HELPER_TIMEOUT_SECONDS: u64 = 20;
const RECOVERY_HELPER_TIMEOUT_SECONDS: u64 = 900;
const BACKUP_HELPER_TIMEOUT_SECONDS: u64 = 7_200;
const BACKUP_LIST_TIMEOUT_SECONDS: u64 = 120;
const INTERACTIVE_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const SECURITY_CONTEXT_BUS_NAME: &str = "systems.mantis.greyward.SecurityContext1";
const SECURITY_CONTEXT_OBJECT_PATH: &str = "/systems/mantis/greyward/SecurityContext1";
const SECURITY_CONTEXT_CALL_TIMEOUT: Duration = Duration::from_secs(12);
// Page reads commonly arrive back-to-back (Overview -> System -> Evidence).
// Share one short-lived authoritative collection across those reads, while
// keeping the window bounded and invalidating it after local mutations.
const CORE_SNAPSHOT_CACHE_TTL: Duration = Duration::from_secs(3);
const SECURITY_CENTER_ROUTES: &[&str] = &[
    "overview",
    "system",
    "network",
    "privacy",
    "updates",
    "files",
    "applications",
    "protected-data",
    "devices",
    "evidence",
    "activity",
    "threats",
    "history",
    "recovery",
];

struct CachedCoreSnapshot {
    collected_at: Instant,
    collection: CoreCollection,
}

static CORE_SNAPSHOT_CACHE: OnceLock<Mutex<Option<CachedCoreSnapshot>>> = OnceLock::new();
static STARTUP_TRACE_START: OnceLock<Instant> = OnceLock::new();

fn startup_trace(stage: &str) {
    if std::env::var_os("GREYWARD_STARTUP_TRACE").is_none()
        && !std::path::Path::new("/tmp/greyward-startup-trace.enable").exists()
    {
        return;
    }
    let elapsed = STARTUP_TRACE_START.get_or_init(Instant::now).elapsed();
    eprintln!(
        "GREYWARD_STARTUP stage={stage} elapsed_ms={:.2}",
        elapsed.as_secs_f64() * 1000.0
    );
}

fn core_collection_for_read() -> CoreCollection {
    startup_trace("core_collection_request");
    let cache = CORE_SNAPSHOT_CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = guard.as_ref()
        && cached.collected_at.elapsed() < CORE_SNAPSHOT_CACHE_TTL
    {
        startup_trace("core_collection_cache_hit");
        return cached.collection.clone();
    }

    // Keep the collection under the lock so concurrent page requests do not
    // start duplicate firmware, package, Flatpak, and service probes.
    startup_trace("core_collection_start");
    let collection = collect_core_collection();
    startup_trace("core_collection_complete");
    *guard = Some(CachedCoreSnapshot {
        collected_at: Instant::now(),
        collection: collection.clone(),
    });
    collection
}

fn invalidate_core_snapshot_cache() {
    if let Some(cache) = CORE_SNAPSHOT_CACHE.get() {
        let mut guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = None;
    }
}

#[derive(Clone, Serialize)]
pub struct OverviewPayload {
    pub posture: PostureSummary,
    pub priority_findings: Vec<FindingSummary>,
    pub metrics: MetricsSummary,
    pub domains: Vec<DomainSummary>,
    pub activity: Vec<ActivitySummary>,
    pub activity_state: String,
    pub clamav: Option<ClamAvStatus>,
}
#[derive(Clone, Serialize)]
pub struct PostureSummary {
    pub state: String,
    pub tone: String,
    pub message_key: String,
    pub care_key: String,
    pub copy_values: BTreeMap<String, String>,
    pub evaluated_at: String,
}
#[derive(Clone, Serialize)]
pub struct FindingSummary {
    pub title_key: String,
    pub state: String,
    pub tone: String,
    pub summary_key: String,
    pub context_key: String,
    pub copy_values: BTreeMap<String, String>,
    pub destination: String,
}
#[derive(Clone, Serialize)]
pub struct MetricsSummary {
    pub protected: usize,
    pub review_needed: usize,
    pub unavailable: usize,
}
#[derive(Clone, Serialize)]
pub struct DomainSummary {
    pub name_key: String,
    pub state: String,
    pub tone: String,
    pub context_key: String,
    pub copy_values: BTreeMap<String, String>,
    pub checks: usize,
    pub destination: String,
}
#[derive(Clone, Serialize)]
pub struct ActivitySummary {
    pub title: String,
    pub detail: String,
    pub category: String,
    pub severity: String,
    pub occurred_at: String,
}

/// Choose the dashboard posture from domain posture, not from the raw count
/// of unavailable checks. A recommended hardware capability can be absent in
/// a VM while the device still has enough evaluated protection to be honestly
/// shown as protected. Required uncertainty and unknown domain state remain a
/// global limitation.
#[derive(Clone, Serialize)]
pub struct StatusRow {
    pub label: String,
    pub label_key: Option<String>,
    pub value: String,
    pub value_key: Option<String>,
    pub detail: String,
    pub detail_key: Option<String>,
    pub copy_values: BTreeMap<String, String>,
    pub tone: String,
}
#[derive(Clone, Serialize)]
pub struct NetworkPayload {
    pub connection: Vec<StatusRow>,
    pub controls: Vec<StatusRow>,
    pub evidence: Vec<StatusRow>,
    pub interface: Option<String>,
    pub zone: String,
}
#[derive(Clone, Serialize)]
pub struct ApplicationPayload {
    pub overview: Vec<StatusRow>,
    pub portal: Vec<StatusRow>,
    pub apps: Vec<ApplicationSummary>,
    pub inventory_total: usize,
    pub shown_count: usize,
    pub review_needed_count: usize,
    pub inventory_state: String,
}
#[derive(Clone, Serialize)]
pub struct ApplicationSummary {
    pub name: String,
    pub access_state: String,
    pub access_categories: Vec<String>,
    pub review_reasons: Vec<String>,
    pub technical: ApplicationTechnicalDetails,
}
#[derive(Clone, Serialize)]
pub struct ApplicationTechnicalDetails {
    pub app_id: String,
    pub scope: String,
    pub origin: Option<String>,
    pub version: Option<String>,
    pub arch: Option<String>,
    pub branch: Option<String>,
    pub runtime: Option<String>,
    pub manifest_permissions: Vec<String>,
    pub effective_permissions: Vec<String>,
    pub deployment_commit: Option<greyward_security_domain::ContentGeneration>,
    pub identity_state: String,
    pub local_overrides: Vec<String>,
}
#[derive(Clone, Serialize)]
pub struct DevicePayload {
    pub usb: Vec<StatusRow>,
    pub recovery: Vec<StatusRow>,
    pub device_history: Value,
    pub recovery_v1: Value,
    pub backup: Value,
}
#[derive(Clone, Serialize)]
pub struct EvidencePayload {
    pub generated_at: String,
    pub policy_profile: String,
    pub sections: Vec<EvidenceSection>,
}
#[derive(Clone, Serialize)]
pub struct EvidenceSection {
    pub domain: String,
    pub count: usize,
    pub rows: Vec<EvidenceRow>,
}
#[derive(Clone, Serialize)]
pub struct EvidenceRow {
    pub title_key: String,
    pub check_id: String,
    pub state: String,
    pub tone: String,
    pub summary_key: String,
    pub recorded_result_key: String,
    pub recommendation_key: String,
    pub copy_values: std::collections::BTreeMap<String, String>,
    pub accepted_deviation: bool,
    pub evidence_count: usize,
    pub remediation: Option<EvidenceRemediationProjection>,
    pub no_remediation_key: Option<String>,
    pub technical: EvidenceTechnicalDetails,
}
#[derive(Clone, Serialize)]
pub struct EvidenceRemediationProjection {
    pub route: String,
    pub action_key: String,
}
#[derive(Clone, Serialize)]
pub struct EvidenceTechnicalDetails {
    pub reference: String,
    pub reason_code: String,
    pub observed_at: String,
    pub fresh_until: String,
}
#[derive(Clone, Serialize)]
pub struct PrivacyPayload {
    pub profile: StatusRow,
    pub identity: StatusRow,
    pub firewall: StatusRow,
    pub vpn: StatusRow,
    pub public_ip: StatusRow,
    pub local: Vec<StatusRow>,
    pub disclosures: Vec<DisclosureSummary>,
    pub activity: Vec<ActivitySummary>,
    pub activity_state: String,
    pub clamav: Option<ClamAvStatus>,
    pub retention_days: i64,
    pub max_activity_items: usize,
}
#[derive(Clone, Serialize)]
pub struct DisclosureSummary {
    pub component: String,
    pub state: String,
    pub purpose: String,
    pub endpoints: String,
    pub trigger: String,
    pub data_disclosed: String,
    pub retention: String,
    pub disable_route: String,
}
#[derive(Clone, Serialize)]
pub struct ActionResult {
    pub ok: bool,
    pub message: String,
    pub refreshed: Option<NetworkPayload>,
    pub profile: Option<String>,
    pub path: Option<String>,
}
#[tauri::command(async)]
fn get_overview() -> Result<OverviewPayload, String> {
    startup_trace("get_overview_start");
    let snapshot = core_collection_for_read().snapshot;
    let protected = snapshot
        .checks
        .iter()
        .filter(|check| matches!(check.state, PostureState::Secure | PostureState::Protected))
        .count();
    let review_needed = snapshot
        .checks
        .iter()
        .filter(|check| {
            check.reason_code != "accepted-deviation"
                && matches!(
                    check.state,
                    PostureState::ReviewNeeded | PostureState::ActionRequired
                )
        })
        .count();
    let unavailable = snapshot
        .checks
        .iter()
        .filter(|check| {
            check.reason_code != "accepted-deviation"
                && matches!(
                    check.state,
                    PostureState::Unavailable | PostureState::Unknown
                )
        })
        .count();
    let required_uncertain = snapshot.checks.iter().any(|check| {
        check.reason_code != "accepted-deviation"
            && check.requiredness == Requiredness::Required
            && matches!(
                check.state,
                PostureState::Unknown | PostureState::Unavailable
            )
    });
    let domain_states: Vec<PostureState> =
        snapshot.domains.iter().map(|domain| domain.state).collect();
    let (state, tone, message_key, care_key, copy_values) = choose_overall_posture(
        &domain_states,
        review_needed,
        unavailable,
        required_uncertain,
    );
    let priority_findings = snapshot
        .checks
        .iter()
        .filter(|c| {
            c.reason_code != "accepted-deviation"
                && matches!(
                    c.state,
                    PostureState::ReviewNeeded | PostureState::ActionRequired
                )
        })
        .take(3)
        .map(|check| {
            let presentation = evidence_presentation(check, &snapshot.accepted_deviations);
            FindingSummary {
                title_key: presentation.title_key.into(),
                state: display_state(check.state),
                tone: state_tone(check.state).into(),
                summary_key: presentation.summary_key.into(),
                context_key: presentation.recommendation_key.into(),
                copy_values: presentation.values,
                destination: presentation
                    .remediation
                    .map(|remediation| remediation.route)
                    .unwrap_or_else(|| evidence_domain_route(check.domain))
                    .into(),
            }
        })
        .collect();
    let domains = snapshot
        .domains
        .iter()
        .map(|domain| {
            let (context_key, copy_values) = snapshot
                .checks
                .iter()
                .find(|c| {
                    c.domain == domain.domain
                        && matches!(
                            c.state,
                            PostureState::ReviewNeeded | PostureState::ActionRequired
                        )
                })
                .map(|check| {
                    let presentation = evidence_presentation(check, &snapshot.accepted_deviations);
                    (presentation.summary_key.into(), presentation.values)
                })
                .unwrap_or_else(|| {
                    let key = match domain.state {
                        PostureState::Secure => "overview.domain.secure",
                        PostureState::Protected => "overview.domain.protected",
                        PostureState::ReviewNeeded | PostureState::ActionRequired => {
                            "overview.domain.review"
                        }
                        PostureState::Unavailable | PostureState::Unknown => {
                            "overview.domain.unavailable"
                        }
                        PostureState::NotApplicable => "overview.domain.notApplicable",
                    };
                    (key.into(), BTreeMap::new())
                });
            DomainSummary {
                name_key: evidence_domain_key(domain.domain).into(),
                state: display_state(domain.state),
                tone: state_tone(domain.state).into(),
                context_key,
                copy_values,
                checks: domain.check_ids.len(),
                destination: evidence_domain_route(domain.domain).into(),
            }
        })
        .collect();
    let clamav = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .and_then(|runtime| {
            load_opensnitch_context_summary(format!(
                "{runtime}/greyward-security-context-summary.json"
            ))
            .ok()
        })
        .and_then(|summary| summary.clamav);
    // Optional history must not hold authoritative posture behind a busy session bus.
    let result = Ok(OverviewPayload {
        posture: PostureSummary {
            state: state.into(),
            tone: tone.into(),
            message_key: message_key.into(),
            care_key: care_key.into(),
            copy_values,
            evaluated_at: snapshot.generated_at.to_rfc3339(),
        },
        priority_findings,
        metrics: MetricsSummary {
            protected,
            review_needed,
            unavailable,
        },
        domains,
        activity: Vec::new(),
        activity_state: "LOADING".into(),
        clamav,
    });
    startup_trace("get_overview_complete");
    result
}
#[tauri::command(async)]
fn get_overview_activity() -> Result<Value, String> {
    let (activity, activity_state) = activity_summaries();
    Ok(json!({"activity": activity, "activity_state": activity_state}))
}
#[tauri::command]
fn set_deviation(check_id: String, accepted: bool) -> Result<OverviewPayload, String> {
    set_accepted_deviation(&check_id, accepted)?;
    let action = if accepted {
        "Ignored security recommendation"
    } else {
        "Stopped ignoring security recommendation"
    };
    record_action(action, &check_id)?;
    invalidate_core_snapshot_cache();
    get_overview()
}
#[tauri::command]
fn get_network() -> Result<NetworkPayload, String> {
    Ok(network_payload())
}
#[tauri::command(async)]
fn get_network_protection() -> Result<Value, String> {
    let mut value =
        security_context_method("systems.mantis.greyward.SecurityContext1.GetNetworkProtection")?;
    let network = collect_network_facts();
    let zone = readable(&format!("{:?}", network.trust_zone));
    value["firewalld"] = json!({
        "state": readable(&format!("{:?}", network.firewall)),
        "zone": zone,
        "interface": network.interface,
        "connection": network.active_connection,
        "detail": "firewalld owns system and inbound network protection; it is separate from application interception."
    });
    Ok(value)
}
#[tauri::command(async)]
fn get_threat_protection() -> Result<Value, String> {
    security_context_method("systems.mantis.greyward.SecurityContext1.GetThreatProtection")
}
#[tauri::command]
fn set_threat_protection_enabled(enabled: bool) -> Result<Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.SetThreatProtectionEnabled",
        &serde_json::to_string(&enabled)
            .map_err(|_| "The threat setting could not be encoded.".to_string())?,
    )
}
#[tauri::command(async)]
fn get_network_activity(since_sequence: u64, limit: u32) -> Result<Value, String> {
    security_context_activity_method(
        "systems.mantis.greyward.SecurityContext1.GetNetworkActivity",
        since_sequence,
        limit,
    )
}
#[tauri::command(async)]
fn get_security_center_digest() -> Result<Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.GetSecurityCenterDigest",
        "{}",
    )
}
#[tauri::command]
fn get_network_history(filters: Value) -> Result<Value, String> {
    let encoded = serde_json::to_string(&filters)
        .map_err(|_| "The network history query could not be encoded.".to_string())?;
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.GetNetworkHistory",
        &encoded,
    )
}
#[tauri::command]
fn get_device_overview() -> Result<Value, String> {
    security_context_method("systems.mantis.greyward.SecurityContext1.GetDeviceOverview")
}
#[tauri::command]
fn get_capability_history(filters: Value) -> Result<Value, String> {
    let encoded = serde_json::to_string(&filters)
        .map_err(|_| "The capability history query could not be encoded.".to_string())?;
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.GetCapabilityHistory",
        &encoded,
    )
}
#[tauri::command]
fn query_telemetry(filters: Value) -> Result<Value, String> {
    let encoded = serde_json::to_string(&filters)
        .map_err(|_| "The telemetry query could not be encoded.".to_string())?;
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.QueryTelemetry",
        &encoded,
    )
}
#[tauri::command]
fn get_related_telemetry(event_id: String, options: Value) -> Result<Value, String> {
    let payload = serde_json::to_string(&json!({"event_id": event_id, "options": options}))
        .map_err(|_| "The telemetry request could not be encoded.".to_string())?;
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.GetRelatedTelemetry",
        &payload,
    )
}
#[tauri::command(async)]
fn get_secure_dns() -> Result<Value, String> {
    security_context_method("systems.mantis.greyward.SecurityContext1.GetSecureDnsState")
}
#[tauri::command]
fn set_secure_dns_mode(mode: String) -> Result<Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.SetSecureDnsMode",
        &mode,
    )
}
#[tauri::command]
fn set_secure_dns_provider(provider: String) -> Result<Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.SetSecureDnsProvider",
        &provider,
    )
}
#[tauri::command]
fn retry_secure_dns() -> Result<Value, String> {
    security_context_method("systems.mantis.greyward.SecurityContext1.RetrySecureDns")
}
#[tauri::command]
fn network_set_rule(payload: Value) -> Result<Value, String> {
    let encoded = serde_json::to_string(&payload)
        .map_err(|_| "The network rule could not be encoded.".to_string())?;
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.NetworkSetRule",
        &encoded,
    )
}
#[tauri::command]
fn network_set_threat_exception(payload: Value) -> Result<Value, String> {
    let encoded = serde_json::to_string(&payload)
        .map_err(|_| "The threat exception could not be encoded.".to_string())?;
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.NetworkSetThreatException",
        &encoded,
    )
}
#[tauri::command]
fn network_remove_rule(rule_id: String) -> Result<Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.NetworkRemoveRule",
        &rule_id,
    )
}
#[tauri::command]
fn network_prompt_decision(payload: Value) -> Result<Value, String> {
    let encoded = serde_json::to_string(&payload)
        .map_err(|_| "The network decision could not be encoded.".to_string())?;
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.NetworkPromptDecision",
        &encoded,
    )
}
#[tauri::command]
fn set_network_trust_zone(
    app: tauri::AppHandle,
    interface: String,
    target: String,
) -> Result<ActionResult, String> {
    let current = collect_network_facts();
    let requested = parse_zone(&target)?;
    let Some(active_interface) = current.interface.clone() else {
        return Ok(ActionResult {
            ok: false,
            message: "No active connection is available for a safe zone change.".into(),
            refreshed: Some(network_payload()),
            profile: None,
            path: None,
        });
    };
    if active_interface != interface {
        return Ok(ActionResult {
            ok: false,
            message: "The active interface changed; no change was applied.".into(),
            refreshed: Some(network_payload()),
            profile: None,
            path: None,
        });
    }
    let result = change_active_trust_zone(&interface, current.trust_zone, requested);
    let refreshed = network_payload();
    match result {
        Ok(zone) => {
            let _ = record_action(
                "Network trust zone changed",
                &format!("Verified current zone: {zone:?}"),
            );
            emit_state_changed(&app);
            Ok(ActionResult {
                ok: true,
                message: format!("Verified current zone: {zone:?}."),
                refreshed: Some(refreshed),
                profile: None,
                path: None,
            })
        }
        Err(error) => Ok(ActionResult {
            ok: false,
            message: format!("Trust-zone change failed: {error}"),
            refreshed: Some(refreshed),
            profile: None,
            path: None,
        }),
    }
}
#[tauri::command(async)]
fn get_applications() -> Result<ApplicationPayload, String> {
    let (flatpak, portal) = std::thread::scope(|scope| {
        let inventory = scope.spawn(collect_flatpak_facts);
        let portal = collect_portal_facts();
        (inventory.join(), portal)
    });
    let flatpak = flatpak.map_err(|_| "Application inventory is unavailable.".to_string())?;
    let inventory_state = match flatpak.availability {
        FlatpakAvailability::Available => "AVAILABLE",
        FlatpakAvailability::Partial => "PARTIAL",
        FlatpakAvailability::Unavailable
        | FlatpakAvailability::Error
        | FlatpakAvailability::Unknown => "UNAVAILABLE",
    };
    let has_apps = !flatpak.apps.is_empty();
    let portal_ready = portal.documents && portal.permission_store;
    let apps: Vec<ApplicationSummary> = flatpak
        .apps
        .into_iter()
        .map(normalize_application_access)
        .collect();
    let inventory_total = apps.len();
    let review_needed_count = apps
        .iter()
        .filter(|app| app.access_state == "REVIEW_NEEDED")
        .count();
    Ok(ApplicationPayload {
        overview: vec![semantic_status_row(
            "applications.status.isolation",
            match inventory_state {
                "AVAILABLE" => "state.available",
                "PARTIAL" => "state.partial",
                _ => "state.unavailable",
            },
            match inventory_state {
                "AVAILABLE" if !has_apps => "applications.status.noApps",
                "AVAILABLE" => "applications.status.available",
                "PARTIAL" => "applications.status.partial",
                _ => "applications.status.unavailable",
            },
            match inventory_state {
                "AVAILABLE" => "protected",
                "PARTIAL" => "review",
                _ => "unavailable",
            },
        )],
        portal: vec![semantic_status_row(
            "applications.status.integration",
            if portal_ready {
                "state.available"
            } else {
                "state.reviewNeeded"
            },
            if portal_ready {
                "applications.status.integrationAvailable"
            } else {
                "applications.status.integrationReview"
            },
            if portal_ready { "protected" } else { "review" },
        )],
        shown_count: inventory_total,
        inventory_total,
        review_needed_count,
        inventory_state: inventory_state.into(),
        apps,
    })
}

fn normalize_application_access(app: greyward_security_backends::FlatpakApp) -> ApplicationSummary {
    let effective_access = resolve_flatpak_access(&app);
    let access_categories = effective_access
        .categories
        .iter()
        .map(|category| category.code().into())
        .collect();
    let review_reasons = effective_access
        .review_reasons
        .iter()
        .map(|category| category.code().into())
        .collect();
    ApplicationSummary {
        name: app.name,
        access_state: if effective_access.availability != FlatpakAvailability::Available {
            "UNAVAILABLE".to_string()
        } else if effective_access.needs_review() {
            "REVIEW_NEEDED".to_string()
        } else {
            "SCOPED".to_string()
        },
        access_categories,
        review_reasons,
        technical: ApplicationTechnicalDetails {
            app_id: app.app_id,
            scope: app.scope,
            origin: app.origin,
            version: app.version,
            arch: app.arch,
            branch: app.branch,
            runtime: app.runtime,
            // Historical wire key retained as a compatibility alias; the
            // provider returns an effective context, not a raw manifest.
            manifest_permissions: app.permissions.clone(),
            effective_permissions: app.permissions,
            deployment_commit: app.deployment_commit,
            identity_state: match app.identity_state {
                greyward_security_backends::FlatpakAvailability::Available => "AVAILABLE",
                greyward_security_backends::FlatpakAvailability::Partial => "PARTIAL",
                greyward_security_backends::FlatpakAvailability::Unavailable
                | greyward_security_backends::FlatpakAvailability::Error => "UNAVAILABLE",
                greyward_security_backends::FlatpakAvailability::Unknown => "UNKNOWN",
            }
            .to_owned(),
            local_overrides: app.overrides,
        },
    }
}

fn recovery_helper_path() -> PathBuf {
    PathBuf::from("/usr/libexec/greyward-recovery-point")
}

fn backup_helper_path() -> PathBuf {
    PathBuf::from("/usr/libexec/greyward-backup")
}

fn run_json_helper(
    path: PathBuf,
    args: &[String],
    input: Option<&str>,
    timeout_seconds: u64,
) -> Result<Value, String> {
    let mut command = Command::new("/usr/bin/timeout");
    command
        .arg("--foreground")
        .arg(format!("{timeout_seconds}s"))
        .arg(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|_| "The GREYWARD recovery helper is unavailable.".to_string())?;
    if let Some(value) = input {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(value.as_bytes())
                .map_err(|_| "The recovery credential could not be passed safely.".to_string())?;
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "The GREYWARD recovery helper did not complete.".to_string())?;
    if output.status.code() == Some(124) {
        return Err("The GREYWARD helper took too long and was stopped.".into());
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() {
        if let Ok(value) = serde_json::from_str::<Value>(&stdout) {
            if let Some(error) = value.get("error").and_then(Value::as_str) {
                let problem = value.get("problem").and_then(Value::as_str).unwrap_or("");
                let detail = if problem.is_empty() {
                    error.to_string()
                } else {
                    format!("[{problem}] {error}")
                };
                return Err(detail.chars().take(240).collect());
            }
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            "The recovery operation was refused.".into()
        } else {
            detail.chars().take(240).collect()
        });
    }
    serde_json::from_str(&stdout).map_err(|_| "The recovery helper returned invalid data.".into())
}

fn recovery_point_status() -> Value {
    run_json_helper(
        recovery_helper_path(),
        &["list".into()],
        None,
        FAST_HELPER_TIMEOUT_SECONDS,
    )
    .unwrap_or_else(|error| json!({"ok": false, "error": error, "points": []}))
}

fn backup_status() -> Value {
    run_json_helper(
        backup_helper_path(),
        &["status".into()],
        None,
        FAST_HELPER_TIMEOUT_SECONDS,
    )
    .unwrap_or_else(|error| json!({"ok": false, "error": error, "configured": false}))
}

#[tauri::command]
fn get_recovery() -> Result<Value, String> {
    Ok(recovery_point_status())
}

#[tauri::command]
fn create_recovery_point() -> Result<Value, String> {
    let helper = recovery_helper_path();
    let args: Vec<String> = vec!["create".into(), "--reason".into(), "manual".into()];
    let value = run_json_helper(
        PathBuf::from("/usr/bin/pkexec"),
        &[
            helper.to_string_lossy().into_owned(),
            args[0].clone(),
            args[1].clone(),
            args[2].clone(),
        ],
        None,
        RECOVERY_HELPER_TIMEOUT_SECONDS,
    )?;
    let _ = record_action(
        "Local recovery point created",
        "A manual Btrfs safety point was recorded.",
    );
    Ok(value)
}

#[tauri::command]
fn cleanup_recovery_points() -> Result<Value, String> {
    let helper = recovery_helper_path();
    run_json_helper(
        PathBuf::from("/usr/bin/pkexec"),
        &[helper.to_string_lossy().into_owned(), "cleanup".into()],
        None,
        RECOVERY_HELPER_TIMEOUT_SECONDS,
    )
}

fn interactive_output(command: &mut Command) -> Result<std::process::Output, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "The native interactive control is unavailable.".to_string())?;
    let deadline = Instant::now() + INTERACTIVE_COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|_| "The native interactive control did not complete.".to_string());
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The native interactive control timed out.".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The native interactive control could not be monitored.".into());
            }
        }
    }
}

fn pick_directory() -> Result<Option<String>, String> {
    let mut command = Command::new("zenity");
    command.args([
        "--file-selection",
        "--directory",
        "--title=Choose a backup destination",
    ]);
    let output = interactive_output(&mut command)
        .map_err(|error| format!("The native directory picker failed: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let path = String::from_utf8(output.stdout)
        .map_err(|_| "The directory picker returned an invalid path.".to_string())?
        .trim()
        .to_string();
    Ok((!path.is_empty()).then_some(path))
}

fn prompt_secret(title: &str) -> Result<Option<String>, String> {
    let mut command = Command::new("zenity");
    command.args(["--password", &format!("--title={title}")]);
    let output = interactive_output(&mut command)
        .map_err(|error| format!("The native password prompt failed: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "The password prompt returned invalid data.".to_string())?
        .trim_end_matches(&['\r', '\n'][..])
        .to_string();
    Ok((!value.is_empty()).then_some(value))
}

fn configure_backup_with_password(
    destination: String,
    password: String,
    confirm: String,
) -> Result<Value, String> {
    run_json_helper(
        backup_helper_path(),
        &[
            "configure".into(),
            "--destination".into(),
            destination,
            "--password-stdin".into(),
        ],
        Some(&format!("{password}\n{confirm}\n")),
        RECOVERY_HELPER_TIMEOUT_SECONDS,
    )
}

fn backup_operation(operation: &str, extra: &[String]) -> Result<Value, String> {
    let status = backup_status();
    if status.get("configured") != Some(&Value::Bool(true)) {
        return Ok(json!({
            "ok": false,
            "needs_configuration": true,
            "message": "Choose a backup destination before starting a Restic backup."
        }));
    }
    if status.get("destination_available") != Some(&Value::Bool(true)) {
        return Ok(json!({
            "ok": false,
            "destination_unavailable": true,
            "problem": status.get("destination_problem").cloned().unwrap_or_else(|| json!("CHECK_DESTINATION")),
            "message": "The configured Restic destination is not available. Reconnect it or choose another destination."
        }));
    }
    let Some(password) = prompt_secret("GREYWARD Restic passphrase")? else {
        return Ok(
            json!({"ok": false, "cancelled": true, "message": "No passphrase was entered."}),
        );
    };
    let mut args = vec![operation.to_string(), "--password-stdin".to_string()];
    args.extend(extra.iter().cloned());
    let timeout = if operation == "list-files" {
        BACKUP_LIST_TIMEOUT_SECONDS
    } else {
        BACKUP_HELPER_TIMEOUT_SECONDS
    };
    run_json_helper(
        backup_helper_path(),
        &args,
        Some(&format!("{password}\n")),
        timeout,
    )
}

#[tauri::command]
fn get_backup() -> Result<Value, String> {
    Ok(backup_status())
}

#[tauri::command]
fn configure_backup() -> Result<Value, String> {
    let Some(destination) = pick_directory()? else {
        return Ok(
            json!({"ok": false, "cancelled": true, "message": "Backup destination selection was cancelled; the current destination was unchanged."}),
        );
    };
    let Some(password) = prompt_secret("Create GREYWARD Restic passphrase")? else {
        return Ok(
            json!({"ok": false, "cancelled": true, "message": "No passphrase was entered."}),
        );
    };
    let Some(confirm) = prompt_secret("Confirm GREYWARD Restic passphrase")? else {
        return Ok(
            json!({"ok": false, "cancelled": true, "message": "Passphrase confirmation was cancelled."}),
        );
    };
    configure_backup_with_password(destination, password, confirm)
}

#[tauri::command]
fn backup_now() -> Result<Value, String> {
    if backup_status().get("configured") != Some(&Value::Bool(true)) {
        return Ok(
            json!({"ok": false, "needs_configuration": true, "message": "Choose a backup destination before starting a Restic backup."}),
        );
    }
    backup_operation("backup", &[])
}

#[tauri::command]
fn verify_backup() -> Result<Value, String> {
    backup_operation("verify", &[])
}

#[tauri::command]
fn list_backup_files() -> Result<Value, String> {
    backup_operation("list-files", &[])
}

#[tauri::command]
fn restore_backup_files(paths: Vec<String>) -> Result<Value, String> {
    if paths.len() > 100 {
        return Err("Select fewer files for one restore operation.".into());
    }
    backup_operation("restore", &paths)
}

#[tauri::command(async)]
fn get_devices(include_history: Option<bool>) -> Result<DevicePayload, String> {
    // Devices only needs local USB/recovery facts. Do not make it wait for the
    // full posture graph's unrelated firmware, package, Flatpak, portal, and
    // network providers.
    let collection = collect_device_snapshot();
    let usb = collection.usb;
    let usb_installed = matches!(
        usb.availability,
        greyward_security_backends::UsbGuardAvailability::Available
    );
    let usb_enforcing = usb_installed
        && matches!(
            usb.policy,
            greyward_security_backends::UsbGuardPolicy::Running
        );
    let snapshot = collection.snapshot;
    let recovery = snapshot
        .checks
        .iter()
        .find(|c| c.check_id.as_str() == "recovery.readiness");
    let recovery_row = match recovery {
        Some(check) => {
            let presentation = evidence_presentation(check, &snapshot.accepted_deviations);
            StatusRow {
                label: String::new(),
                label_key: Some(presentation.title_key.into()),
                value: display_state(check.state),
                value_key: (check.reason_code == "accepted-deviation")
                    .then(|| "evidence.limitation.accepted".into()),
                detail: String::new(),
                detail_key: Some(presentation.summary_key.into()),
                copy_values: presentation.values,
                tone: state_tone(check.state).into(),
            }
        }
        None => semantic_row(
            "devices.recovery.readiness",
            "UNKNOWN",
            "devices.recovery.readinessUnavailable",
            "unknown",
        ),
    };
    // These are independent read-only surfaces. Keep the local device facts
    // authoritative, while avoiding a serial wait on three unrelated IPC /
    // helper paths before the page can render.
    let (device_history, recovery_v1, backup) = std::thread::scope(|scope| {
        let device_history = scope.spawn(|| {
            // Backup/recovery has no device-history surface. Keep its required
            // local readiness/status reads independent of this optional user-bus read.
            if include_history == Some(false) {
                return json!({"summary":{"source_state":"UNAVAILABLE","connected_external":null,"new_unknown_count":null,"new_unknown":[]},"devices":[]});
            }
            security_context_method(
                "systems.mantis.greyward.SecurityContext1.GetDeviceOverview",
            )
            .unwrap_or_else(|_| {
                json!({"summary":{"source_state":"UNAVAILABLE","connected_external":null,"new_unknown_count":null,"new_unknown":[]},"devices":[]})
            })
        });
        let recovery_v1 = scope.spawn(recovery_point_status);
        let backup = scope.spawn(backup_status);
        (
            device_history.join().unwrap_or_else(|_| json!({"summary":{"source_state":"UNAVAILABLE","connected_external":null,"new_unknown_count":null,"new_unknown":[]},"devices":[]})),
            recovery_v1.join().unwrap_or_else(|_| json!({"ok":false,"points":[]})),
            backup.join().unwrap_or_else(|_| json!({"ok":false,"configured":false})),
        )
    });
    Ok(DevicePayload {
        usb: vec![
            row(
                "USBGUARD",
                if usb_installed {
                    "INSTALLED"
                } else {
                    "UNAVAILABLE"
                },
                &format!(
                    "Installed capability: {} Â· Enforcement: {:?}",
                    if usb_installed { "present" } else { "absent" },
                    usb.policy
                ),
                if usb_enforcing {
                    "protected"
                } else if usb_installed {
                    "review"
                } else {
                    "unavailable"
                },
            ),
            row(
                "CONNECTED DEVICES",
                &usb.connected_devices.to_string(),
                &format!(
                    "Authorized: {} Â· Unknown: {}",
                    usb.authorized_devices, usb.unknown_devices
                ),
                "unknown",
            ),
        ],
        recovery: vec![
            recovery_row,
            semantic_row(
                "devices.recovery.evidence",
                "OBSERVED",
                "devices.recovery.evidenceCopy",
                "protected",
            ),
        ],
        device_history,
        recovery_v1,
        backup,
    })
}
#[tauri::command(async)]
fn get_evidence() -> Result<EvidencePayload, String> {
    let snapshot = core_collection_for_read().snapshot;
    let mut groups: std::collections::BTreeMap<String, Vec<EvidenceRow>> =
        std::collections::BTreeMap::new();
    for check in &snapshot.checks {
        let presentation = evidence_presentation(check, &snapshot.accepted_deviations);
        groups
            .entry(presentation.domain_key.into())
            .or_default()
            .push(EvidenceRow {
                title_key: presentation.title_key.into(),
                check_id: check.check_id.to_string(),
                state: display_state(check.state),
                tone: state_tone(check.state).into(),
                summary_key: presentation.summary_key.into(),
                recorded_result_key: presentation.recorded_result_key.into(),
                recommendation_key: presentation.recommendation_key.into(),
                copy_values: presentation.values,
                accepted_deviation: check.reason_code == "accepted-deviation",
                evidence_count: check.evidence.len(),
                remediation: presentation
                    .remediation
                    .map(|value| EvidenceRemediationProjection {
                        route: value.route.into(),
                        action_key: value.action_key.into(),
                    }),
                no_remediation_key: presentation.no_remediation_key.map(Into::into),
                technical: EvidenceTechnicalDetails {
                    reference: check.check_id.to_string(),
                    reason_code: check.reason_code.clone(),
                    observed_at: check.observed_at.to_rfc3339(),
                    fresh_until: check.fresh_until.to_rfc3339(),
                },
            });
    }
    Ok(EvidencePayload {
        generated_at: snapshot.generated_at.to_rfc3339(),
        policy_profile: snapshot.policy_profile,
        sections: groups
            .into_iter()
            .map(|(domain, rows)| EvidenceSection {
                domain,
                count: rows.len(),
                rows,
            })
            .collect(),
    })
}
fn security_context_string_method(method: &str, path: &str) -> Result<serde_json::Value, String> {
    if path.len() > 4096 {
        return Err("Security Context rejected an oversized path.".into());
    }
    security_context_json_call(method, (path,))
}

fn security_context_method(method: &str) -> Result<serde_json::Value, String> {
    security_context_json_call(method, ())
}

fn security_context_activity_method(
    method: &str,
    since_sequence: u64,
    limit: u32,
) -> Result<serde_json::Value, String> {
    let bounded_limit = limit.clamp(1, 256);
    security_context_json_call(method, (since_sequence, bounded_limit))
}

fn security_context_payload_method(method: &str, payload: &str) -> Result<Value, String> {
    if payload.len() > 8192 || payload.contains('\0') {
        return Err("Security Context rejected an oversized or invalid request.".into());
    }
    security_context_json_call(method, (payload,))
}

fn security_context_json_call<A>(method: &str, arguments: A) -> Result<Value, String>
where
    A: dbus::arg::AppendAll,
{
    let member = method
        .rsplit('.')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Security Context method is invalid.".to_string())?;
    let connection = Connection::new_session()
        .map_err(|_| "Security Context user service is unavailable.".to_string())?;
    let proxy = connection.with_proxy(
        SECURITY_CONTEXT_BUS_NAME,
        SECURITY_CONTEXT_OBJECT_PATH,
        SECURITY_CONTEXT_CALL_TIMEOUT,
    );
    let (payload,): (String,) = proxy
        .method_call(SECURITY_CONTEXT_BUS_NAME, member, arguments)
        .map_err(|_| "Security Context refused the request.".to_string())?;
    serde_json::from_str(&payload).map_err(|_| "Security Context returned invalid JSON.".into())
}

// Only the fixed commands below can call this source read transport. No UI
// argument selects a member, claimed UID, filesystem path or policy operation.
fn application_security_read<A>(member: &'static str, arguments: A) -> Result<String, String>
where
    A: dbus::arg::AppendAll,
{
    let connection = Connection::new_session()
        .map_err(|_| "Application Security Context is unavailable.".to_string())?;
    let proxy = connection.with_proxy(
        SECURITY_CONTEXT_BUS_NAME,
        SECURITY_CONTEXT_OBJECT_PATH,
        Duration::from_secs(8),
    );
    let (payload,): (String,) = proxy
        .method_call(SECURITY_CONTEXT_BUS_NAME, member, arguments)
        .map_err(|_| "Application Security Context refused the read.".to_string())?;
    if payload.len() > MAX_APPLICATION_READ_BYTES {
        return Err("Application Security exceeded its response budget.".into());
    }
    Ok(payload)
}

#[tauri::command(async)]
fn get_administration_state() -> Result<serde_json::Value, String> {
    let payload = application_security_read("GetAdministrationState", ())?;
    let value: serde_json::Value = serde_json::from_str(&payload)
        .map_err(|_| "Administration state is unavailable.".to_string())?;
    if value.get("schema") != Some(&serde_json::json!("greyward.administration/v1"))
        || !value
            .get("available")
            .is_some_and(serde_json::Value::is_boolean)
        || !value
            .get("active")
            .is_some_and(serde_json::Value::is_boolean)
        || value.get("authentication_window_seconds") != Some(&serde_json::json!(120))
        || value.as_object().is_none_or(|object| object.len() != 4)
    {
        return Err("Administration returned invalid state.".into());
    }
    Ok(value)
}
#[tauri::command(async)]
fn open_administration() -> Result<(), String> {
    let payload = application_security_read("OpenAdministration", ())?;
    let value: serde_json::Value = serde_json::from_str(&payload)
        .map_err(|_| "Administration returned an invalid response.".to_string())?;
    if value != serde_json::json!({"opened":true}) {
        return Err("Administration could not be opened.".into());
    }
    Ok(())
}
#[tauri::command(async)]
fn get_application_security_coverage()
-> Result<ApplicationReadEnvelope<ApplicationCoverage>, String> {
    let payload = application_security_read("GetApplicationCoverage", ())?;
    decode_application_coverage(&payload, Utc::now()).map_err(|error| error.to_string())
}

#[tauri::command(async)]
fn list_application_security_applications(
    query: ApplicationPageQuery,
) -> Result<ApplicationReadEnvelope<ApplicationInventoryPage>, String> {
    query.validate().map_err(|error| error.to_string())?;
    let after = query.after.as_ref().map_or("", SecurityReference::as_str);
    let payload = application_security_read(
        "ListApplications",
        (
            query.limit,
            query.revision.is_some(),
            query.revision.unwrap_or(0),
            after,
        ),
    )?;
    decode_application_page(&payload, &query, Utc::now()).map_err(|error| error.to_string())
}

#[tauri::command(async)]
fn get_application_security_application(
    installation_ref: SecurityReference,
) -> Result<ApplicationReadEnvelope<ApplicationLookup>, String> {
    if installation_ref.namespace() != "installation" {
        return Err("Application Security rejected an invalid installation reference.".into());
    }
    let payload = application_security_read("GetApplication", (installation_ref.as_str(),))?;
    decode_application_detail(&payload, &installation_ref, Utc::now())
        .map_err(|error| error.to_string())
}

#[tauri::command(async)]
fn list_application_security_resources(
    query: ProtectedResourcePageQuery,
) -> Result<ApplicationReadEnvelope<ProtectedResourcePage>, String> {
    query.validate().map_err(|error| error.to_string())?;
    let after = query.after.as_ref().map_or("", SecurityReference::as_str);
    let payload = application_security_read(
        "ListProtectedResources",
        (
            query.limit,
            query.revision.is_some(),
            query.revision.unwrap_or(0),
            after,
        ),
    )?;
    decode_protected_resource_page(&payload, &query, Utc::now()).map_err(|error| error.to_string())
}

#[tauri::command(async)]
fn get_application_security_resource(
    resource_ref: SecurityReference,
) -> Result<ApplicationReadEnvelope<ProtectedResourceLookup>, String> {
    if resource_ref.namespace() != "resource" {
        return Err("Application Security rejected an invalid resource reference.".into());
    }
    let payload = application_security_read("GetProtectedResource", (resource_ref.as_str(),))?;
    decode_protected_resource_lookup(&payload, &resource_ref, Utc::now())
        .map_err(|error| error.to_string())
}

#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApplicationGrantList {
    schema: String,
    policy_revision: u64,
    enforcement_health: String,
    grants: Vec<AccessGrant>,
    #[serde(default)]
    capabilities: ApplicationWorkflowCapabilities,
}
#[derive(Default, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApplicationWorkflowCapabilities {
    isolation: bool,
    policy_changes: bool,
}
#[tauri::command(async)]
fn list_application_security_grants() -> Result<ApplicationGrantList, String> {
    let payload = application_security_read("ListApplicationAccessGrants", ())?;
    let list: ApplicationGrantList = serde_json::from_str(&payload)
        .map_err(|_| "Application Security returned invalid grants.".to_string())?;
    if list.schema != greyward_security_domain::APPLICATION_SECURITY_SCHEMA
        || list.policy_revision == 0
        || list.enforcement_health != "UNKNOWN"
        || list.grants.len() > 256
    {
        return Err("Application Security returned invalid grants.".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for grant in &list.grants {
        grant.validate().map_err(|error| error.to_string())?;
        if grant.owner_uid != rustix::process::getuid().as_raw()
            || grant.policy_revision > list.policy_revision
            || !seen.insert(&grant.grant_ref)
        {
            return Err("Application Security returned invalid grants.".into());
        }
    }
    Ok(list)
}
fn application_review(payload: &str) -> Result<WorkflowPreview, String> {
    let preview: WorkflowPreview = serde_json::from_str(payload)
        .map_err(|_| "Application Security returned an invalid review.".to_string())?;
    preview.validate().map_err(|error| error.to_string())?;
    Ok(preview)
}
fn application_picker(directory: bool) -> Result<Option<String>, String> {
    let mut command = Command::new("zenity");
    command.args([
        "--file-selection",
        "--title=Application Guard â€” choose a resource or installed tool",
    ]);
    if directory {
        command.arg("--directory");
    }
    let output = interactive_output(&mut command)?;
    if !output.status.success() {
        return Ok(None);
    }
    let path =
        String::from_utf8(output.stdout).map_err(|_| "The selection was invalid.".to_string())?;
    let path = path.trim_end_matches(['\r', '\n']);
    if path.is_empty() || path.len() > 4096 || !path.starts_with('/') || path.contains('\0') {
        return Err("The selection was invalid.".into());
    }
    Ok(Some(path.to_owned()))
}
#[tauri::command(async)]
fn pick_application_security_resource(
    revision: u64,
    label: String,
    category: Option<String>,
) -> Result<Option<WorkflowPreview>, String> {
    let category = category.as_deref().unwrap_or("CUSTOM");
    if ![
        "CREDENTIALS",
        "CLOUD",
        "DEVELOPMENT",
        "BROWSER_SESSION",
        "CUSTOM",
    ]
    .contains(&category)
    {
        return Err("Choose a supported resource category.".into());
    }
    if revision == 0 || label.is_empty() || label.len() > 256 || label.chars().any(char::is_control)
    {
        return Err("Choose a bounded resource label and refresh policy first.".into());
    }
    let Some(path) = application_picker(true)? else {
        return Ok(None);
    };
    let directory = rustix::fs::open(
        &path,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "The selected directory could not be held.".to_string())?;
    let file = std::fs::File::from(directory);
    let payload = application_security_read(
        "PreviewProtectedResource",
        (file, category, label, revision),
    )?;
    let preview = application_review(&payload)?;
    if !matches!(&preview, WorkflowPreview::Registration(p) if p.resource.owner_uid == rustix::process::getuid().as_raw())
    {
        return Err("The provider returned a different review.".into());
    }
    Ok(Some(preview))
}
#[tauri::command(async)]
fn pick_application_security_grant(
    resource_refs: Vec<SecurityReference>,
    revision: u64,
) -> Result<Option<WorkflowPreview>, String> {
    if revision == 0
        || resource_refs.is_empty()
        || resource_refs.len() > 64
        || resource_refs.iter().any(|r| r.namespace() != "resource")
    {
        return Err("Select registered resources and refresh policy first.".into());
    }
    let Some(path) = application_picker(false)? else {
        return Ok(None);
    };
    greyward_security_domain::InstalledExecutablePath::try_from(path.as_str())
        .map_err(|error| error.to_string())?;
    let resources: Vec<_> = resource_refs
        .iter()
        .map(SecurityReference::as_str)
        .collect();
    let payload =
        application_security_read("PreviewApplicationGrant", (path, resources, revision))?;
    let preview = application_review(&payload)?;
    if !matches!(&preview, WorkflowPreview::Grant { .. }) {
        return Err("The provider returned a different review.".into());
    }
    Ok(Some(preview))
}
#[tauri::command(async)]
fn pick_application_security_revocation(
    grant_ref: SecurityReference,
    revision: u64,
) -> Result<Option<WorkflowPreview>, String> {
    if grant_ref.namespace() != "grant" || revision == 0 {
        return Err("Invalid grant review.".into());
    }
    let payload = application_security_read(
        "PreviewApplicationRevocation",
        (grant_ref.as_str(), "", revision),
    )?;
    let preview = application_review(&payload)?;
    if !matches!(&preview, WorkflowPreview::Revocation(_)) {
        return Err("The provider returned a different review.".into());
    }
    Ok(Some(preview))
}
fn application_operation(
    member: &'static str,
    operation_ref: &SecurityReference,
) -> Result<OperationResult, String> {
    if operation_ref.namespace() != "operation" {
        return Err("Invalid operation reference.".into());
    }
    let payload = application_security_read(member, (operation_ref.as_str(),))?;
    let result: OperationResult = serde_json::from_str(&payload)
        .map_err(|_| "Application Security returned an invalid result.".to_string())?;
    result.validate().map_err(|error| error.to_string())?;
    if &result.operation_ref != operation_ref {
        return Err("Application Security returned a different operation.".into());
    }
    Ok(result)
}
#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApplicationLaunchReview {
    schema: String,
    launch_ref: SecurityReference,
    requested_profile: String,
    enforcement_health: String,
    private_display_requested: bool,
    expires_after_ms: u64,
}
#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApplicationLaunchResult {
    schema: String,
    launch_ref: SecurityReference,
    state: String,
    isolation_established: bool,
    enforcement_health: String,
    private_display: bool,
}
#[tauri::command(async)]
fn pick_application_security_launch() -> Result<Option<ApplicationLaunchReview>, String> {
    let Some(path) = application_picker(false)? else {
        return Ok(None);
    };
    let descriptor = rustix::fs::open(
        &path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "The selected code could not be held.".to_string())?;
    let payload = application_security_read(
        "PrepareApplicationLaunch",
        (std::fs::File::from(descriptor), true),
    )?;
    let review: ApplicationLaunchReview = serde_json::from_str(&payload)
        .map_err(|_| "Application Guard returned an invalid preparation.".to_string())?;
    if review.schema != greyward_security_domain::APPLICATION_SECURITY_SCHEMA
        || review.launch_ref.namespace() != "launch"
        || review.requested_profile != "ISOLATED"
        || review.enforcement_health != "UNKNOWN"
        || !review.private_display_requested
        || review.expires_after_ms == 0
        || review.expires_after_ms > 90000
    {
        return Err("Application Guard returned an invalid preparation.".into());
    }
    Ok(Some(review))
}
#[tauri::command(async)]
fn start_application_security_launch(
    launch_ref: SecurityReference,
) -> Result<ApplicationLaunchResult, String> {
    if launch_ref.namespace() != "launch" {
        return Err("Invalid launch reference.".into());
    }
    let payload = application_security_read("StartApplicationLaunch", (launch_ref.as_str(),))?;
    let result: ApplicationLaunchResult = serde_json::from_str(&payload)
        .map_err(|_| "Application Guard returned an invalid launch readback.".to_string())?;
    if result.schema != greyward_security_domain::APPLICATION_SECURITY_SCHEMA
        || result.launch_ref != launch_ref
        || result.state != "LAUNCHED"
        || !result.isolation_established
        || !result.private_display
        || result.enforcement_health != "UNKNOWN"
    {
        return Err("Application Guard could not confirm private isolation.".into());
    }
    Ok(result)
}
#[tauri::command(async)]
fn apply_application_security_policy(
    operation_ref: SecurityReference,
) -> Result<OperationResult, String> {
    application_operation("ApplyApplicationPolicy", &operation_ref)
}
#[tauri::command(async)]
fn get_application_security_operation(
    operation_ref: SecurityReference,
) -> Result<OperationResult, String> {
    application_operation("GetApplicationOperation", &operation_ref)
}
#[tauri::command(async)]
fn cancel_application_security_operation(
    operation_ref: SecurityReference,
) -> Result<OperationResult, String> {
    application_operation("CancelApplicationOperation", &operation_ref)
}

#[tauri::command]
fn get_clamav_status() -> Result<ClamAvStatus, String> {
    serde_json::from_value(security_context_method(
        "systems.mantis.greyward.SecurityContext1.GetClamAvStatus",
    )?)
    .map_err(|_| "ClamAV returned an invalid status.".into())
}
#[tauri::command(async)]
fn get_updates() -> Result<serde_json::Value, String> {
    update_center_dbus_method("GetSnapshot")
}

fn update_center_dbus_method(method: &str) -> Result<serde_json::Value, String> {
    let connection = Connection::new_session()
        .map_err(|_| "GREYWARD Update Center user service is unavailable.".to_string())?;
    let proxy = connection.with_proxy(
        "org.greyward.Update1",
        "/org/greyward/Update1",
        SECURITY_CONTEXT_CALL_TIMEOUT,
    );
    let (payload,): (String,) = proxy
        .method_call("org.greyward.Update1", method, ())
        .map_err(|_| "GREYWARD Update Center refused the request.".to_string())?;
    serde_json::from_str(&payload)
        .map_err(|_| "GREYWARD Update Center returned invalid JSON.".into())
}

fn navigation_request_path() -> std::path::PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("greyward-security-center-navigation")
}

#[tauri::command]
fn consume_navigation_request(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let path = navigation_request_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(value) => value.trim().to_string(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "Could not read the Security Center navigation request: {error}"
            ));
        }
    };
    let _ = std::fs::remove_file(path);
    let mut lines = raw.lines();
    let value = lines.next().unwrap_or("").trim().to_string();
    let event_id = lines.next().unwrap_or("").trim().to_string();
    if value == "protected-data"
        && !event_id.is_empty()
        && (event_id.len() != 73
            || !event_id.starts_with("resource_")
            || !event_id[9..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Ok(None);
    }
    // A shell deep-link can arrive while the existing Security Center window
    // is minimized. Restore and focus that same window before the frontend
    // switches pages; this preserves the single-instance taskbar identity.
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    if SECURITY_CENTER_ROUTES.contains(&value.as_str()) {
        let value =
            if matches!(value.as_str(), "threats" | "protected-data") && !event_id.is_empty() {
                format!("{value}|{event_id}")
            } else {
                value
            };
        use tauri::Emitter;
        let _ = app.emit("security-navigation", &value);
        return Ok(Some(value));
    }
    Ok(None)
}

#[tauri::command]
fn get_update_transaction() -> Result<serde_json::Value, String> {
    update_center_dbus_method("GetTransactionStatus")
}

#[tauri::command]
fn resolve_system_update() -> Result<serde_json::Value, String> {
    update_center_dbus_method("ResolveSystemUpdate")
}

#[tauri::command]
fn update_all() -> Result<serde_json::Value, String> {
    update_center_dbus_method("UpdateAll")
}

#[tauri::command]
fn apply_system_update() -> Result<serde_json::Value, String> {
    update_center_dbus_method("ApplySystemUpdate")
}

#[tauri::command]
fn prepare_system_update() -> Result<serde_json::Value, String> {
    update_center_dbus_method("PrepareSystemUpdate")
}

#[tauri::command]
fn restart_apply_update() -> Result<serde_json::Value, String> {
    update_center_dbus_method("RestartAndApply")
}

#[tauri::command]
fn cancel_update() -> Result<serde_json::Value, String> {
    update_center_dbus_method("CancelUpdate")
}
#[tauri::command]
fn get_file_context() -> Result<Option<serde_json::Value>, String> {
    let Some(path) = std::env::var_os("GREYWARD_CONTEXT_FILE") else {
        return Ok(None);
    };
    let path = path.to_string_lossy().into_owned();
    let provenance = security_context_string_method(
        "systems.mantis.greyward.SecurityContext1.GetProvenance",
        &path,
    )?;
    Ok(Some(
        serde_json::json!({"file_name": std::path::Path::new(&path).file_name().and_then(|v| v.to_str()).unwrap_or("Selected file"), "path": path, "provenance": provenance}),
    ))
}
#[tauri::command]
fn start_file_security_scan(mode: String, paths: Vec<String>) -> Result<serde_json::Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.StartScan",
        &serde_json::to_string(&serde_json::json!({"mode": mode, "paths": paths}))
            .map_err(|_| "The file scan request could not be encoded.".to_string())?,
    )
}
#[tauri::command]
fn get_file_security_scan_status(operation_id: String) -> Result<serde_json::Value, String> {
    security_context_string_method(
        "systems.mantis.greyward.SecurityContext1.GetScanStatus",
        &operation_id,
    )
}
#[tauri::command]
fn cancel_file_security_scan(operation_id: String) -> Result<serde_json::Value, String> {
    security_context_string_method(
        "systems.mantis.greyward.SecurityContext1.CancelScan",
        &operation_id,
    )
}
#[tauri::command]
fn list_file_security_detections(state: Option<String>) -> Result<serde_json::Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.ListFileDetections",
        &serde_json::to_string(&serde_json::json!({"state": state, "limit": 128}))
            .map_err(|_| "The detection request could not be encoded.".to_string())?,
    )
}
#[tauri::command]
fn quarantine_file_security_detection(detection_id: String) -> Result<serde_json::Value, String> {
    security_context_string_method(
        "systems.mantis.greyward.SecurityContext1.QuarantineDetection",
        &detection_id,
    )
}
#[tauri::command]
fn restore_file_security_detection(
    detection_id: String,
    destination: Option<String>,
) -> Result<serde_json::Value, String> {
    security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.RestoreDetection",
        &serde_json::to_string(&serde_json::json!({"detection_id": detection_id, "destination": destination.unwrap_or_default()}))
            .map_err(|_| "The restore request could not be encoded.".to_string())?,
    )
}
#[tauri::command]
fn delete_file_security_detection(detection_id: String) -> Result<serde_json::Value, String> {
    security_context_string_method(
        "systems.mantis.greyward.SecurityContext1.DeleteDetection",
        &detection_id,
    )
}
#[tauri::command]
fn get_provenance(path: String) -> Result<serde_json::Value, String> {
    security_context_string_method(
        "systems.mantis.greyward.SecurityContext1.GetProvenance",
        &path,
    )
}
#[tauri::command]
fn sanitize_copy(path: String) -> Result<serde_json::Value, String> {
    security_context_string_method(
        "systems.mantis.greyward.SecurityContext1.SanitizeCopy",
        &path,
    )
}
#[tauri::command]
fn safe_open(path: String) -> Result<serde_json::Value, String> {
    if path.len() > 4096 {
        return Err("Safe Open rejected an oversized path.".into());
    }
    security_context_string_method("systems.mantis.greyward.SecurityContext1.SafeOpen", &path)
}
#[tauri::command]
fn pick_safe_open_file() -> Result<Option<String>, String> {
    let mut command = std::process::Command::new("zenity");
    command.args(["--file-selection", "--title=Choose a file for Safe Open"]);
    let output = interactive_output(&mut command)
        .map_err(|error| format!("The native file picker failed: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let path = String::from_utf8(output.stdout)
        .map_err(|_| "The native file picker returned an invalid path.".to_string())?
        .trim()
        .to_string();
    Ok((!path.is_empty()).then_some(path))
}
#[tauri::command]
fn pick_file_security_source(directory: bool) -> Result<Option<String>, String> {
    let mut command = std::process::Command::new("zenity");
    command.args([
        "--file-selection",
        "--title=Choose a file or folder for scanning",
    ]);
    if directory {
        command.arg("--directory");
    }
    let output = interactive_output(&mut command)
        .map_err(|error| format!("The native file picker failed: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((!value.is_empty()).then_some(value))
}
#[tauri::command]
fn open_software() -> Result<serde_json::Value, String> {
    if std::process::Command::new("/usr/local/libexec/greyward-software")
        .spawn()
        .is_err()
    {
        return Err(
            "Software is unavailable because the Flatpak runtime or Bazaar is not installed."
                .into(),
        );
    }
    Ok(json!({"ok": true, "message": "Software opened."}))
}
#[tauri::command(async)]
fn set_privacy_profile(app: tauri::AppHandle, profile: String) -> Result<ActionResult, String> {
    let target = profile.trim().to_ascii_uppercase();
    let result = security_context_payload_method(
        "systems.mantis.greyward.SecurityContext1.SetPrivacyProfile",
        &target,
    )?;
    let confirmed_profile = result
        .get("profile")
        .and_then(Value::as_str)
        .map(str::to_ascii_uppercase);
    let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false)
        && confirmed_profile.as_deref() == Some(target.as_str());
    let message = if ok {
        format!(
            "{} profile applied and verified; Travel rotates identity only on reconnect.",
            target
                .to_ascii_lowercase()
                .replace("standard", "Standard")
                .replace("private", "Private")
                .replace("travel", "Travel")
        )
    } else if result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        format!(
            "Privacy profile confirmation did not match the requested {} profile.",
            target.to_ascii_lowercase()
        )
    } else {
        result
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("Privacy profile was not applied.")
            .to_string()
    };
    if ok {
        let _ = record_action("Privacy profile changed", &message);
        emit_state_changed(&app);
    }
    Ok(ActionResult {
        ok,
        message,
        refreshed: None,
        profile: confirmed_profile,
        path: None,
    })
}

#[tauri::command(async)]
fn get_filesecurity() -> Result<serde_json::Value, String> {
    // File Security must be independently readable. Do not make its page wait
    // for the full posture graph (or unrelated update/device providers).
    let file_security =
        security_context_method("systems.mantis.greyward.SecurityContext1.GetFileSecuritySummary")
            .unwrap_or_else(|_| {
                serde_json::json!({
                    "schema": "greyward.file-security/v1",
                    "state": "UNAVAILABLE",
                    "active_scan": null,
                    "latest_scan": null,
                    "detections": [],
                    "detail": "File Security status is unavailable."
                })
            });
    Ok(serde_json::json!({
        "clamav": file_security.get("clamav").cloned().unwrap_or(serde_json::Value::Null),
        "active_scan": file_security.get("active_scan").cloned().unwrap_or(serde_json::Value::Null),
        "latest_scan": file_security.get("latest_scan").cloned().unwrap_or(serde_json::Value::Null),
        "detections": file_security.get("detections").cloned().unwrap_or_else(|| serde_json::json!([])),
        "state": file_security.get("state").cloned().unwrap_or_else(|| serde_json::json!("UNAVAILABLE")),
        "activity": file_security.get("activity").cloned().unwrap_or_else(|| serde_json::json!([])),
    }))
}

#[tauri::command(async)]
fn get_privacy() -> Result<PrivacyPayload, String> {
    let actual = read_actual_state().ok();
    let (items, activity_state) = activity_summaries();
    let clamav = get_clamav_status().ok();
    let profile = actual
        .as_ref()
        .and_then(|state| state.profile)
        .map(|value| value.label())
        .unwrap_or("UNKNOWN");
    let identity = actual
        .as_ref()
        .map(|state| match state.mac_policy {
            greyward_security_backends::MacPolicy::Stable => row(
                "MAC IDENTITY",
                "STABLE PER NETWORK",
                "NetworkManager is configured to keep one identity for this connection.",
                "protected",
            ),
            greyward_security_backends::MacPolicy::RandomOnReconnect => row(
                "MAC IDENTITY",
                "ROTATES ON RECONNECT",
                "The active connection changes identity when it reconnects.",
                "review",
            ),
            greyward_security_backends::MacPolicy::Unknown if state.actual_mac.is_some() => row(
                "MAC IDENTITY",
                "DEVICE DEFAULT",
                "No cloned identity is configured; the active connection uses the device default.",
                "protected",
            ),
            greyward_security_backends::MacPolicy::Unknown => row(
                "MAC IDENTITY",
                "EVIDENCE UNAVAILABLE",
                "The active connection did not expose its configured identity behavior.",
                "unknown",
            ),
        })
        .unwrap_or_else(|| {
            row(
                "MAC IDENTITY",
                "UNAVAILABLE",
                "The active network connection could not be read.",
                "unavailable",
            )
        });
    let firewall = actual
        .as_ref()
        .map(|state| {
            row(
                "FIREWALL POSTURE",
                &readable(&format!("{:?}", state.firewall_zone)),
                "Firewall zone reported for this device.",
                "protected",
            )
        })
        .unwrap_or_else(|| {
            row(
                "FIREWALL POSTURE",
                "UNAVAILABLE",
                "firewalld state could not be verified.",
                "unavailable",
            )
        });
    let vpn = actual
        .as_ref()
        .map(|state| match state.vpn_active {
            Some(true) => row(
                "VPN",
                "ACTIVE",
                "An active VPN connection is reported.",
                "protected",
            ),
            Some(false) => row(
                "VPN",
                "NOT ACTIVE",
                "No active VPN connection is reported.",
                "muted",
            ),
            None => row(
                "VPN",
                "EVIDENCE UNAVAILABLE",
                "NetworkManager did not expose a reliable VPN state.",
                "unknown",
            ),
        })
        .unwrap_or_else(|| {
            row(
                "VPN",
                "UNAVAILABLE",
                "The active network connection could not be read.",
                "unavailable",
            )
        });
    let public_ip = row(
        "PUBLIC IP",
        "NOT ASSESSED",
        "Not checked in this local view.",
        "muted",
    );
    Ok(PrivacyPayload {
        profile: row(
            "ACTIVE PROFILE",
            profile,
            "Inferred from actual NetworkManager and firewalld state.",
            if profile == "UNKNOWN" {
                "unknown"
            } else {
                "protected"
            },
        ),
        identity,
        firewall,
        vpn,
        public_ip,
        clamav,
        local: vec![
            row(
                "DATA PATH",
                "LOCAL ONLY",
                "This view uses local security evidence.",
                "protected",
            ),
            row(
                "RETENTION",
                &format!("{} DAYS", greyward_security_backends::RETENTION_DAYS),
                &format!(
                    "At most {} activity items are retained.",
                    greyward_security_backends::MAX_ACTIVITY_ITEMS
                ),
                "unknown",
            ),
        ],
        disclosures: external_service_manifest()
            .into_iter()
            .map(|service| DisclosureSummary {
                component: service.component,
                state: if service.local_only {
                    "LOCAL ONLY".into()
                } else {
                    "DISCLOSED".into()
                },
                purpose: service.purpose,
                endpoints: if service.endpoints.is_empty() {
                    "none".into()
                } else {
                    service.endpoints.join(", ")
                },
                trigger: service.trigger,
                data_disclosed: service.data_disclosed,
                retention: service.retention,
                disable_route: service.disable_route,
            })
            .collect(),
        activity: items,
        activity_state,
        retention_days: greyward_security_backends::RETENTION_DAYS,
        max_activity_items: greyward_security_backends::MAX_ACTIVITY_ITEMS,
    })
}
#[tauri::command(async)]
fn export_posture(app: tauri::AppHandle) -> Result<ActionResult, String> {
    let path = write_safe_export(&collect_core_snapshot()).map_err(|e| e.to_string())?;
    let message = format!("Safe posture export written to {}.", path.display());
    let _ = record_action("Safe posture exported", &message);
    emit_state_changed(&app);
    Ok(ActionResult {
        ok: true,
        message,
        refreshed: None,
        profile: None,
        path: Some(path.to_string_lossy().into_owned()),
    })
}
#[tauri::command(async)]
fn clear_history(app: tauri::AppHandle) -> Result<ActionResult, String> {
    clear_activity().map_err(|e| e.to_string())?;
    emit_state_changed(&app);
    Ok(ActionResult {
        ok: true,
        message: "Local activity history cleared.".into(),
        refreshed: None,
        profile: None,
        path: None,
    })
}
fn emit_state_changed(app: &tauri::AppHandle) {
    invalidate_core_snapshot_cache();
    use tauri::Emitter;
    let _ = app.emit("security-state-changed", "local-state-updated");
}

fn network_payload() -> NetworkPayload {
    let network = collect_network_facts();
    let zone = readable(&format!("{:?}", network.trust_zone));
    NetworkPayload {
        connection: vec![row(
            "CONNECTION",
            network
                .active_connection
                .as_deref()
                .unwrap_or("UNAVAILABLE"),
            &format!(
                "Interface: {} Â· Type: {}",
                network.interface.as_deref().unwrap_or("unknown"),
                network.connection_type.as_deref().unwrap_or("unknown")
            ),
            if network.active_connection.is_some() {
                "protected"
            } else {
                "unavailable"
            },
        )],
        controls: vec![row(
            "FIREWALL ZONE",
            &zone,
            &format!(
                "Firewall service: {}",
                readable(&format!("{:?}", network.firewall))
            ),
            "review",
        )],
        evidence: vec![
            row(
                "INTERFACE",
                network.interface.as_deref().unwrap_or("UNAVAILABLE"),
                "Active interface identity",
                "unknown",
            ),
            row(
                "CONNECTION TYPE",
                network.connection_type.as_deref().unwrap_or("UNKNOWN"),
                "NetworkManager connection type",
                "unknown",
            ),
        ],
        interface: network.interface,
        zone,
    }
}
fn row(label: &str, value: &str, detail: &str, tone: &str) -> StatusRow {
    StatusRow {
        label: label.into(),
        label_key: None,
        value: value.into(),
        value_key: None,
        detail: detail.into(),
        detail_key: None,
        copy_values: BTreeMap::new(),
        tone: tone.into(),
    }
}
fn semantic_row(label_key: &str, value: &str, detail_key: &str, tone: &str) -> StatusRow {
    StatusRow {
        label: String::new(),
        label_key: Some(label_key.into()),
        value: value.into(),
        value_key: None,
        detail: String::new(),
        detail_key: Some(detail_key.into()),
        copy_values: BTreeMap::new(),
        tone: tone.into(),
    }
}
fn semantic_status_row(
    label_key: &str,
    value_key: &str,
    detail_key: &str,
    tone: &str,
) -> StatusRow {
    StatusRow {
        label: String::new(),
        label_key: Some(label_key.into()),
        value: String::new(),
        value_key: Some(value_key.into()),
        detail: String::new(),
        detail_key: Some(detail_key.into()),
        copy_values: BTreeMap::new(),
        tone: tone.into(),
    }
}
fn parse_zone(value: &str) -> Result<TrustZone, String> {
    match value.to_ascii_lowercase().as_str() {
        "public" => Ok(TrustZone::Public),
        "trusted" => Ok(TrustZone::Trusted),
        "home" => Ok(TrustZone::Home),
        "work" => Ok(TrustZone::Work),
        "drop" => Ok(TrustZone::Drop),
        "block" => Ok(TrustZone::Block),
        "external" => Ok(TrustZone::External),
        "dmz" => Ok(TrustZone::Dmz),
        _ => Err("Unsupported trust zone.".into()),
    }
}
fn readable(raw: &str) -> String {
    raw.split(['-', '_'])
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn display_state(state: PostureState) -> String {
    match state {
        PostureState::Secure => "SECURE",
        PostureState::Protected => "PROTECTED",
        PostureState::ReviewNeeded => "REVIEW NEEDED",
        PostureState::ActionRequired => "REVIEW NEEDED",
        PostureState::Unavailable => "UNAVAILABLE",
        PostureState::Unknown => "UNKNOWN",
        PostureState::NotApplicable => "NOT APPLICABLE",
    }
    .into()
}
fn state_tone(state: PostureState) -> &'static str {
    match state {
        PostureState::Secure => "secure",
        PostureState::Protected => "protected",
        PostureState::ReviewNeeded => "review",
        PostureState::ActionRequired => "review",
        PostureState::Unavailable => "unavailable",
        _ => "unknown",
    }
}
fn activity_summaries() -> (Vec<ActivitySummary>, String) {
    let Ok(items) = load_activity() else {
        return (Vec::new(), "UNAVAILABLE".into());
    };
    let result = items
        .into_iter()
        .rev()
        .take(8)
        .map(|item| ActivitySummary {
            title: item.title,
            detail: item.detail,
            category: format!("{:?}", item.category),
            severity: format!("{:?}", item.severity),
            occurred_at: item.occurred_at.to_rfc3339(),
        })
        .collect();
    (result, "AVAILABLE".into())
}
fn record_action(title: &str, detail: &str) -> Result<(), String> {
    record_activity(ActivityItem {
        event_id: format!(
            "action-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ),
        category: ActivityCategory::Action,
        severity: ActivitySeverity::Information,
        occurred_at: Utc::now(),
        title: title.into(),
        detail: detail.into(),
        related_check_id: None,
    })
    .map_err(|e| e.to_string())
}
struct InstanceLock {
    path: std::path::PathBuf,
}
impl InstanceLock {
    fn acquire() -> Option<Self> {
        let dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = dir.join("greyward-security-center.lock");
        for _ in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    use std::io::Write;
                    let mut file = file;
                    let _ = writeln!(file, "{}", std::process::id());
                    return Some(Self { path });
                }
                Err(_) => {
                    let stale = std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|pid| pid.trim().parse::<u32>().ok())
                        .map(|pid| {
                            #[cfg(unix)]
                            {
                                !std::path::Path::new("/proc").join(pid.to_string()).exists()
                            }
                            #[cfg(not(unix))]
                            {
                                false
                            }
                        })
                        .unwrap_or(false);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                    } else {
                        return None;
                    }
                }
            }
        }
        None
    }
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn run_cli_or_gui() {
    startup_trace("process_entry");
    if std::env::args().any(|arg| arg == "--print-posture") {
        match get_overview() {
            Ok(payload) => println!(
                "{}",
                serde_json::to_string(&payload).expect("serialize posture")
            ),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    run();
}

pub fn run() {
    startup_trace("run_entry");
    let _instance_lock = if std::env::var_os("GREYWARD_CONTEXT_FILE").is_some() {
        None
    } else {
        let Some(lock) = InstanceLock::acquire() else {
            return;
        };
        Some(lock)
    };
    startup_trace("instance_lock_ready");
    startup_trace("tauri_builder_start");
    tauri::Builder::default()
        .setup(|app| {
            startup_trace("tauri_setup_start");
            // Labwc may retain an old toplevel state across a launcher or
            // deep-link invocation. Always ask the canonical window to become
            // visible and focused once Tauri has created it; this is harmless
            // for a fresh window and keeps the single-instance launch path
            // observable in the installed desktop session.
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(target_os = "linux")]
                {
                    use gtk::prelude::GtkWindowExt;
                    let native = window.gtk_window()?;
                    // The main window owns its chrome. GTK can retain a native
                    // titlebar despite the initial Wayland decoration hint.
                    native.set_titlebar(None::<&gtk::Widget>);
                    native.set_decorated(false);
                }
                // WebKit does not inherit the desktop locale automatically.
                // Set its native language preference before frontend startup.
                #[cfg(target_os = "linux")]
                window.with_webview(|webview| {
                    use webkit2gtk::{WebContextExt, WebViewExt};
                    let languages: Vec<String> = webkit2gtk::glib::language_names()
                        .iter()
                        .filter_map(|language| {
                            let language = language.split('.').next()?.split('@').next()?;
                            (!matches!(language, "C" | "POSIX")).then(|| language.replace('_', "-"))
                        })
                        .take(16)
                        .collect();
                    let preferred: Vec<&str> = languages.iter().map(String::as_str).collect();
                    if let Some(context) = webview.inner().context() {
                        context.set_preferred_languages(&preferred);
                    }
                })?;
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
                startup_trace("window_show_requested");
            }
            // Hidden WebKit timers pause navigation polling. A native wake-up
            // consumes only an explicit shell request, including covered windows;
            // it never polls collectors or changes policy in the background.
            let navigation_app = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                    if navigation_app.get_webview_window("main").is_none() {
                        break;
                    }
                    if navigation_request_path().exists() {
                        let _ = consume_navigation_request(navigation_app.clone());
                    }
                }
            });
            startup_trace("tauri_setup_complete");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            window_chrome::window_chrome,
            get_overview,
            get_overview_activity,
            get_clamav_status,
            get_updates,
            consume_navigation_request,
            update_all,
            get_update_transaction,
            resolve_system_update,
            apply_system_update,
            prepare_system_update,
            restart_apply_update,
            cancel_update,
            safe_open,
            get_file_context,
            start_file_security_scan,
            get_file_security_scan_status,
            cancel_file_security_scan,
            list_file_security_detections,
            quarantine_file_security_detection,
            restore_file_security_detection,
            delete_file_security_detection,
            get_provenance,
            sanitize_copy,
            pick_safe_open_file,
            pick_file_security_source,
            open_software,
            set_deviation,
            get_network,
            get_network_protection,
            get_threat_protection,
            set_threat_protection_enabled,
            get_network_activity,
            get_security_center_digest,
            get_network_history,
            get_device_overview,
            get_capability_history,
            query_telemetry,
            get_related_telemetry,
            get_secure_dns,
            set_secure_dns_mode,
            set_secure_dns_provider,
            retry_secure_dns,
            network_set_rule,
            network_set_threat_exception,
            network_remove_rule,
            network_prompt_decision,
            set_network_trust_zone,
            get_applications,
            get_application_security_coverage,
            list_application_security_applications,
            get_application_security_application,
            list_application_security_resources,
            get_application_security_resource,
            list_application_security_grants,
            pick_application_security_resource,
            pick_application_security_grant,
            pick_application_security_revocation,
            pick_application_security_launch,
            start_application_security_launch,
            open_administration,
            get_administration_state,
            apply_application_security_policy,
            get_application_security_operation,
            cancel_application_security_operation,
            get_devices,
            get_recovery,
            create_recovery_point,
            cleanup_recovery_points,
            get_backup,
            configure_backup,
            backup_now,
            verify_backup,
            list_backup_files,
            restore_backup_files,
            get_evidence,
            get_privacy,
            get_filesecurity,
            export_posture,
            clear_history,
            set_privacy_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running GREYWARD Security Center");
}

#[cfg(test)]
mod posture_tests {
    use super::choose_overall_posture;
    use greyward_security_domain::PostureState;

    #[test]
    fn optional_unavailable_evidence_does_not_hide_evaluated_protection() {
        let (state, tone, message, care, values) = choose_overall_posture(
            &[PostureState::Protected, PostureState::Secure],
            0,
            1,
            false,
        );
        assert_eq!(state, "PROTECTED");
        assert_eq!(tone, "protected");
        assert_eq!(message, "overview.posture.limited.message");
        assert_eq!(care, "overview.posture.limited.care");
        assert_eq!(values.get("count").map(String::as_str), Some("1"));
    }

    #[test]
    fn required_uncertainty_still_blocks_global_protection_claim() {
        let (state, tone, message, _, _) =
            choose_overall_posture(&[PostureState::Protected, PostureState::Secure], 0, 1, true);
        assert_eq!(state, "UNAVAILABLE");
        assert_eq!(tone, "unavailable");
        assert_eq!(message, "overview.posture.unavailable.message");
    }

    #[test]
    fn unknown_domain_still_blocks_global_protection_claim() {
        let (state, _, _, _, _) = choose_overall_posture(
            &[PostureState::Unknown, PostureState::Protected],
            0,
            0,
            false,
        );
        assert_eq!(state, "UNAVAILABLE");
    }
}
