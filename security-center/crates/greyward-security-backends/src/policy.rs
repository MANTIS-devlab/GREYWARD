#![allow(clippy::wildcard_imports, clippy::too_many_lines)]
use crate::facts::*;
use crate::privacy::external_service_manifest;
use chrono::{Duration, Utc};
use greyward_security_domain::*;
use std::collections::BTreeMap;
use std::fs;
pub const MAX_ACCEPTED_DEVIATIONS: usize = 64;
fn accepted_deviations_path() -> Result<std::path::PathBuf, String> {
    crate::privacy::state_directory()
        .map(|dir| dir.join("accepted-deviations.json"))
        .map_err(|e| e.to_string())
}
pub fn load_accepted_deviations() -> Vec<String> {
    let Ok(path) = accepted_deviations_path() else {
        return Vec::new();
    };
    let Ok(raw) = fs::read(path) else {
        return Vec::new();
    };
    serde_json::from_slice::<Vec<String>>(&raw)
        .unwrap_or_default()
        .into_iter()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 96
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
        })
        .take(MAX_ACCEPTED_DEVIATIONS)
        .collect()
}
/// Updates the bounded list of accepted check deviations and persists it.
///
/// # Errors
///
/// Returns an error when `check_id` is invalid, the state directory cannot be
/// resolved or created, or the updated list cannot be serialized or written.
pub fn set_accepted_deviation(check_id: &str, accepted: bool) -> Result<Vec<String>, String> {
    if check_id.is_empty()
        || check_id.len() > 96
        || !check_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return Err("invalid check identifier".into());
    }
    let mut values = load_accepted_deviations();
    if accepted {
        if !values.iter().any(|id| id == check_id) {
            values.push(check_id.into());
        }
    } else {
        values.retain(|id| id != check_id);
    }
    values.sort();
    values.truncate(MAX_ACCEPTED_DEVIATIONS);
    let path = accepted_deviations_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        &path,
        serde_json::to_vec(&values).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(values)
}
pub fn evaluate_facts(facts: &[AdapterFacts]) -> PostureSnapshot {
    evaluate_facts_with_deviations(facts, &[])
}
pub fn evaluate_facts_with_deviations(
    facts: &[AdapterFacts],
    accepted_deviations: &[String],
) -> PostureSnapshot {
    let now = Utc::now();
    let fresh = now + Duration::minutes(5);
    let mut checks: Vec<CheckResult> = Vec::new();
    let mut se = SelinuxMode::Unknown;
    let mut sb = SecureBootState::Unknown;
    let mut enc = EncryptionState::Unknown;
    let mut tpm = TpmCapability::Unknown;
    let mut firmware = FirmwareFacts {
        fwupd_available: false,
        security: FirmwareSecurityState::Unknown,
        updates: FirmwareUpdateState::Unknown,
    };
    let mut updates = SecurityUpdatesFacts {
        backend: UpdateBackendState::Unknown,
        available_count: None,
    };
    let mut flatpak = FlatpakFacts {
        availability: FlatpakAvailability::Unknown,
        apps: Vec::new(),
        broad_permission_apps: 0,
    };
    let mut portal = PortalFacts {
        health: PortalHealth::Unknown,
        owner: None,
        version: None,
        documents: false,
        permission_store: false,
    };
    let mut usb = UsbFacts {
        availability: UsbGuardAvailability::Unknown,
        policy: UsbGuardPolicy::Unknown,
        connected_devices: 0,
        authorized_devices: 0,
        unknown_devices: 0,
    };
    let mut recovery = RecoveryFacts {
        readiness: RecoveryReadiness::Unknown,
        rescue_kernel: false,
        uefi: false,
        secure_boot: SecureBootState::Unknown,
        encryption: EncryptionState::Unknown,
        firmware_updates: FirmwareUpdateState::Unknown,
        tpm: TpmCapability::Unknown,
    };
    let mut network = NetworkFacts {
        active_connection: None,
        interface: None,
        connection_type: None,
        firewall: FirewallState::Unknown,
        trust_zone: TrustZone::Unknown,
    };
    for f in facts {
        match f {
            AdapterFacts::Selinux(x) => se = x.mode.clone(),
            AdapterFacts::Boot(x) => sb = x.secure_boot.clone(),
            AdapterFacts::Storage(x) => enc = x.root.clone(),
            AdapterFacts::Tpm(x) => tpm = x.capability.clone(),
            AdapterFacts::Firmware(x) => firmware = x.clone(),
            AdapterFacts::SecurityUpdates(x) => updates = x.clone(),
            AdapterFacts::Network(x) => network = x.clone(),
            AdapterFacts::Usb(x) => usb = x.clone(),
            AdapterFacts::Recovery(x) => recovery = x.clone(),
            AdapterFacts::Flatpak(x) => flatpak = x.clone(),
            AdapterFacts::Portal(x) => portal = x.clone(),
        }
    }
    let make = |id: &str,
                domain: Domain,
                requiredness: Requiredness,
                runtime: RuntimeAvailability,
                predicate: PredicateResult,
                value: EvidenceValue|
     -> CheckResult {
        let def = CheckDefinition {
            check_id: CheckId::new(id),
            definition_version: 1,
            domain,
            requiredness,
            maturity: CapabilityMaturity::Verified,
            applicability_rule: ApplicabilityRule::Always {
                reason_code: "session-7-core".into(),
            },
            evidence_schema: vec![EvidenceRequirement {
                evidence_id: id.into(),
                kind: value.kind(),
                required: true,
            }],
            remediation: None,
        };
        let obs = CheckObservation {
            runtime,
            observed_at: now,
            fresh_until: fresh,
            evidence: vec![Evidence {
                evidence_id: id.into(),
                source: EvidenceSource {
                    backend_id: "greyward-security-backends".into(),
                    interface: "typed-read-only".into(),
                    object: id.into(),
                },
                kind: value.kind(),
                value,
                sensitivity: Sensitivity::Device,
                display_policy: DisplayPolicy::SummaryOnly,
                observed_at: now,
                provenance: Provenance {
                    backend_version: "0.1".into(),
                    interface_version: "1".into(),
                },
            }],
            predicate_result: predicate,
        };
        evaluate_check(&def, &BTreeMap::new(), &obs, now)
    };
    checks.push(make(
        "system.selinux.mode",
        Domain::System,
        Requiredness::Required,
        RuntimeAvailability::Available,
        if matches!(se, SelinuxMode::Enforcing) {
            PredicateResult::Satisfied
        } else if matches!(se, SelinuxMode::Permissive | SelinuxMode::Disabled) {
            PredicateResult::Failed
        } else {
            PredicateResult::Indeterminate
        },
        EvidenceValue::Text(format!("{se:?}")),
    ));
    checks.push(make(
        "system.firmware.hsi",
        Domain::System,
        Requiredness::Recommended,
        match firmware.security {
            FirmwareSecurityState::Unavailable => RuntimeAvailability::Absent,
            FirmwareSecurityState::Unsupported => RuntimeAvailability::Unsupported,
            _ => RuntimeAvailability::Available,
        },
        match firmware.security {
            FirmwareSecurityState::Secure => PredicateResult::Satisfied,
            FirmwareSecurityState::Insecure => PredicateResult::Failed,
            _ => PredicateResult::Indeterminate,
        },
        EvidenceValue::Text(format!("{:?}", firmware.security)),
    ));
    checks.push(make(
        "system.firmware.updates",
        Domain::System,
        Requiredness::Informational,
        if firmware.fwupd_available {
            RuntimeAvailability::Available
        } else {
            RuntimeAvailability::Absent
        },
        match firmware.updates {
            FirmwareUpdateState::NoneKnown => PredicateResult::Satisfied,
            FirmwareUpdateState::Available => PredicateResult::ImprovementRecommended,
            _ => PredicateResult::Indeterminate,
        },
        EvidenceValue::Text(format!("{:?}", firmware.updates)),
    ));
    let update_value = updates
        .available_count
        .map_or(EvidenceValue::Text("unknown".into()), |n| {
            EvidenceValue::Integer(i64::from(n))
        });
    checks.push(make(
        "system.security-updates",
        Domain::System,
        Requiredness::Recommended,
        match updates.backend {
            UpdateBackendState::Operational => RuntimeAvailability::Available,
            UpdateBackendState::Unavailable => RuntimeAvailability::Absent,
            _ => RuntimeAvailability::Failed,
        },
        match updates.available_count {
            Some(0) => PredicateResult::Satisfied,
            Some(_) => PredicateResult::ImprovementRecommended,
            None => PredicateResult::Indeterminate,
        },
        update_value,
    ));
    checks.push(make(
        "applications.flatpak.posture",
        Domain::Applications,
        Requiredness::Recommended,
        match flatpak.availability {
            FlatpakAvailability::Available => RuntimeAvailability::Available,
            FlatpakAvailability::Partial | FlatpakAvailability::Error => {
                RuntimeAvailability::Failed
            }
            FlatpakAvailability::Unavailable => RuntimeAvailability::Absent,
            FlatpakAvailability::Unknown => RuntimeAvailability::Unsupported,
        },
        if matches!(flatpak.availability, FlatpakAvailability::Available) {
            PredicateResult::Satisfied
        } else {
            PredicateResult::Indeterminate
        },
        EvidenceValue::Text(format!(
            "apps={};broad-permission-apps={}",
            flatpak.apps.len(),
            flatpak.broad_permission_apps
        )),
    ));
    checks.push(make(
        "applications.portal-health",
        Domain::Applications,
        Requiredness::Recommended,
        match portal.health {
            PortalHealth::Healthy | PortalHealth::Degraded => RuntimeAvailability::Available,
            PortalHealth::Unavailable => RuntimeAvailability::Absent,
            PortalHealth::Unsupported => RuntimeAvailability::Unsupported,
            PortalHealth::ConfigurationError | PortalHealth::Unknown => RuntimeAvailability::Failed,
        },
        match portal.health {
            PortalHealth::Healthy => PredicateResult::Satisfied,
            PortalHealth::Degraded => PredicateResult::ImprovementRecommended,
            _ => PredicateResult::Indeterminate,
        },
        EvidenceValue::Text(format!(
            "health={:?};documents={};permission-store={}",
            portal.health, portal.documents, portal.permission_store
        )),
    ));
    checks.push(make(
        "network.active-connection",
        Domain::Network,
        Requiredness::Recommended,
        match network.firewall {
            FirewallState::Available => RuntimeAvailability::Available,
            FirewallState::Unavailable => RuntimeAvailability::Absent,
            _ => RuntimeAvailability::Failed,
        },
        if matches!(network.trust_zone, TrustZone::Unknown) {
            PredicateResult::Indeterminate
        } else {
            PredicateResult::Satisfied
        },
        EvidenceValue::Text(format!(
            "connection={:?};interface={:?};type={:?};zone={:?}",
            network.active_connection,
            network.interface,
            network.connection_type,
            network.trust_zone
        )),
    ));
    checks.push(make(
        "system.boot.secure-boot",
        Domain::System,
        Requiredness::Required,
        if matches!(sb, SecureBootState::Unsupported) {
            RuntimeAvailability::Unsupported
        } else {
            RuntimeAvailability::Available
        },
        if matches!(sb, SecureBootState::Enabled) {
            PredicateResult::Satisfied
        } else if matches!(sb, SecureBootState::Disabled) {
            PredicateResult::Failed
        } else {
            PredicateResult::Indeterminate
        },
        EvidenceValue::Text(format!("{sb:?}")),
    ));
    checks.push(make(
        "data.storage.root-encryption",
        Domain::Data,
        Requiredness::Recommended,
        RuntimeAvailability::Available,
        if matches!(enc, EncryptionState::Encrypted) {
            PredicateResult::Satisfied
        } else if matches!(enc, EncryptionState::Plain) {
            PredicateResult::Failed
        } else {
            PredicateResult::Indeterminate
        },
        EvidenceValue::Text(format!("{enc:?}")),
    ));
    checks.push(make(
        "devices.tpm.presence",
        Domain::Devices,
        Requiredness::Recommended,
        if matches!(tpm, TpmCapability::Missing | TpmCapability::Unusable) {
            RuntimeAvailability::Absent
        } else {
            RuntimeAvailability::Available
        },
        if matches!(tpm, TpmCapability::Available) {
            PredicateResult::Satisfied
        } else {
            PredicateResult::Indeterminate
        },
        EvidenceValue::Text(format!("{tpm:?}")),
    ));
    checks.push(make(
        "devices.usbguard.posture",
        Domain::Devices,
        Requiredness::Recommended,
        match usb.availability {
            UsbGuardAvailability::Available => RuntimeAvailability::Available,
            UsbGuardAvailability::Unavailable => RuntimeAvailability::Absent,
            UsbGuardAvailability::Error => RuntimeAvailability::Failed,
            UsbGuardAvailability::Unknown => RuntimeAvailability::Unsupported,
        },
        match usb.policy {
            UsbGuardPolicy::Running => PredicateResult::Satisfied,
            UsbGuardPolicy::Stopped | UsbGuardPolicy::Unconfigured => {
                PredicateResult::ImprovementRecommended
            }
            UsbGuardPolicy::Unknown => PredicateResult::Indeterminate,
        },
        EvidenceValue::Text(format!(
            "policy={:?};connected={};authorized={};unknown={}",
            usb.policy, usb.connected_devices, usb.authorized_devices, usb.unknown_devices
        )),
    ));
    checks.push(make(
        "recovery.readiness",
        Domain::Devices,
        Requiredness::Recommended,
        RuntimeAvailability::Available,
        match recovery.readiness {
            RecoveryReadiness::Ready => PredicateResult::Satisfied,
            RecoveryReadiness::Partial => PredicateResult::ImprovementRecommended,
            RecoveryReadiness::Unavailable | RecoveryReadiness::Error => PredicateResult::Failed,
            RecoveryReadiness::Unknown => PredicateResult::Indeterminate,
        },
        EvidenceValue::Text(format!(
            "readiness={:?};rescue-kernel={};uefi={};secure-boot={:?};encryption={:?};tpm={:?}",
            recovery.readiness,
            recovery.rescue_kernel,
            recovery.uefi,
            recovery.secure_boot,
            recovery.encryption,
            recovery.tpm
        )),
    ));
    let disclosures = external_service_manifest();
    checks.push(make(
        "privacy.transparency",
        Domain::Privacy,
        Requiredness::Recommended,
        RuntimeAvailability::Available,
        PredicateResult::Satisfied,
        EvidenceValue::Text(format!(
            "services={};local_only={}",
            disclosures.len(),
            disclosures.iter().filter(|s| s.local_only).count()
        )),
    ));
    for check in &mut checks {
        if matches!(
            check.state,
            PostureState::ReviewNeeded | PostureState::ActionRequired | PostureState::Unavailable
        ) && accepted_deviations
            .iter()
            .any(|id| id == check.check_id.as_str())
        {
            check.state = PostureState::Protected;
            check.reason_code = "accepted-deviation".into();
            check.explanation = LocalizedMessage {
                key: "posture.accepted-deviation.explanation".into(),
                parameters: BTreeMap::new(),
            };
        }
    }
    let domains = [
        Domain::System,
        Domain::Applications,
        Domain::Network,
        Domain::Data,
        Domain::Devices,
        Domain::Privacy,
    ]
    .into_iter()
    .map(|domain| {
        let ids = checks
            .iter()
            .filter(|c| c.domain == domain)
            .map(|c| c.check_id.clone())
            .collect();
        let owned: Vec<CheckResult> = checks
            .iter()
            .filter(|c| c.domain == domain)
            .cloned()
            .collect();
        DomainResult {
            domain,
            state: aggregate_domain(&owned),
            check_ids: ids,
        }
    })
    .collect();
    PostureSnapshot {
        schema: SNAPSHOT_V1_SCHEMA.into(),
        generated_at: now,
        boot_id: None,
        evaluator_version: CURRENT_EVALUATOR_VERSION.into(),
        policy_profile: "session-7-core".into(),
        domains,
        checks,
        collection_issues: Vec::new(),
        accepted_deviations: accepted_deviations.iter().take(64).cloned().collect(),
    }
}
