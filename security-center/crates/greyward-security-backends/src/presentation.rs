//! Product-facing evidence descriptors.
//!
//! The evaluator owns the relationship between a factual check and the
//! product concept it represents.  Presentation code receives semantic copy
//! keys and bounded interpolation values, not an internal check identifier or
//! backend evidence string to reinterpret.

use std::collections::BTreeMap;

use greyward_security_domain::{CheckResult, Domain, EvidenceValue};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidencePresentation {
    pub domain_key: &'static str,
    pub title_key: &'static str,
    pub summary_key: &'static str,
    pub recorded_result_key: &'static str,
    pub recommendation_key: &'static str,
    pub values: BTreeMap<String, String>,
    pub remediation: Option<EvidenceRemediation>,
    pub no_remediation_key: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRemediation {
    pub route: &'static str,
    pub action_key: &'static str,
}

// Keep the centralized presentation mapping together; a separate
// maintainability refactor is outside this CI-hygiene change.
#[allow(clippy::too_many_lines)]
pub fn evidence_presentation(
    check: &CheckResult,
    accepted_deviations: &[String],
) -> EvidencePresentation {
    let evidence = evidence_text(check);
    let lower = evidence.to_ascii_lowercase();
    let domain_key = evidence_domain_key(check.domain);
    let no_direct = || EvidencePresentation {
        domain_key,
        title_key: "evidence.finding.generic.title",
        summary_key: "evidence.finding.generic.summary",
        recorded_result_key: recorded_result_key(check),
        recommendation_key: "evidence.finding.generic.recommendation",
        values: BTreeMap::new(),
        remediation: None,
        no_remediation_key: Some("evidence.remediation.noDirect"),
    };
    match check.check_id.as_str() {
        "system.selinux.mode" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.selinux.title",
            summary_key: if lower.contains("enforcing") {
                "evidence.finding.selinux.enforcing"
            } else {
                "evidence.finding.selinux.review"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.selinux.recommendation",
            values: BTreeMap::new(),
            remediation: None,
            no_remediation_key: Some("evidence.remediation.noDirect"),
        },
        "system.firmware.hsi" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.firmwareSecurity.title",
            summary_key: if lower.contains("secure") {
                "evidence.finding.firmwareSecurity.secure"
            } else if lower.contains("unavailable") || lower.contains("unsupported") {
                "evidence.finding.firmwareSecurity.unavailable"
            } else {
                "evidence.finding.firmwareSecurity.review"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.firmwareSecurity.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "updates",
                action_key: "system.checks.openUpdates",
            }),
            no_remediation_key: None,
        },
        "system.firmware.updates" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.firmwareUpdates.title",
            summary_key: if lower.contains("available") {
                "evidence.finding.firmwareUpdates.available"
            } else if lower.contains("noneknown") || lower.contains("none_known") {
                "evidence.finding.firmwareUpdates.none"
            } else {
                "evidence.finding.firmwareUpdates.review"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.firmwareUpdates.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "updates",
                action_key: "system.checks.openUpdates",
            }),
            no_remediation_key: None,
        },
        "system.security-updates" => {
            let count = evidence.parse::<i64>().ok();
            let mut values = BTreeMap::new();
            if let Some(count) = count {
                values.insert("count".into(), count.to_string());
            }
            EvidencePresentation {
                domain_key,
                title_key: "evidence.finding.securityUpdates.title",
                summary_key: match count {
                    Some(0) => "evidence.finding.securityUpdates.none",
                    Some(_) => "evidence.finding.securityUpdates.available",
                    None => "evidence.finding.securityUpdates.unavailable",
                },
                recorded_result_key: recorded_result_key(check),
                recommendation_key: "evidence.finding.securityUpdates.recommendation",
                values,
                remediation: Some(EvidenceRemediation {
                    route: "updates",
                    action_key: "system.checks.openUpdates",
                }),
                no_remediation_key: None,
            }
        }
        "applications.flatpak.posture" => {
            let mut values = BTreeMap::new();
            values.insert("count".into(), "0".into());
            values.insert("review_count".into(), "0".into());
            if let Some(value) = evidence_field(&evidence, "apps") {
                values.insert("count".into(), value.into());
            }
            if let Some(value) = evidence_field(&evidence, "broad-permission-apps") {
                values.insert("review_count".into(), value.into());
            }
            EvidencePresentation {
                domain_key,
                title_key: "evidence.finding.applicationIsolation.title",
                summary_key: if lower.contains("apps=") {
                    "evidence.finding.applicationIsolation.summary"
                } else {
                    "evidence.finding.applicationIsolation.unavailable"
                },
                recorded_result_key: recorded_result_key(check),
                recommendation_key: "evidence.finding.applicationIsolation.recommendation",
                values,
                remediation: Some(EvidenceRemediation {
                    route: "applications",
                    action_key: "system.checks.openApplications",
                }),
                no_remediation_key: None,
            }
        }
        "applications.portal-health" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.applicationPortals.title",
            summary_key: if lower.contains("health=healthy") {
                "evidence.finding.applicationPortals.healthy"
            } else {
                "evidence.finding.applicationPortals.review"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.applicationPortals.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "applications",
                action_key: "system.checks.openApplications",
            }),
            no_remediation_key: None,
        },
        "network.active-connection" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.networkBoundary.title",
            summary_key: if lower.contains("zone=unknown") {
                "evidence.finding.networkBoundary.unavailable"
            } else {
                "evidence.finding.networkBoundary.available"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.networkBoundary.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "network",
                action_key: "evidence.remediation.openNetwork",
            }),
            no_remediation_key: None,
        },
        "system.boot.secure-boot" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.secureBoot.title",
            summary_key: if lower.contains("enabled") {
                "evidence.finding.secureBoot.enabled"
            } else if lower.contains("disabled") {
                "evidence.finding.secureBoot.disabled"
            } else {
                "evidence.finding.secureBoot.unavailable"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.secureBoot.recommendation",
            values: BTreeMap::new(),
            remediation: None,
            no_remediation_key: Some("evidence.remediation.noDirect"),
        },
        "data.storage.root-encryption" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.encryption.title",
            summary_key: if lower.contains("encrypted") && !lower.contains("not") {
                "evidence.finding.encryption.enabled"
            } else if lower.contains("plain") {
                "evidence.finding.encryption.disabled"
            } else {
                "evidence.finding.encryption.unavailable"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.encryption.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "privacy",
                action_key: "system.checks.openPrivacy",
            }),
            no_remediation_key: None,
        },
        "devices.tpm.presence" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.tpm.title",
            summary_key: if lower.contains("available") {
                "evidence.finding.tpm.available"
            } else {
                "evidence.finding.tpm.unavailable"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.tpm.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "devices",
                action_key: "system.checks.openRecovery",
            }),
            no_remediation_key: None,
        },
        "devices.usbguard.posture" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.usbGuard.title",
            summary_key: if lower.contains("policy=running") {
                "evidence.finding.usbGuard.running"
            } else {
                "evidence.finding.usbGuard.review"
            },
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.usbGuard.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "devices",
                action_key: "system.checks.openRecovery",
            }),
            no_remediation_key: None,
        },
        "recovery.readiness" => {
            let missing = recovery_missing(&lower, accepted_deviations);
            let mut values = BTreeMap::new();
            if !missing.is_empty() {
                values.insert("missing".into(), missing.join("|"));
            }
            EvidencePresentation {
                domain_key,
                title_key: "evidence.finding.recovery.title",
                summary_key: if check.reason_code == "accepted-deviation" {
                    "evidence.finding.recovery.accepted"
                } else if lower.contains("readiness=ready") {
                    "evidence.finding.recovery.ready"
                } else if lower.contains("readiness=partial") && !missing.is_empty() {
                    "evidence.finding.recovery.partialWithMissing"
                } else if lower.contains("readiness=partial") {
                    "evidence.finding.recovery.partial"
                } else {
                    "evidence.finding.recovery.unavailable"
                },
                recorded_result_key: recorded_result_key(check),
                recommendation_key: "evidence.finding.recovery.recommendation",
                values,
                remediation: Some(EvidenceRemediation {
                    route: "devices",
                    action_key: "system.checks.openRecovery",
                }),
                no_remediation_key: None,
            }
        }
        "privacy.transparency" => EvidencePresentation {
            domain_key,
            title_key: "evidence.finding.privacy.title",
            summary_key: "evidence.finding.privacy.summary",
            recorded_result_key: recorded_result_key(check),
            recommendation_key: "evidence.finding.privacy.recommendation",
            values: BTreeMap::new(),
            remediation: Some(EvidenceRemediation {
                route: "privacy",
                action_key: "system.checks.openPrivacy",
            }),
            no_remediation_key: None,
        },
        _ => no_direct(),
    }
}

pub fn evidence_domain_key(domain: Domain) -> &'static str {
    match domain {
        Domain::System => "evidence.domain.system",
        Domain::Applications => "evidence.domain.applications",
        Domain::Network => "evidence.domain.network",
        Domain::Data => "evidence.domain.data",
        Domain::Devices => "evidence.domain.devices",
        Domain::Privacy => "evidence.domain.privacy",
    }
}

pub fn evidence_domain_route(domain: Domain) -> &'static str {
    match domain {
        Domain::Network => "network",
        Domain::Applications => "applications",
        Domain::Devices => "devices",
        Domain::Privacy | Domain::Data => "privacy",
        Domain::System => "evidence",
    }
}

fn recorded_result_key(check: &CheckResult) -> &'static str {
    if check.reason_code == "accepted-deviation" {
        return "evidence.recorded.accepted";
    }
    match check.state {
        greyward_security_domain::PostureState::Secure
        | greyward_security_domain::PostureState::Protected => "evidence.recorded.meets",
        greyward_security_domain::PostureState::ReviewNeeded
        | greyward_security_domain::PostureState::ActionRequired => "evidence.recorded.followUp",
        greyward_security_domain::PostureState::Unavailable
        | greyward_security_domain::PostureState::Unknown => "evidence.recorded.unavailable",
        greyward_security_domain::PostureState::NotApplicable => "evidence.recorded.notApplicable",
    }
}

fn evidence_text(check: &CheckResult) -> String {
    check
        .evidence
        .iter()
        .find_map(|evidence| match &evidence.value {
            EvidenceValue::Boolean(value) => Some(value.to_string()),
            EvidenceValue::Integer(value) => Some(value.to_string()),
            EvidenceValue::Text(value) => Some(value.clone()),
            EvidenceValue::Object(_) => None,
        })
        .unwrap_or_default()
}

fn evidence_field<'a>(evidence: &'a str, key: &str) -> Option<&'a str> {
    evidence.split(';').find_map(|part| {
        let (field, value) = part.split_once('=')?;
        (field == key).then_some(value)
    })
}

fn recovery_missing(evidence: &str, accepted_deviations: &[String]) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if evidence.contains("rescue-kernel=false") {
        missing.push("evidence.recovery.missing.rescueKernel");
    }
    if evidence.contains("uefi=false") {
        missing.push("evidence.recovery.missing.uefi");
    }
    if evidence.contains("secure-boot=disabled")
        && !accepted_deviations
            .iter()
            .any(|id| id == "system.boot.secure-boot")
    {
        missing.push("evidence.recovery.missing.secureBoot");
    }
    if evidence.contains("encryption=plain") {
        missing.push("evidence.recovery.missing.encryption");
    }
    if (evidence.contains("tpm=missing") || evidence.contains("tpm=unusable"))
        && !accepted_deviations
            .iter()
            .any(|id| id == "devices.tpm.presence" || id == "recovery.readiness")
    {
        missing.push("evidence.recovery.missing.tpm");
    }
    missing
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use greyward_security_domain::{
        Applicability, CapabilityMaturity, CapabilityStatus, CheckId, Evidence, EvidenceSource,
        LocalizedMessage, PostureState, Requiredness, RuntimeAvailability, Sensitivity,
    };

    use super::*;

    fn check(id: &str, domain: Domain, evidence: &str) -> CheckResult {
        let now = Utc::now();
        CheckResult {
            check_id: CheckId::new(id),
            definition_version: 1,
            domain,
            state: PostureState::ReviewNeeded,
            reason_code: "predicate-failed".into(),
            summary: LocalizedMessage {
                key: "fixture.summary".into(),
                parameters: BTreeMap::new(),
            },
            explanation: LocalizedMessage {
                key: "fixture.explanation".into(),
                parameters: BTreeMap::new(),
            },
            observed_at: now,
            fresh_until: now + Duration::minutes(5),
            applicability: Applicability {
                applies: true,
                reason_code: "fixture".into(),
                facts: BTreeMap::new(),
            },
            requiredness: Requiredness::Recommended,
            capability_status: CapabilityStatus {
                maturity: CapabilityMaturity::Verified,
                runtime: RuntimeAvailability::Available,
            },
            evidence: vec![Evidence {
                evidence_id: id.into(),
                source: EvidenceSource {
                    backend_id: "fixture".into(),
                    interface: "test".into(),
                    object: id.into(),
                },
                kind: greyward_security_domain::EvidenceKind::Text,
                value: EvidenceValue::Text(evidence.into()),
                sensitivity: Sensitivity::Device,
                display_policy: greyward_security_domain::DisplayPolicy::SummaryOnly,
                observed_at: now,
                provenance: greyward_security_domain::Provenance {
                    backend_version: "test".into(),
                    interface_version: "1".into(),
                },
            }],
            remediation: None,
        }
    }

    #[test]
    fn update_presentation_carries_count_and_remediation() {
        let value =
            evidence_presentation(&check("system.security-updates", Domain::System, "3"), &[]);
        assert_eq!(value.title_key, "evidence.finding.securityUpdates.title");
        assert_eq!(value.values.get("count"), Some(&"3".to_string()));
        assert_eq!(value.remediation.unwrap().route, "updates");
    }

    #[test]
    fn recovery_presentation_omits_an_accepted_secure_boot_deviation() {
        let value = evidence_presentation(
            &check(
                "recovery.readiness",
                Domain::Devices,
                "readiness=Partial;secure-boot=Disabled;encryption=Plain",
            ),
            &["system.boot.secure-boot".into()],
        );
        assert_eq!(
            value.values.get("missing"),
            Some(&"evidence.recovery.missing.encryption".to_string())
        );
    }

    #[test]
    fn recovery_presentation_omits_an_ignored_tpm_recommendation() {
        let value = evidence_presentation(
            &check(
                "recovery.readiness",
                Domain::Devices,
                "readiness=Partial;secure-boot=Enabled;encryption=Encrypted;tpm=Missing",
            ),
            &["devices.tpm.presence".into()],
        );
        assert!(!value.values.contains_key("missing"));
    }
}
