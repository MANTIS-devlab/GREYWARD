use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

use crate::{
    Applicability, ApplicabilityRule, CapabilityMaturity, CapabilityStatus, CheckId, CheckResult,
    Domain, Evidence, EvidenceKind, LocalizedMessage, PostureState, RemediationDescriptor,
    Requiredness, RuntimeAvailability, ScalarValue,
};

const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRequirement {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckDefinition {
    pub check_id: CheckId,
    pub definition_version: u32,
    pub domain: Domain,
    pub requiredness: Requiredness,
    pub maturity: CapabilityMaturity,
    pub applicability_rule: ApplicabilityRule,
    pub evidence_schema: Vec<EvidenceRequirement>,
    pub remediation: Option<RemediationDescriptor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredicateResult {
    Satisfied,
    Failed,
    ImprovementRecommended,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckObservation {
    pub runtime: RuntimeAvailability,
    pub observed_at: DateTime<Utc>,
    pub fresh_until: DateTime<Utc>,
    pub evidence: Vec<Evidence>,
    pub predicate_result: PredicateResult,
}

pub fn evaluate_applicability(
    rule: &ApplicabilityRule,
    facts: &BTreeMap<String, ScalarValue>,
) -> Applicability {
    let (applies, reason_code) = match rule {
        ApplicabilityRule::Always { reason_code } => (true, reason_code.clone()),
        ApplicabilityRule::Never { reason_code } => (false, reason_code.clone()),
        ApplicabilityRule::FactPresent { key, reason_code } => {
            (facts.contains_key(key), reason_code.clone())
        }
        ApplicabilityRule::FactEquals {
            key,
            value,
            reason_code,
        } => (facts.get(key) == Some(value), reason_code.clone()),
    };
    Applicability {
        applies,
        reason_code,
        facts: facts.clone(),
    }
}

pub fn is_fresh(
    now: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    fresh_until: DateTime<Utc>,
) -> bool {
    fresh_until >= observed_at
        && now <= fresh_until
        && observed_at <= now + Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
}

pub fn evaluate_check(
    definition: &CheckDefinition,
    facts: &BTreeMap<String, ScalarValue>,
    observation: &CheckObservation,
    now: DateTime<Utc>,
) -> CheckResult {
    let applicability = evaluate_applicability(&definition.applicability_rule, facts);
    let evidence_valid = validate_evidence(&definition.evidence_schema, &observation.evidence);

    let (state, reason_code) = if applicability.applies {
        match observation.runtime {
            RuntimeAvailability::Absent
            | RuntimeAvailability::Unsupported
            | RuntimeAvailability::VersionMismatch => {
                (PostureState::Unavailable, "capability-unavailable")
            }
            RuntimeAvailability::Denied | RuntimeAvailability::Failed => {
                (PostureState::Unknown, "collection-failed")
            }
            RuntimeAvailability::Available
                if !is_fresh(now, observation.observed_at, observation.fresh_until) =>
            {
                (PostureState::Unknown, "evidence-stale")
            }
            RuntimeAvailability::Available if !evidence_valid => {
                (PostureState::Unknown, "evidence-invalid")
            }
            RuntimeAvailability::Available => match observation.predicate_result {
                PredicateResult::Satisfied => (PostureState::Secure, "condition-satisfied"),
                PredicateResult::ImprovementRecommended => {
                    (PostureState::ReviewNeeded, "improvement-recommended")
                }
                PredicateResult::Failed => match definition.requiredness {
                    Requiredness::Required => {
                        (PostureState::ActionRequired, "required-condition-failed")
                    }
                    Requiredness::Recommended => {
                        (PostureState::ReviewNeeded, "recommended-condition-failed")
                    }
                    Requiredness::Informational => {
                        (PostureState::Protected, "informational-observation")
                    }
                },
                PredicateResult::Indeterminate => {
                    (PostureState::Unknown, "predicate-indeterminate")
                }
            },
        }
    } else {
        (PostureState::NotApplicable, "not-applicable")
    };

    CheckResult {
        check_id: definition.check_id.clone(),
        definition_version: definition.definition_version,
        domain: definition.domain,
        state,
        reason_code: reason_code.to_owned(),
        summary: message(&format!("fixture.check.{reason_code}.summary")),
        explanation: message(&format!("fixture.check.{reason_code}.explanation")),
        observed_at: observation.observed_at,
        fresh_until: observation.fresh_until,
        applicability,
        requiredness: definition.requiredness,
        capability_status: CapabilityStatus {
            maturity: definition.maturity,
            runtime: observation.runtime,
        },
        evidence: observation.evidence.clone(),
        remediation: definition.remediation.clone(),
    }
}

fn validate_evidence(schema: &[EvidenceRequirement], evidence: &[Evidence]) -> bool {
    evidence.iter().all(|item| item.kind == item.value.kind())
        && schema.iter().all(|requirement| {
            let found = evidence
                .iter()
                .find(|item| item.evidence_id == requirement.evidence_id);
            match found {
                Some(item) => item.kind == requirement.kind,
                None => !requirement.required,
            }
        })
}

pub fn aggregate_domain(checks: &[CheckResult]) -> PostureState {
    let applicable: Vec<_> = checks
        .iter()
        .filter(|check| check.state != PostureState::NotApplicable)
        .collect();

    if applicable.is_empty() {
        return PostureState::NotApplicable;
    }
    if applicable.iter().any(|check| {
        check.requiredness == Requiredness::Required && check.state == PostureState::ActionRequired
    }) {
        return PostureState::ActionRequired;
    }
    if applicable
        .iter()
        .any(|check| check.state == PostureState::ReviewNeeded)
    {
        return PostureState::ReviewNeeded;
    }
    if applicable.iter().any(|check| {
        check.requiredness == Requiredness::Required && check.state == PostureState::Unknown
    }) {
        return PostureState::Unknown;
    }

    let required_are_protected = applicable
        .iter()
        .filter(|check| check.requiredness == Requiredness::Required)
        .all(|check| matches!(check.state, PostureState::Secure | PostureState::Protected));
    let any_evaluable = applicable.iter().any(|check| {
        matches!(
            check.state,
            PostureState::Secure
                | PostureState::Protected
                | PostureState::ReviewNeeded
                | PostureState::ActionRequired
        )
    });
    if any_evaluable && required_are_protected {
        if applicable
            .iter()
            .any(|check| check.state == PostureState::Protected)
        {
            return PostureState::Protected;
        }
        return PostureState::Secure;
    }
    if applicable
        .iter()
        .all(|check| check.state == PostureState::Unavailable)
    {
        return PostureState::Unavailable;
    }
    PostureState::Unknown
}

fn message(key: &str) -> LocalizedMessage {
    LocalizedMessage {
        key: key.to_owned(),
        parameters: BTreeMap::new(),
    }
}
