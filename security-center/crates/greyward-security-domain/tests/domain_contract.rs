use std::collections::BTreeMap;

use chrono::{Duration, TimeZone, Utc};
use greyward_security_domain::{
    Applicability, ApplicabilityRule, CURRENT_EVALUATOR_VERSION, CapabilityMaturity,
    CapabilityStatus, CheckDefinition, CheckId, CheckObservation, CheckResult, Domain,
    DomainResult, Evidence, EvidenceKind, EvidenceRequirement, EvidenceSource, EvidenceValue,
    LocalizedMessage, MAX_SNAPSHOT_BYTES, PostureSnapshot, PostureState, PredicateResult,
    Provenance, Requiredness, RuntimeAvailability, SNAPSHOT_V1_SCHEMA, ScalarValue, Sensitivity,
    SnapshotError, aggregate_domain, evaluate_applicability, evaluate_check, is_fresh,
    parse_snapshot_v1,
};

fn instant() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn message(key: &str) -> LocalizedMessage {
    LocalizedMessage {
        key: key.to_owned(),
        parameters: BTreeMap::new(),
    }
}

fn result(state: PostureState, requiredness: Requiredness) -> CheckResult {
    let observed_at = instant();
    CheckResult {
        check_id: CheckId::new("fixture.contract.check"),
        definition_version: 1,
        domain: Domain::System,
        state,
        reason_code: "fixture-reason".to_owned(),
        summary: message("fixture.summary"),
        explanation: message("fixture.explanation"),
        observed_at,
        fresh_until: observed_at + Duration::minutes(5),
        applicability: Applicability {
            applies: state != PostureState::NotApplicable,
            reason_code: "fixture-applicability".to_owned(),
            facts: BTreeMap::new(),
        },
        requiredness,
        capability_status: CapabilityStatus {
            maturity: CapabilityMaturity::Verified,
            runtime: RuntimeAvailability::Available,
        },
        evidence: Vec::new(),
        remediation: None,
    }
}

fn snapshot() -> PostureSnapshot {
    let check = result(PostureState::Protected, Requiredness::Required);
    PostureSnapshot {
        schema: SNAPSHOT_V1_SCHEMA.to_owned(),
        generated_at: instant(),
        boot_id: Some("fixture-boot".to_owned()),
        evaluator_version: CURRENT_EVALUATOR_VERSION.to_owned(),
        policy_profile: "fixture".to_owned(),
        domains: vec![DomainResult {
            domain: Domain::System,
            state: PostureState::Protected,
            check_ids: vec![check.check_id.clone()],
        }],
        checks: vec![check],
        collection_issues: Vec::new(),
        accepted_deviations: Vec::new(),
    }
}

#[test]
fn posture_distinguishes_secure_from_accepted_protected() {
    assert_eq!(
        aggregate_domain(&[result(PostureState::Secure, Requiredness::Recommended)]),
        PostureState::Secure
    );
    assert_eq!(
        aggregate_domain(&[result(
            PostureState::ReviewNeeded,
            Requiredness::Recommended
        )]),
        PostureState::ReviewNeeded
    );
    assert_eq!(
        aggregate_domain(&[result(PostureState::Protected, Requiredness::Recommended)]),
        PostureState::Protected
    );
}

#[test]
fn aggregation_table_is_exhaustive_across_states_and_requiredness() {
    use PostureState::{
        ActionRequired, NotApplicable, Protected, ReviewNeeded, Secure, Unavailable, Unknown,
    };
    use Requiredness::{Informational, Recommended, Required};

    let table = [
        (Protected, Required, Protected),
        (ReviewNeeded, Required, ReviewNeeded),
        (ActionRequired, Required, ActionRequired),
        (Unknown, Required, Unknown),
        (Unavailable, Required, Unavailable),
        (NotApplicable, Required, NotApplicable),
        (Protected, Recommended, Protected),
        (ReviewNeeded, Recommended, ReviewNeeded),
        (ActionRequired, Recommended, Secure),
        (Unknown, Recommended, Unknown),
        (Unavailable, Recommended, Unavailable),
        (NotApplicable, Recommended, NotApplicable),
        (Protected, Informational, Protected),
        (ReviewNeeded, Informational, ReviewNeeded),
        (ActionRequired, Informational, Secure),
        (Unknown, Informational, Unknown),
        (Unavailable, Informational, Unavailable),
        (NotApplicable, Informational, NotApplicable),
    ];
    assert_eq!(table.len(), 6 * 3);
    for (state, requiredness, expected) in table {
        assert_eq!(
            aggregate_domain(&[result(state, requiredness)]),
            expected,
            "state={state:?}, requiredness={requiredness:?}"
        );
    }
}

#[test]
fn aggregation_applies_the_normative_precedence_and_is_order_independent() {
    let checks = vec![
        result(PostureState::Unknown, Requiredness::Required),
        result(PostureState::ReviewNeeded, Requiredness::Recommended),
        result(PostureState::ActionRequired, Requiredness::Required),
    ];
    let mut reversed = checks.clone();
    reversed.reverse();
    assert_eq!(aggregate_domain(&checks), PostureState::ActionRequired);
    assert_eq!(aggregate_domain(&checks), aggregate_domain(&reversed));
}

#[test]
fn protected_is_impossible_with_unresolved_required_evidence() {
    for state in [PostureState::Unknown, PostureState::ActionRequired] {
        let checks = [
            result(PostureState::Protected, Requiredness::Required),
            result(state, Requiredness::Required),
        ];
        assert_ne!(aggregate_domain(&checks), PostureState::Protected);
    }
}

#[test]
fn applicability_rules_are_pure_and_typed() {
    let facts = BTreeMap::from([("fixture.present".to_owned(), ScalarValue::Boolean(true))]);
    let rule = ApplicabilityRule::FactEquals {
        key: "fixture.present".to_owned(),
        value: ScalarValue::Boolean(true),
        reason_code: "fixture-match".to_owned(),
    };
    let first = evaluate_applicability(&rule, &facts);
    assert!(first.applies);
    assert_eq!(first, evaluate_applicability(&rule, &facts));
}

#[test]
fn freshness_rejects_stale_invalid_and_far_future_observations() {
    let now = instant();
    assert!(is_fresh(
        now,
        now - Duration::minutes(1),
        now + Duration::minutes(1)
    ));
    assert!(!is_fresh(
        now,
        now - Duration::minutes(2),
        now - Duration::seconds(1)
    ));
    assert!(!is_fresh(now, now, now - Duration::seconds(1)));
    assert!(!is_fresh(
        now,
        now + Duration::minutes(6),
        now + Duration::minutes(7)
    ));
}

#[test]
fn evaluator_checks_availability_freshness_schema_and_requiredness() {
    let now = instant();
    let definition = CheckDefinition {
        check_id: CheckId::new("fixture.contract.check"),
        definition_version: 1,
        domain: Domain::System,
        requiredness: Requiredness::Required,
        maturity: CapabilityMaturity::Verified,
        applicability_rule: ApplicabilityRule::Always {
            reason_code: "fixture-applies".to_owned(),
        },
        evidence_schema: vec![EvidenceRequirement {
            evidence_id: "fixture.flag".to_owned(),
            kind: EvidenceKind::Boolean,
            required: true,
        }],
        remediation: None,
    };
    let evidence = Evidence {
        evidence_id: "fixture.flag".to_owned(),
        source: EvidenceSource {
            backend_id: "fixture".to_owned(),
            interface: "fixture-api".to_owned(),
            object: "fixture-object".to_owned(),
        },
        kind: EvidenceKind::Boolean,
        value: EvidenceValue::Boolean(false),
        sensitivity: Sensitivity::Public,
        display_policy: greyward_security_domain::DisplayPolicy::Full,
        observed_at: now,
        provenance: Provenance {
            backend_version: "fixture-1".to_owned(),
            interface_version: "fixture-1".to_owned(),
        },
    };
    let observation = CheckObservation {
        runtime: RuntimeAvailability::Available,
        observed_at: now,
        fresh_until: now + Duration::minutes(1),
        evidence: vec![evidence],
        predicate_result: PredicateResult::Failed,
    };
    assert_eq!(
        evaluate_check(&definition, &BTreeMap::new(), &observation, now).state,
        PostureState::ActionRequired
    );

    let mut stale = observation.clone();
    stale.fresh_until = now - Duration::seconds(1);
    assert_eq!(
        evaluate_check(&definition, &BTreeMap::new(), &stale, now).state,
        PostureState::Unknown
    );

    let mut missing = observation;
    missing.evidence.clear();
    assert_eq!(
        evaluate_check(&definition, &BTreeMap::new(), &missing, now).state,
        PostureState::Unknown
    );
}

#[test]
fn snapshot_v1_round_trips() {
    let original = snapshot();
    let json = serde_json::to_vec(&original).unwrap();
    assert_eq!(parse_snapshot_v1(&json).unwrap(), original);
    let fixture = include_bytes!("../../../tests/fixtures/snapshot-v1.json");
    let parsed = parse_snapshot_v1(fixture).unwrap();
    assert_eq!(parsed.schema, SNAPSHOT_V1_SCHEMA);
    assert_eq!(
        serde_json::from_slice::<PostureSnapshot>(fixture).unwrap(),
        parsed
    );
}

#[test]
fn snapshot_rejects_unknown_version_enum_and_malformed_json() {
    let json = serde_json::to_string(&snapshot()).unwrap();
    let unknown_version = json.replace(SNAPSHOT_V1_SCHEMA, "greyward.security.snapshot/v2");
    assert!(matches!(
        parse_snapshot_v1(unknown_version.as_bytes()),
        Err(SnapshotError::UnsupportedSchema(_))
    ));

    let unknown_enum = json.replace("PROTECTED", "PERFECTLY_SECURE");
    assert!(matches!(
        parse_snapshot_v1(unknown_enum.as_bytes()),
        Err(SnapshotError::Malformed(_))
    ));
    assert!(matches!(
        parse_snapshot_v1(include_bytes!(
            "../../../tests/fixtures/snapshot-forward-version.json"
        )),
        Err(SnapshotError::UnsupportedSchema(_))
    ));
    assert!(matches!(
        parse_snapshot_v1(b"{not-json"),
        Err(SnapshotError::Malformed(_))
    ));
}

#[test]
fn snapshot_rejects_oversized_input_and_bounded_fields() {
    let oversized = vec![b' '; MAX_SNAPSHOT_BYTES + 1];
    assert_eq!(
        parse_snapshot_v1(&oversized),
        Err(SnapshotError::InputTooLarge)
    );

    let mut value = serde_json::to_value(snapshot()).unwrap();
    value["policy_profile"] = serde_json::Value::String("x".repeat(4_097));
    assert_eq!(
        parse_snapshot_v1(&serde_json::to_vec(&value).unwrap()),
        Err(SnapshotError::Bounds("string"))
    );
}

#[test]
fn snapshot_applies_the_explicit_v1_check_id_alias() {
    let json = serde_json::to_string(&snapshot()).unwrap();
    let legacy = json.replace("fixture.contract.check", "system.selinux");
    let migrated = parse_snapshot_v1(legacy.as_bytes()).unwrap();
    assert!(
        migrated
            .checks
            .iter()
            .all(|check| check.check_id.as_str() == "system.selinux.mode")
    );
    assert!(
        migrated.domains[0]
            .check_ids
            .iter()
            .all(|check_id| check_id.as_str() == "system.selinux.mode")
    );
}
