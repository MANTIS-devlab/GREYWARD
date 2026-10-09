//! Shared posture projection for the GUI and fixed read-only helper.
use greyward_security_domain::{PostureSnapshot, PostureState, Requiredness};
use std::collections::BTreeMap;

pub fn choose_overall_posture(
    domain_states: &[PostureState],
    review_needed: usize,
    unavailable_checks: usize,
    required_uncertain: bool,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    BTreeMap<String, String>,
) {
    if domain_states.contains(&PostureState::ActionRequired) {
        return (
            "REVIEW NEEDED",
            "action",
            "overview.posture.action.message",
            "overview.posture.action.care",
            BTreeMap::new(),
        );
    }
    if review_needed > 0 {
        let mut copy_values = BTreeMap::new();
        copy_values.insert("count".into(), review_needed.to_string());
        return (
            "REVIEW NEEDED",
            "review",
            "overview.posture.review.message",
            "overview.posture.review.care",
            copy_values,
        );
    }

    let has_unknown_domain = domain_states.contains(&PostureState::Unknown);
    let has_evaluated_domain = domain_states
        .iter()
        .any(|state| matches!(state, PostureState::Secure | PostureState::Protected));
    if required_uncertain || has_unknown_domain || !has_evaluated_domain {
        return (
            "UNAVAILABLE",
            "unavailable",
            "overview.posture.unavailable.message",
            "overview.posture.unavailable.care",
            BTreeMap::new(),
        );
    }

    let state = if domain_states.contains(&PostureState::Protected) {
        "PROTECTED"
    } else {
        "SECURE"
    };
    if unavailable_checks > 0 {
        let mut copy_values = BTreeMap::new();
        copy_values.insert("count".into(), unavailable_checks.to_string());
        return (
            state,
            if state == "PROTECTED" {
                "protected"
            } else {
                "secure"
            },
            "overview.posture.limited.message",
            "overview.posture.limited.care",
            copy_values,
        );
    }
    if state == "PROTECTED" {
        (
            state,
            "protected",
            "overview.posture.protected.message",
            "overview.posture.protected.care",
            BTreeMap::new(),
        )
    } else {
        (
            state,
            "secure",
            "overview.posture.secure.message",
            "overview.posture.secure.care",
            BTreeMap::new(),
        )
    }
}
pub fn posture_digest(snapshot: &PostureSnapshot) -> serde_json::Value {
    let review = snapshot
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
                    PostureState::Unknown | PostureState::Unavailable
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
    let states: Vec<_> = snapshot.domains.iter().map(|domain| domain.state).collect();
    let (state, _, _, _, _) =
        choose_overall_posture(&states, review, unavailable, required_uncertain);
    let checks: Vec<_> = snapshot
        .checks
        .iter()
        .map(|check| {
            serde_json::json!({
                "check_id": check.check_id.as_str(), "state": check.state,
                "accepted_deviation": check.reason_code == "accepted-deviation",
                "requiredness": check.requiredness,
            })
        })
        .collect();
    serde_json::json!({"schema": "greyward.security.posture/v1", "posture": {"state": state, "evaluated_at": snapshot.generated_at.to_rfc3339()}, "metrics": {"review_needed": review, "unavailable": unavailable}, "checks": checks})
}
