use chrono::{DateTime, Duration, Utc};
use greyward_security_domain::{
    CONTEXT_RETENTION_DAYS, MAX_CONTEXT_EVENTS, NotificationClass, PostureSnapshot, PostureState,
    SECURITY_CONTEXT_V1_SCHEMA, SecurityContextEvent, SecurityContextSummary, SecurityEventKind,
    SecurityLiveState, SecurityLiveStateKind,
};
fn bounded_text(value: &str, maximum: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(maximum)
        .collect()
}
pub fn notification_class(kind: SecurityEventKind) -> NotificationClass {
    match kind {
        SecurityEventKind::UsbDeviceBlocked => NotificationClass::ActionRequired,
        SecurityEventKind::MicrophoneStarted | SecurityEventKind::CameraStarted => {
            NotificationClass::OngoingState
        }
        SecurityEventKind::PublicIpExposed | SecurityEventKind::PublicIpProtected => {
            NotificationClass::OngoingState
        }
        SecurityEventKind::InboundAttackActivity | SecurityEventKind::AppConnectionBlocked => {
            NotificationClass::Aggregatable
        }
        _ => NotificationClass::HistoryOnly,
    }
}
pub fn retain_context_events(
    mut events: Vec<SecurityContextEvent>,
    now: DateTime<Utc>,
) -> Vec<SecurityContextEvent> {
    events.retain(|event| event.occurred_at >= now - Duration::days(CONTEXT_RETENTION_DAYS));
    for event in &mut events {
        event.event_id = bounded_text(&event.event_id, 64);
        event.title = bounded_text(&event.title, 160);
        event.detail = bounded_text(&event.detail, 320);
        event.source = bounded_text(&event.source, 96);
    }
    events.sort_by_key(|event| event.occurred_at);
    if events.len() > MAX_CONTEXT_EVENTS {
        events.split_off(events.len() - MAX_CONTEXT_EVENTS)
    } else {
        events
    }
}
pub fn context_summary(
    snapshot: &PostureSnapshot,
    events: Vec<SecurityContextEvent>,
) -> SecurityContextSummary {
    let state = aggregate_context_state(snapshot);
    let review_count = snapshot
        .domains
        .iter()
        .filter(|domain| {
            matches!(
                domain.state,
                PostureState::ReviewNeeded | PostureState::ActionRequired
            )
        })
        .count() as u32;
    let fresh_until = snapshot
        .checks
        .iter()
        .map(|check| check.fresh_until)
        .min()
        .unwrap_or(snapshot.generated_at);
    let live_states = if review_count > 0 {
        vec![SecurityLiveState {
            kind: SecurityLiveStateKind::ReviewNeeded,
            state,
            detail: "Security context needs review.".into(),
            observed_at: snapshot.generated_at,
        }]
    } else {
        vec![SecurityLiveState {
            kind: SecurityLiveStateKind::Protected,
            state,
            detail: "No actionable posture finding is currently open.".into(),
            observed_at: snapshot.generated_at,
        }]
    };
    SecurityContextSummary {
        schema: SECURITY_CONTEXT_V1_SCHEMA.into(),
        state,
        generated_at: snapshot.generated_at,
        fresh_until,
        review_count,
        live_states,
        recent_events: retain_context_events(events, Utc::now()),
        clamav: None,
        accepted_deviations: snapshot.accepted_deviations.clone(),
        privacy_profile: None,
    }
}
pub const OPENSNITCH_CONTEXT_SUMMARY_PATH: &str =
    "/run/greyward-security-context/opensnitch-summary.json";

/// Reads the already-redacted, bounded summary emitted by the privileged
/// `OpenSnitch` control plane. Consumers never decode `OpenSnitch` protobuf data.
pub fn load_opensnitch_context_summary(
    path: impl AsRef<std::path::Path>,
) -> Result<SecurityContextSummary, String> {
    let raw = std::fs::read(path).map_err(|error| error.to_string())?;
    let mut summary: SecurityContextSummary =
        serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
    if summary.schema != SECURITY_CONTEXT_V1_SCHEMA {
        return Err("unsupported Security Context schema".into());
    }
    summary.recent_events = retain_context_events(summary.recent_events, Utc::now());
    Ok(summary)
}
fn aggregate_context_state(snapshot: &PostureSnapshot) -> PostureState {
    let states: Vec<_> = snapshot.domains.iter().map(|domain| domain.state).collect();
    if states.is_empty() {
        return PostureState::Unknown;
    }
    if states.contains(&PostureState::ActionRequired) {
        return PostureState::ActionRequired;
    }
    if states.contains(&PostureState::ReviewNeeded) {
        return PostureState::ReviewNeeded;
    }
    if states.contains(&PostureState::Unknown) {
        return PostureState::Unknown;
    }
    if states
        .iter()
        .all(|state| *state == PostureState::Unavailable)
    {
        return PostureState::Unavailable;
    }
    if states.iter().all(|state| {
        matches!(
            *state,
            PostureState::Secure | PostureState::Protected | PostureState::NotApplicable
        )
    }) {
        return if states.contains(&PostureState::Protected) {
            PostureState::Protected
        } else {
            PostureState::Secure
        };
    }
    PostureState::Unknown
}
#[cfg(test)]
mod tests {
    use super::*;
    use greyward_security_domain::{Domain, DomainResult, PostureSnapshot, SNAPSHOT_V1_SCHEMA};
    fn snapshot(states: &[PostureState]) -> PostureSnapshot {
        let now = Utc::now();
        let domains = [
            Domain::System,
            Domain::Network,
            Domain::Applications,
            Domain::Devices,
        ];
        PostureSnapshot {
            schema: SNAPSHOT_V1_SCHEMA.into(),
            generated_at: now,
            boot_id: None,
            evaluator_version: "1".into(),
            policy_profile: "standard".into(),
            checks: Vec::new(),
            collection_issues: Vec::new(),
            accepted_deviations: Vec::new(),
            domains: states
                .iter()
                .enumerate()
                .map(|(index, state)| DomainResult {
                    domain: domains[index],
                    state: *state,
                    check_ids: Vec::new(),
                })
                .collect(),
        }
    }
    #[test]
    fn summary_prioritizes_actionable_state_and_serializes() {
        let summary = context_summary(
            &snapshot(&[PostureState::Unavailable, PostureState::ActionRequired]),
            Vec::new(),
        );
        assert_eq!(summary.state, PostureState::ActionRequired);
        assert!(serde_json::to_string(&summary).is_ok());
    }
    #[test]
    fn notification_policy_prevents_packet_noise() {
        for sensor in [
            SecurityEventKind::MicrophoneStarted,
            SecurityEventKind::CameraStarted,
        ] {
            assert_eq!(notification_class(sensor), NotificationClass::OngoingState);
        }
        assert_eq!(
            notification_class(SecurityEventKind::UsbDeviceBlocked),
            NotificationClass::ActionRequired
        );
        assert_eq!(
            notification_class(SecurityEventKind::AppConnectionBlocked),
            NotificationClass::Aggregatable
        );
    }
    #[test]
    fn context_retention_is_bounded_and_redacted() {
        let now = Utc::now();
        let events = (0..(MAX_CONTEXT_EVENTS + 3))
            .map(|index| SecurityContextEvent {
                event_id: format!("{index}\n"),
                kind: SecurityEventKind::PostureChanged,
                notification: NotificationClass::HistoryOnly,
                occurred_at: now,
                title: "safe\n".into(),
                detail: "safe\t".into(),
                source: "fixture".into(),
                file_ref: None,
                state: None,
                detection_name: None,
                category: None,
                scan_context: None,
            })
            .collect();
        let retained = retain_context_events(events, now);
        assert_eq!(retained.len(), MAX_CONTEXT_EVENTS);
        assert!(!retained[0].title.contains('\n'));
    }
}
