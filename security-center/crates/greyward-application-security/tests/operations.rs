use greyward_application_security::*;
use greyward_security_domain::*;
use std::time::{Duration, Instant};

fn reference(kind: &str, digit: &str) -> SecurityReference {
    SecurityReference::try_from(format!("{kind}_{}", digit.repeat(64))).unwrap()
}

fn owner() -> ExecutionIdentity {
    ExecutionIdentity {
        execution_ref: reference("execution", "a"),
        installation_ref: None,
        owner_uid: 1000,
        boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        pid: 42,
        start_ticks: 100,
        selinux_context: "user_u:user_r:user_t:s0".into(),
    }
}

fn preview() -> PolicyChangePreview {
    PolicyChangePreview {
        operation_ref: reference("operation", "b"),
        installation_ref: reference("installation", "c"),
        generation: ContentGeneration::try_from("d".repeat(64)).unwrap(),
        resource_refs: vec![reference("resource", "e")],
        risks: vec![
            PolicyRisk::RawCredentialAccess,
            PolicyRisk::InProcessExtensionsShareAccess,
        ],
        expected_revision: 10,
        expires_after_ms: 1000,
    }
}

#[test]
fn stale_revision_generation_and_pid_reuse_do_not_acquire_a_preview() {
    let mut operations = OperationTable::default();
    let now = Instant::now();
    let request = preview();
    let actor = owner();
    operations
        .prepare(actor.clone(), request.clone(), now)
        .unwrap();
    assert_eq!(
        operations.begin(&request.operation_ref, &actor, 11, &request.generation, now),
        Err(OperationError::StalePreview)
    );
    let generation = ContentGeneration::try_from("f".repeat(64)).unwrap();
    assert_eq!(
        operations.begin(&request.operation_ref, &actor, 10, &generation, now),
        Err(OperationError::StalePreview)
    );
    let mut reused_pid = actor.clone();
    reused_pid.start_ticks += 1;
    assert_eq!(
        operations.get(&request.operation_ref, &reused_pid),
        Err(OperationError::NotOwned)
    );
    assert_eq!(
        operations.cancel(&request.operation_ref, &reused_pid),
        Err(OperationError::NotOwned)
    );
}

#[test]
fn running_cancel_is_only_a_request_until_the_worker_stops() {
    let mut operations = OperationTable::default();
    let now = Instant::now();
    let request = preview();
    let actor = owner();
    operations
        .prepare(actor.clone(), request.clone(), now)
        .unwrap();
    operations
        .begin(&request.operation_ref, &actor, 10, &request.generation, now)
        .unwrap();
    operations.cancel(&request.operation_ref, &actor).unwrap();
    assert_eq!(
        operations
            .get(&request.operation_ref, &actor)
            .unwrap()
            .outcome,
        OperationOutcome::CancelRequested
    );
    assert!(
        operations
            .committed(&request.operation_ref, 11, now)
            .is_err()
    );
    operations.stopped(&request.operation_ref).unwrap();
    assert_eq!(
        operations
            .get(&request.operation_ref, &actor)
            .unwrap()
            .outcome,
        OperationOutcome::Cancelled
    );
}

#[test]
fn expiry_uses_a_backend_monotonic_deadline_and_worker_acknowledgement() {
    let mut operations = OperationTable::default();
    let now = Instant::now();
    let request = preview();
    let actor = owner();
    operations
        .prepare(actor.clone(), request.clone(), now)
        .unwrap();
    operations
        .begin(&request.operation_ref, &actor, 10, &request.generation, now)
        .unwrap();
    assert_eq!(
        operations.expire(now + Duration::from_secs(1)),
        vec![request.operation_ref.clone()]
    );
    assert_eq!(
        operations
            .get(&request.operation_ref, &actor)
            .unwrap()
            .outcome,
        OperationOutcome::CancelRequested
    );
    operations.stopped(&request.operation_ref).unwrap();
    let result = operations.get(&request.operation_ref, &actor).unwrap();
    assert_eq!(result.outcome, OperationOutcome::Expired);
    result.validate().unwrap();
}

#[test]
fn a_commit_is_not_success_until_readback_matches() {
    let mut operations = OperationTable::default();
    let now = Instant::now();
    let request = preview();
    let actor = owner();
    operations
        .prepare(actor.clone(), request.clone(), now)
        .unwrap();
    operations
        .begin(&request.operation_ref, &actor, 10, &request.generation, now)
        .unwrap();
    operations
        .committed(&request.operation_ref, 11, now)
        .unwrap();
    assert_eq!(
        operations
            .get(&request.operation_ref, &actor)
            .unwrap()
            .outcome,
        OperationOutcome::Verifying
    );
    assert!(operations.cancel(&request.operation_ref, &actor).is_err());
    operations
        .verified(&request.operation_ref, 12, true, now)
        .unwrap();
    let result = operations.get(&request.operation_ref, &actor).unwrap();
    assert_eq!(result.outcome, OperationOutcome::Failed);
    assert!(!result.verified_readback);
}

#[test]
fn late_real_commit_retains_its_revision_without_a_false_cancelled_result() {
    let mut operations = OperationTable::default();
    let now = Instant::now();
    let request = preview();
    let actor = owner();
    operations
        .prepare(actor.clone(), request.clone(), now)
        .unwrap();
    operations
        .begin(&request.operation_ref, &actor, 10, &request.generation, now)
        .unwrap();
    assert_eq!(
        operations.committed(&request.operation_ref, 11, now + Duration::from_secs(1)),
        Err(OperationError::Deadline)
    );
    let result = operations.get(&request.operation_ref, &actor).unwrap();
    assert_eq!(result.outcome, OperationOutcome::Failed);
    assert_eq!(result.committed_revision, Some(11));
    result.validate().unwrap();
}

#[test]
fn a_hung_verifier_expires_without_erasing_the_real_commit() {
    let mut operations = OperationTable::default();
    let now = Instant::now();
    let request = preview();
    let actor = owner();
    operations
        .prepare(actor.clone(), request.clone(), now)
        .unwrap();
    operations
        .begin(&request.operation_ref, &actor, 10, &request.generation, now)
        .unwrap();
    operations
        .committed(&request.operation_ref, 11, now)
        .unwrap();
    operations.expire(now + Duration::from_secs(1));
    let result = operations.get(&request.operation_ref, &actor).unwrap();
    assert_eq!(result.outcome, OperationOutcome::Failed);
    assert_eq!(result.committed_revision, Some(11));
    assert!(!result.verified_readback);
}

#[test]
fn descriptor_registration_is_not_an_application_grant_and_preserves_failed_commit() {
    let actor = owner();
    let now = Instant::now();
    let mut operations = OperationTable::default();
    let preview = ResourceRegistrationPreview {
        operation_ref: reference("operation", "f"),
        resource: ProtectedResource {
            resource_ref: reference("resource", "e"),
            owner_uid: actor.owner_uid,
            category: ProtectedCategory::Custom,
            label: "Synthetic directory".into(),
            coverage: ResourceCoverage::Unknown,
            policy_revision: 11,
        },
        expected_revision: 10,
        expires_after_ms: 1000,
    };
    operations
        .prepare_registration(actor.clone(), preview.clone(), now)
        .unwrap();
    let generation = ContentGeneration::try_from("d".repeat(64)).unwrap();
    assert_eq!(
        operations.begin(&preview.operation_ref, &actor, 10, &generation, now),
        Err(OperationError::StalePreview)
    );
    operations
        .begin_registration(&preview.operation_ref, &actor, 10, now)
        .unwrap();
    operations
        .committed(&preview.operation_ref, 11, now)
        .unwrap();
    operations
        .failed(
            &preview.operation_ref,
            &actor,
            OperationFailure::ReadbackFailed,
        )
        .unwrap();
    let result = operations.get(&preview.operation_ref, &actor).unwrap();
    assert_eq!(result.outcome, OperationOutcome::Failed);
    assert_eq!(result.committed_revision, Some(11));
    assert!(!result.verified_readback);
    result.validate().unwrap();
    let mut fabricated = preview;
    fabricated.resource.coverage = ResourceCoverage::Protected;
    assert!(fabricated.validate().is_err());
}
