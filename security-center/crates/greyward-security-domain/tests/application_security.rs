use greyward_security_domain::*;

#[test]
fn installed_metadata_paths_cannot_be_commands_aliases_or_unbounded_selectors() {
    assert_eq!(
        InstalledExecutablePath::try_from("/usr/bin/cat")
            .unwrap()
            .as_str(),
        "/usr/bin/cat"
    );
    for path in [
        "/usr",
        "/usr/",
        "/usr//bin/cat",
        "/usr/./bin/cat",
        "/usr/bin/../cat",
        "--eval=exec",
        "/home/user/cat",
        "/usr/bin/a\0",
        "/usr/bin/a\n",
    ] {
        assert!(InstalledExecutablePath::try_from(path).is_err());
    }
    assert!(
        InstalledExecutablePath::try_from(format!("/usr/{}", "a/".repeat(33)).as_str()).is_err()
    );
    assert!(
        InstalledExecutablePath::try_from(format!("/usr/{}", "a".repeat(4096)).as_str()).is_err()
    );
}

fn verified() -> EnforcementEvidence {
    EnforcementEvidence {
        selinux_enforcing: Some(true),
        production_policy_loaded: Some(true),
        subject_confined: Some(true),
        coverage: SessionCoverage {
            graphical_session: true,
            user_manager: true,
            direct_exec: true,
            services_and_scheduled_jobs: true,
            enrolled_remote_sessions: true,
            protected_resource_labels: true,
            deputies_and_portals: true,
        },
        policy_revision: 1,
        evidence_age_ms: Some(0),
        ..Default::default()
    }
}

#[test]
fn enforcing_unconfined_user_is_not_protected() {
    let mut evidence = verified();
    evidence.subject_confined = Some(false);
    let result = ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &evidence);
    assert_eq!(result.health, EnforcementHealth::Unavailable);
    assert!(result.effective_profile.is_none());
}

#[test]
fn missing_or_unknown_policy_cannot_claim_protection() {
    for value in [None, Some(false)] {
        let mut evidence = verified();
        evidence.production_policy_loaded = value;
        assert!(
            ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &evidence)
                .effective_profile
                .is_none()
        );
    }
}

#[test]
fn a_launcher_only_result_is_degraded() {
    let mut evidence = verified();
    evidence.coverage.direct_exec = false;
    let result = ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &evidence);
    assert_eq!(result.health, EnforcementHealth::Degraded);
    assert!(result.effective_profile.is_none());
}

#[test]
fn portal_gap_does_not_erase_verified_baseline() {
    let mut evidence = verified();
    evidence.coverage.deputies_and_portals = false;
    assert!(
        ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &evidence)
            .effective_profile
            .is_some()
    );
}

#[test]
fn trusted_requires_review_and_isolation_requires_actual_primitives() {
    let evidence = verified();
    for profile in [ProtectionProfile::Trusted, ProtectionProfile::Isolated] {
        let snapshot = ProtectionSnapshot::from_evidence(profile, &evidence);
        assert_eq!(snapshot.health, EnforcementHealth::Degraded);
        assert!(snapshot.effective_profile.is_none());
    }
}

#[test]
fn complete_protection_has_a_revision_and_coherent_wire_shape() {
    let snapshot = ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &verified());
    assert_eq!(
        snapshot.effective_profile,
        Some(ProtectionProfile::Protected)
    );
    snapshot.validate().unwrap();
    let encoded = serde_json::to_value(snapshot).unwrap();
    assert_eq!(encoded["effective_profile"], "PROTECTED");
}

#[test]
fn old_or_missing_observations_cannot_keep_a_protected_badge() {
    for age in [None, Some(APPLICATION_ENFORCEMENT_LEASE_MS + 1)] {
        let mut evidence = verified();
        evidence.evidence_age_ms = age;
        let snapshot = ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &evidence);
        assert!(snapshot.effective_profile.is_none());
        snapshot.validate().unwrap();
    }
    let mut stale_wire =
        ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &verified());
    stale_wire.evidence_age_ms = Some(APPLICATION_ENFORCEMENT_LEASE_MS + 1);
    assert!(stale_wire.validate().is_err());
}

#[test]
fn contradictory_wire_projection_is_rejected() {
    let mut snapshot = ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &verified());
    snapshot.health = EnforcementHealth::Unknown;
    assert!(snapshot.validate().is_err());
}

#[test]
fn forged_isolation_and_exception_flags_do_not_validate() {
    let mut snapshot = ProtectionSnapshot::from_evidence(ProtectionProfile::Protected, &verified());
    for profile in [ProtectionProfile::Isolated, ProtectionProfile::Trusted] {
        snapshot.requested_profile = profile;
        snapshot.effective_profile = Some(profile);
        assert!(snapshot.validate().is_err());
    }
}

#[test]
fn process_identity_requires_pid_start_time_and_boot_generation() {
    let mut execution = ExecutionIdentity {
        execution_ref: SecurityReference::try_from(format!("execution_{}", "a".repeat(64)))
            .unwrap(),
        installation_ref: None,
        owner_uid: 1000,
        boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        pid: 42,
        start_ticks: 100,
        selinux_context: "user_u:user_r:user_t:s0".into(),
    };
    execution.validate().unwrap();
    execution.start_ticks = 0;
    assert!(execution.validate().is_err());
    execution.start_ticks = 100;
    execution.boot_id = "different-boot".into();
    assert!(execution.validate().is_err());
}

#[test]
fn opaque_references_reject_paths_and_wrong_namespaces() {
    assert!(SecurityReference::try_from(format!("launch_{}", "a".repeat(64))).is_ok());
    for reference in [
        "../../root",
        "application_short",
        "application_/etc/passwd",
        "shell_0123",
    ] {
        assert!(SecurityReference::try_from(reference.to_string()).is_err());
    }
    let resource = SecurityReference::try_from(format!("resource_{}", "a".repeat(64))).unwrap();
    let identity = ApplicationIdentity {
        display_name: None,
        application_ref: resource.clone(),
        installation_ref: resource,
        generation: ContentGeneration::try_from("b".repeat(64)).unwrap(),
        provider: ApplicationProvider::Manual,
        owner_uid: 1000,
        provenance: ProvenanceSnapshot::default(),
    };
    assert!(identity.validate().is_err());
}

fn reference(namespace: &str, digit: &str) -> SecurityReference {
    SecurityReference::try_from(format!("{namespace}_{}", digit.repeat(64))).unwrap()
}

#[test]
fn partial_permission_reads_are_not_empty_safe_permissions() {
    let mut permission = PermissionSnapshot {
        capability: PermissionCapability::Filesystem,
        resource_ref: None,
        decision: PermissionDecision::Denied,
        provider: ApplicationProvider::Flatpak,
        sources: vec![PermissionLayer::UserApplication],
        health: EnforcementHealth::Degraded,
        policy_revision: 1,
    };
    assert!(permission.validate().is_err());
    permission.decision = PermissionDecision::Unknown;
    permission.validate().unwrap();
}

#[test]
fn grants_require_explicit_resources_and_a_generation_bound_lifetime() {
    let mut grant = AccessGrant {
        grant_ref: reference("grant", "a"),
        owner_uid: 1000,
        installation_ref: reference("installation", "b"),
        generation: ContentGeneration::try_from("c".repeat(64)).unwrap(),
        resources: vec![reference("resource", "d")],
        access: vec![ResourceAccess::Read],
        lifetime: GrantLifetime::ThisRun {
            execution_ref: reference("execution", "e"),
        },
        policy_revision: 1,
    };
    grant.validate().unwrap();
    grant.resources.push(grant.resources[0].clone());
    assert!(grant.validate().is_err());
    grant.resources.clear();
    assert!(grant.validate().is_err());
}

#[test]
fn operation_completion_requires_authoritative_readback() {
    let mut result = OperationResult {
        operation_ref: reference("operation", "a"),
        outcome: OperationOutcome::Completed,
        committed_revision: Some(1),
        verified_readback: false,
        failure: None,
    };
    assert!(result.validate().is_err());
    result.verified_readback = true;
    result.validate().unwrap();
    result.outcome = OperationOutcome::CancelRequested;
    assert!(result.validate().is_err());
}

#[test]
fn signed_provenance_requires_a_receipt_and_does_not_establish_protection() {
    let mut identity = ApplicationIdentity {
        display_name: None,
        application_ref: reference("application", "a"),
        installation_ref: reference("installation", "b"),
        generation: ContentGeneration::try_from("c".repeat(64)).unwrap(),
        provider: ApplicationProvider::Rpm,
        owner_uid: 1000,
        provenance: ProvenanceSnapshot {
            state: ProvenanceState::Verified,
            source_receipt: None,
        },
    };
    assert!(identity.validate().is_err());
    identity.provenance.source_receipt = Some(ContentGeneration::try_from("d".repeat(64)).unwrap());
    identity.validate().unwrap();
    assert!(
        ProtectionSnapshot::from_evidence(
            ProtectionProfile::Protected,
            &EnforcementEvidence::default()
        )
        .effective_profile
        .is_none()
    );
}
