use greyward_application_security::*;
use greyward_security_domain::*;

fn reference(namespace: &str, seed: &str) -> SecurityReference {
    SecurityReference::try_from(format!(
        "{namespace}_{}",
        content_generation(seed.as_bytes()).as_str()
    ))
    .unwrap()
}

fn application(uid: u32, source: &str, code: &str) -> ApplicationIdentity {
    IdentitySeed {
        provider: ApplicationProvider::Manual,
        logical_id: "tool".into(),
        installation_id: "managed".into(),
        source_id: source.into(),
        owner_uid: uid,
    }
    .identity(content_generation(code.as_bytes()))
    .unwrap()
}

fn resource(uid: u32, name: &str) -> ProtectedResource {
    ProtectedResource {
        resource_ref: reference("resource", name),
        owner_uid: uid,
        category: ProtectedCategory::Credentials,
        label: "Synthetic credentials".into(),
        coverage: ResourceCoverage::Unknown,
        policy_revision: 1,
    }
}

fn grant(app: &ApplicationIdentity, resource: &ProtectedResource) -> AccessGrant {
    AccessGrant {
        grant_ref: reference("grant", "review"),
        owner_uid: app.owner_uid,
        installation_ref: app.installation_ref.clone(),
        generation: app.generation.clone(),
        resources: vec![resource.resource_ref.clone()],
        access: vec![ResourceAccess::Read],
        lifetime: GrantLifetime::Persistent,
        policy_revision: 1,
    }
}

fn execution(app: &ApplicationIdentity) -> ExecutionIdentity {
    ExecutionIdentity {
        execution_ref: reference("execution", "run"),
        installation_ref: Some(app.installation_ref.clone()),
        owner_uid: app.owner_uid,
        boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        pid: 2000,
        start_ticks: 100,
        selinux_context: "test_u:test_r:test_t:s0".into(),
    }
}

#[test]
fn ordinary_rules_default_to_deny_and_candidates_are_access_and_resource_scoped() {
    let app = application(1002, "reviewed", "one");
    let secret = resource(1002, "ssh");
    let other = resource(1002, "cloud");
    let review = grant(&app, &secret);
    let index = PolicyIndex::prepare(
        2,
        vec![app.clone()],
        vec![secret.clone(), other.clone()],
        vec![review.clone()],
        vec![],
    )
    .unwrap();
    assert_eq!(
        index
            .resource_rule(2, &app, None, &secret.resource_ref, ResourceAccess::Read)
            .unwrap(),
        ResourceRule::ReviewedCandidate(&review.grant_ref)
    );
    assert_eq!(
        index
            .resource_rule(2, &app, None, &secret.resource_ref, ResourceAccess::Write)
            .unwrap(),
        ResourceRule::DenyUnlessReviewed
    );
    assert_eq!(
        index
            .resource_rule(2, &app, None, &other.resource_ref, ResourceAccess::Read)
            .unwrap(),
        ResourceRule::DenyUnlessReviewed
    );
    assert_eq!(secret.coverage, ResourceCoverage::Unknown);
}

#[test]
fn unsigned_generation_changes_suspend_old_grants_without_transferring_them() {
    let old = application(1002, "reviewed", "one");
    let new = application(1002, "reviewed", "two");
    let secret = resource(1002, "ssh");
    let review = grant(&old, &secret);
    let index = PolicyIndex::prepare(
        2,
        vec![new.clone()],
        vec![secret.clone()],
        vec![review.clone()],
        vec![],
    )
    .unwrap();
    assert_eq!(
        index.stale_grants().collect::<Vec<_>>(),
        vec![&review.grant_ref]
    );
    for app in [&old, &new] {
        assert_eq!(
            index
                .resource_rule(2, app, None, &secret.resource_ref, ResourceAccess::Read)
                .unwrap(),
            ResourceRule::DenyUnlessReviewed
        );
    }
}

#[test]
fn same_names_and_contents_cannot_transfer_a_review_across_sources_or_owners() {
    let app = application(1002, "approved", "one");
    let other = application(1002, "different", "one");
    let secret = resource(1002, "ssh");
    let index = PolicyIndex::prepare(
        2,
        vec![app.clone(), other.clone()],
        vec![secret.clone()],
        vec![grant(&app, &secret)],
        vec![],
    )
    .unwrap();
    assert_eq!(
        index
            .resource_rule(2, &other, None, &secret.resource_ref, ResourceAccess::Read)
            .unwrap(),
        ResourceRule::DenyUnlessReviewed
    );
    assert_eq!(
        index.resource_rule(
            2,
            &application(1003, "approved", "one"),
            None,
            &secret.resource_ref,
            ResourceAccess::Read
        ),
        Err(PolicyError::UnknownResource)
    );
    let mut forged = app;
    forged.provenance.state = ProvenanceState::Unverified;
    assert_eq!(
        index
            .resource_rule(2, &forged, None, &secret.resource_ref, ResourceAccess::Read)
            .unwrap(),
        ResourceRule::DenyUnlessReviewed
    );
}

#[test]
fn this_run_requires_the_exact_root_record_including_pid_start_boot_and_context() {
    let app = application(1002, "approved", "one");
    let secret = resource(1002, "ssh");
    let run = execution(&app);
    let mut review = grant(&app, &secret);
    review.lifetime = GrantLifetime::ThisRun {
        execution_ref: run.execution_ref.clone(),
    };
    let index = PolicyIndex::prepare(
        2,
        vec![app.clone()],
        vec![secret.clone()],
        vec![review.clone()],
        vec![RunPolicyMembership {
            execution: run.clone(),
            generation: app.generation.clone(),
        }],
    )
    .unwrap();
    assert_eq!(
        index
            .resource_rule(
                2,
                &app,
                Some(&run),
                &secret.resource_ref,
                ResourceAccess::Read
            )
            .unwrap(),
        ResourceRule::ReviewedCandidate(&review.grant_ref)
    );
    let mut variants = vec![];
    let mut changed = run.clone();
    changed.start_ticks += 1;
    variants.push(changed);
    let mut changed = run.clone();
    changed.pid += 1;
    variants.push(changed);
    let mut changed = run.clone();
    changed.boot_id.replace_range(0..1, "a");
    variants.push(changed);
    let mut changed = run.clone();
    changed.selinux_context = "test_u:test_r:other_t:s0".into();
    variants.push(changed);
    let mut changed = run.clone();
    changed.owner_uid += 1;
    variants.push(changed);
    let mut changed = run;
    changed.installation_ref = None;
    variants.push(changed);
    for changed in &variants {
        assert_eq!(
            index
                .resource_rule(
                    2,
                    &app,
                    Some(changed),
                    &secret.resource_ref,
                    ResourceAccess::Read
                )
                .unwrap(),
            ResourceRule::DenyUnlessReviewed
        );
    }
    assert_eq!(
        index
            .resource_rule(2, &app, None, &secret.resource_ref, ResourceAccess::Read)
            .unwrap(),
        ResourceRule::DenyUnlessReviewed
    );
}

#[test]
fn removed_membership_or_revoked_grant_does_not_survive_rebuilt_revision() {
    let app = application(1002, "approved", "one");
    let secret = resource(1002, "ssh");
    let run = execution(&app);
    let mut review = grant(&app, &secret);
    review.lifetime = GrantLifetime::ThisRun {
        execution_ref: run.execution_ref.clone(),
    };
    for grants in [vec![review], vec![]] {
        let index =
            PolicyIndex::prepare(3, vec![app.clone()], vec![secret.clone()], grants, vec![])
                .unwrap();
        assert_eq!(
            index
                .resource_rule(
                    3,
                    &app,
                    Some(&run),
                    &secret.resource_ref,
                    ResourceAccess::Read
                )
                .unwrap(),
            ResourceRule::DenyUnlessReviewed
        );
        assert_eq!(
            index.resource_rule(
                2,
                &app,
                Some(&run),
                &secret.resource_ref,
                ResourceAccess::Read
            ),
            Err(PolicyError::Revision)
        );
    }
}

#[test]
fn foreign_missing_future_and_duplicate_policy_records_fail_preparation() {
    let app = application(1002, "approved", "one");
    let secret = resource(1002, "ssh");
    let review = grant(&app, &secret);
    assert!(matches!(
        PolicyIndex::prepare(
            2,
            vec![app.clone()],
            vec![resource(1003, "ssh")],
            vec![review.clone()],
            vec![]
        ),
        Err(PolicyError::ForeignObject)
    ));
    assert!(matches!(
        PolicyIndex::prepare(2, vec![app.clone()], vec![], vec![review.clone()], vec![]),
        Err(PolicyError::ForeignObject)
    ));
    assert!(matches!(
        PolicyIndex::prepare(
            2,
            vec![app.clone()],
            vec![secret.clone()],
            vec![review.clone(), review.clone()],
            vec![]
        ),
        Err(PolicyError::Duplicate)
    ));
    let mut future = review;
    future.policy_revision = 3;
    assert!(matches!(
        PolicyIndex::prepare(
            2,
            vec![app.clone()],
            vec![secret.clone()],
            vec![future],
            vec![]
        ),
        Err(PolicyError::Revision)
    ));
    assert!(matches!(
        PolicyIndex::prepare(2, vec![app.clone(), app], vec![secret], vec![], vec![]),
        Err(PolicyError::Duplicate)
    ));
}

#[test]
fn one_installation_cannot_create_an_unbounded_launch_lookup() {
    let app = application(1002, "approved", "one");
    let secret = resource(1002, "ssh");
    let grants = (0..33)
        .map(|index| {
            let mut review = grant(&app, &secret);
            review.grant_ref = reference("grant", &index.to_string());
            review
        })
        .collect();
    assert!(matches!(
        PolicyIndex::prepare(2, vec![app], vec![secret], grants, vec![]),
        Err(PolicyError::Capacity)
    ));
}

#[test]
fn an_old_running_generation_cannot_use_a_new_generation_run_grant() {
    let old = application(1002, "approved", "one");
    let new = application(1002, "approved", "two");
    let secret = resource(1002, "ssh");
    let run = execution(&old);
    let mut review = grant(&new, &secret);
    review.lifetime = GrantLifetime::ThisRun {
        execution_ref: run.execution_ref.clone(),
    };
    let index = PolicyIndex::prepare(
        2,
        vec![new.clone()],
        vec![secret.clone()],
        vec![review],
        vec![RunPolicyMembership {
            execution: run.clone(),
            generation: old.generation,
        }],
    )
    .unwrap();
    assert_eq!(
        index
            .resource_rule(
                2,
                &new,
                Some(&run),
                &secret.resource_ref,
                ResourceAccess::Read
            )
            .unwrap(),
        ResourceRule::DenyUnlessReviewed
    );
}

#[test]
fn persistent_reviews_do_not_transfer_to_an_old_or_unregistered_running_workload() {
    let old = application(1002, "approved", "one");
    let new = application(1002, "approved", "two");
    let secret = resource(1002, "ssh");
    let run = execution(&old);
    for memberships in [
        vec![],
        vec![RunPolicyMembership {
            execution: run.clone(),
            generation: old.generation.clone(),
        }],
    ] {
        let index = PolicyIndex::prepare(
            2,
            vec![new.clone()],
            vec![secret.clone()],
            vec![grant(&new, &secret)],
            memberships,
        )
        .unwrap();
        assert_eq!(
            index
                .resource_rule(
                    2,
                    &new,
                    Some(&run),
                    &secret.resource_ref,
                    ResourceAccess::Read
                )
                .unwrap(),
            ResourceRule::DenyUnlessReviewed
        );
        assert!(matches!(
            index
                .resource_rule(2, &new, None, &secret.resource_ref, ResourceAccess::Read)
                .unwrap(),
            ResourceRule::ReviewedCandidate(_)
        ));
    }
}

#[test]
#[ignore = "Bounded Fedora source profiling, not installed enforcement or release acceptance"]
fn profile_two_thousand_policy_records() {
    use std::time::Instant;
    fn distribution(mut values: Vec<u64>) -> serde_json::Value {
        values.sort_unstable();
        let last = values.len() - 1;
        serde_json::json!({"samples": values.len(), "median_ns": values[values.len()/2],
            "p95_ns": values[(values.len()*95).div_ceil(100)-1],
            "min_ns": values[0], "max_ns": values[last]})
    }
    let mut applications = Vec::new();
    let mut resources = Vec::new();
    let mut grants = Vec::new();
    for number in 0..2_000 {
        let app = application(1002, &format!("source-{number}"), "synthetic-code");
        let secret = resource(1002, &format!("synthetic-resource-{number}"));
        let mut review = grant(&app, &secret);
        review.grant_ref = reference("grant", &format!("synthetic-review-{number}"));
        applications.push(app);
        resources.push(secret);
        grants.push(review);
    }
    let mut cold = Vec::new();
    for _ in 0..10 {
        let input = (applications.clone(), resources.clone(), grants.clone());
        let start = Instant::now();
        let prepared = PolicyIndex::prepare(2, input.0, input.1, input.2, vec![]).unwrap();
        std::hint::black_box(&prepared);
        cold.push(u64::try_from(start.elapsed().as_nanos()).unwrap());
    }
    let index =
        PolicyIndex::prepare(2, applications.clone(), resources.clone(), grants, vec![]).unwrap();
    let mut warm = Vec::new();
    for _ in 0..30 {
        for (app, secret) in applications.iter().zip(&resources) {
            let start = Instant::now();
            let rule = index
                .resource_rule(2, app, None, &secret.resource_ref, ResourceAccess::Read)
                .unwrap();
            std::hint::black_box(&rule);
            warm.push(u64::try_from(start.elapsed().as_nanos()).unwrap());
            assert!(matches!(rule, ResourceRule::ReviewedCandidate(_)));
        }
    }
    println!(
        "{}",
        serde_json::json!({"schema": "greyward.application-security.policy-profile/v1",
        "records": 2_000, "cold_index": distribution(cold), "warm_lookup": distribution(warm),
        "enforcement_established": false})
    );
}
