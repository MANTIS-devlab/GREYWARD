use greyward_application_security::*;
use greyward_security_backends::{FlatpakApp, FlatpakAvailability, FlatpakFacts};
use greyward_security_domain::{ApplicationProvider, ProvenanceState};

fn app(scope: &str, branch: &str, code: &[u8]) -> FlatpakApp {
    FlatpakApp {
        app_id: "org.example.App".into(),
        name: "Example".into(),
        scope: scope.into(),
        origin: Some("flathub".into()),
        version: None,
        arch: Some("x86_64".into()),
        branch: Some(branch.into()),
        runtime: None,
        deployment_commit: Some(content_generation(code)),
        identity_state: FlatpakAvailability::Available,
        permissions: vec![],
        permissions_state: FlatpakAvailability::Available,
        overrides: vec![],
    }
}
fn facts(apps: Vec<FlatpakApp>) -> FlatpakFacts {
    FlatpakFacts {
        availability: FlatpakAvailability::Available,
        apps,
        broad_permission_apps: 0,
    }
}
fn apply(store: &mut PolicyStore, facts: &FlatpakFacts, uid: u32, time: u64) {
    let revision = store.inventory_revision().unwrap();
    FlatpakInventoryObservation::from_provider(facts, uid)
        .unwrap()
        .reconcile(store, revision, time)
        .unwrap();
}

#[test]
fn installations_channels_repositories_and_owners_remain_distinct_without_trust() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let mut other_repository = app("user", "stable", b"same");
    other_repository.origin = Some("other".into());
    // An installation cannot simultaneously report two repositories; compare
    // successive observations instead of admitting duplicate scope/ref rows.
    let first = facts(vec![
        app("system", "stable", b"same"),
        app("user", "stable", b"same"),
        app("user", "beta", b"same"),
    ]);
    apply(&mut store, &first, 1000, 10);
    apply(&mut store, &first, 1001, 10);
    let original = store.list_applications(1000, None, 100).unwrap();
    assert_eq!(original.len(), 3);
    assert!(original.iter().all(|entry| entry.identity.provenance.state
        == ProvenanceState::Unknown
        && entry.identity.provenance.source_receipt.is_none()));
    assert!(original.iter().all(|entry| {
        !store
            .list_applications(1001, None, 100)
            .unwrap()
            .iter()
            .any(|foreign| foreign.identity.installation_ref == entry.identity.installation_ref)
    }));
    apply(&mut store, &facts(vec![other_repository]), 1000, 20);
    let changed = store.list_applications(1000, None, 100).unwrap();
    assert_eq!(changed.len(), 1);
    assert!(
        !original
            .iter()
            .any(|old| old.identity.installation_ref == changed[0].identity.installation_ref)
    );
    assert_eq!(store.list_applications(1001, None, 100).unwrap().len(), 3);
}

#[test]
fn partial_or_missing_generation_preserves_previous_records_and_native_inventory() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let native = IdentitySeed {
        provider: ApplicationProvider::Rpm,
        logical_id: "native".into(),
        installation_id: "system".into(),
        source_id: "unverified".into(),
        owner_uid: 1000,
    }
    .identity(content_generation(b"native"))
    .unwrap();
    store
        .reconcile_provider(
            1000,
            ApplicationProvider::Rpm,
            vec![native.clone()],
            true,
            0,
            10,
        )
        .unwrap();
    apply(
        &mut store,
        &facts(vec![app("user", "stable", b"old")]),
        1000,
        10,
    );
    let original = store.list_applications(1000, None, 100).unwrap();
    let mut missing = app("user", "stable", b"new");
    missing.deployment_commit = None;
    let incomplete = facts(vec![missing]);
    assert!(
        !FlatpakInventoryObservation::from_provider(&incomplete, 1000)
            .unwrap()
            .is_complete()
    );
    apply(&mut store, &incomplete, 1000, 20);
    assert_eq!(original, store.list_applications(1000, None, 100).unwrap());
    let mut partial = facts(vec![app("user", "beta", b"beta")]);
    partial.availability = FlatpakAvailability::Partial;
    apply(&mut store, &partial, 1000, 20);
    assert_eq!(store.list_applications(1000, None, 100).unwrap().len(), 3);
    apply(&mut store, &facts(vec![]), 1000, 30);
    assert_eq!(
        store.list_applications(1000, None, 100).unwrap()[0].identity,
        native
    );
}

#[test]
fn generation_changes_stale_batches_and_invalid_metadata_fail_atomically() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let before = facts(vec![app("user", "stable", b"old")]);
    apply(&mut store, &before, 1000, 10);
    let old = store.list_applications(1000, None, 100).unwrap()[0].clone();
    let stale = FlatpakInventoryObservation::from_provider(&before, 1000).unwrap();
    let revision = store.inventory_revision().unwrap();
    apply(
        &mut store,
        &facts(vec![app("user", "stable", b"new")]),
        1000,
        20,
    );
    let current = store.list_applications(1000, None, 100).unwrap()[0].clone();
    assert_eq!(
        old.identity.installation_ref,
        current.identity.installation_ref
    );
    assert_ne!(old.identity.generation, current.identity.generation);
    assert!(matches!(
        stale.reconcile(&mut store, revision, 30),
        Err(StoreError::StaleRevision)
    ));
    for bad in [
        facts(vec![app("user", "--command=sh", b"code")]),
        facts(vec![app("unexpected", "stable", b"code")]),
        facts(vec![
            app("user", "stable", b"code"),
            app("user", "stable", b"other"),
        ]),
    ] {
        assert!(FlatpakInventoryObservation::from_provider(&bad, 1000).is_err());
    }
    assert_eq!(
        store.list_applications(1000, None, 100).unwrap()[0],
        current
    );
}
