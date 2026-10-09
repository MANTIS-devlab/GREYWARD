use greyward_application_security::*;
use greyward_security_domain::{ApplicationIdentity, ApplicationProvider};

fn identity(uid: u32, name: &str, content: &[u8]) -> ApplicationIdentity {
    IdentitySeed {
        provider: ApplicationProvider::Manual,
        logical_id: name.into(),
        installation_id: "managed".into(),
        source_id: "unknown".into(),
        owner_uid: uid,
    }
    .identity(content_generation(content))
    .unwrap()
}

#[test]
fn transactional_inventory_preserves_other_users_and_generation_changes() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let first = identity(1000, "first", b"old");
    let foreign = identity(1001, "second", b"foreign");
    store
        .reconcile_applications(1000, vec![first.clone()], 0, 10)
        .unwrap();
    store
        .reconcile_applications(1001, vec![foreign], 1, 20)
        .unwrap();
    let replacement = identity(1000, "first", b"new");
    let changes = store
        .reconcile_applications(1000, vec![replacement], 2, 30)
        .unwrap();
    assert_eq!(
        changes[0].obsolete_generation.as_ref(),
        Some(&first.generation)
    );
    assert_eq!(
        store.list_applications(1000, None, 10).unwrap()[0].first_seen,
        10
    );
    assert_eq!(store.list_applications(1001, None, 10).unwrap().len(), 1);
    assert!(store.list_applications(9999, None, 10).unwrap().is_empty());
}

#[test]
fn stale_or_invalid_batches_leave_the_committed_rows_and_revision_intact() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let first = identity(1000, "first", b"old");
    store
        .reconcile_applications(1000, vec![first.clone()], 0, 10)
        .unwrap();
    assert!(matches!(
        store.reconcile_applications(1000, vec![], 0, 20),
        Err(StoreError::StaleRevision)
    ));
    assert!(
        store
            .reconcile_applications(1000, vec![identity(1001, "foreign", b"code")], 1, 20)
            .is_err()
    );
    assert_eq!(store.inventory_revision().unwrap(), 1);
    assert_eq!(
        store.list_applications(1000, None, 10).unwrap()[0].identity,
        first
    );
}

#[test]
fn two_thousand_records_are_retained_across_bounded_pages() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let entries = (0..2000)
        .map(|index| identity(1000, &format!("app-{index}"), b"code"))
        .collect();
    store.reconcile_applications(1000, entries, 0, 10).unwrap();
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let page = store.list_applications(1000, cursor.as_ref(), 500).unwrap();
        assert!(page.len() <= 100);
        if page.is_empty() {
            break;
        }
        for entry in &page {
            assert!(seen.insert(entry.identity.installation_ref.clone()));
        }
        cursor = page
            .last()
            .map(|entry| entry.identity.installation_ref.clone());
    }
    assert_eq!(seen.len(), 2000);
}

#[test]
fn application_detail_is_owner_scoped_and_not_limited_to_the_first_page() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let entries: Vec<_> = (0..150)
        .map(|index| identity(1000, &format!("app-{index}"), b"code"))
        .collect();
    let foreign = identity(1001, "foreign", b"code");
    store
        .reconcile_applications(1000, entries.clone(), 0, 10)
        .unwrap();
    store
        .reconcile_applications(1001, vec![foreign.clone()], 1, 20)
        .unwrap();
    for entry in entries {
        assert_eq!(
            store
                .get_application(1000, &entry.installation_ref)
                .unwrap()
                .unwrap()
                .identity,
            entry
        );
    }
    assert!(
        store
            .get_application(1000, &foreign.installation_ref)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_application(1001, &foreign.application_ref)
            .unwrap()
            .is_none()
    );
}

#[test]
fn provider_transaction_preserves_partial_and_other_provider_records() {
    let mut store = PolicyStore::isolated_memory().unwrap();
    let manual = identity(1000, "tool", b"tool");
    let flatpak = IdentitySeed {
        provider: ApplicationProvider::Flatpak,
        logical_id: "org.example.App".into(),
        installation_id: "system".into(),
        source_id: "flathub".into(),
        owner_uid: 1000,
    }
    .identity(content_generation(b"deployment"))
    .unwrap();
    store
        .reconcile_applications(1000, vec![manual.clone(), flatpak.clone()], 0, 10)
        .unwrap();
    store
        .reconcile_provider(1000, ApplicationProvider::Flatpak, vec![], false, 1, 20)
        .unwrap();
    assert_eq!(store.inventory_revision().unwrap(), 1);
    assert_eq!(store.list_applications(1000, None, 10).unwrap().len(), 2);
    store
        .reconcile_provider(1000, ApplicationProvider::Flatpak, vec![], true, 1, 20)
        .unwrap();
    assert_eq!(store.inventory_revision().unwrap(), 2);
    assert_eq!(
        store
            .get_application(1000, &manual.installation_ref)
            .unwrap()
            .unwrap()
            .identity,
        manual
    );
    assert!(
        store
            .get_application(1000, &flatpak.installation_ref)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        store.reconcile_provider(
            1000,
            ApplicationProvider::Flatpak,
            vec![flatpak],
            true,
            1,
            30
        ),
        Err(StoreError::StaleRevision)
    ));
}
