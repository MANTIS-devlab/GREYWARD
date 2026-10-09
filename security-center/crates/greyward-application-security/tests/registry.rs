use greyward_application_security::*;
use greyward_security_domain::ApplicationProvider;

fn seed(uid: u32) -> IdentitySeed {
    IdentitySeed {
        provider: ApplicationProvider::Flatpak,
        logical_id: "org.example.App".into(),
        installation_id: "user".into(),
        source_id: "flathub".into(),
        owner_uid: uid,
    }
}

#[test]
fn owners_installations_and_sources_have_distinct_identities() {
    let generation = content_generation(b"deployment");
    let first = seed(1000).identity(generation.clone()).unwrap();
    let other_owner = seed(1001).identity(generation.clone()).unwrap();
    assert_ne!(first.application_ref, other_owner.application_ref);
    let mut other = seed(1000);
    other.installation_id = "system".into();
    assert_ne!(
        first.installation_ref,
        other.identity(generation.clone()).unwrap().installation_ref
    );
    other.installation_id = "user".into();
    other.source_id = "another-repository".into();
    assert_ne!(
        first.installation_ref,
        other.identity(generation).unwrap().installation_ref
    );
}

#[test]
fn changed_bytes_do_not_reuse_generation_binding() {
    let mut registry = ApplicationRegistry::default();
    let old = seed(1000)
        .identity(content_generation(b"old code"))
        .unwrap();
    registry.reconcile(1000, vec![old.clone()], 10).unwrap();
    let new = seed(1000)
        .identity(content_generation(b"new code"))
        .unwrap();
    let changes = registry.reconcile(1000, vec![new.clone()], 20).unwrap();
    assert_eq!(changes[0].obsolete_generation, Some(old.generation.clone()));
    assert!(!registry.generation_matches(1000, &old.installation_ref, &old.generation));
    assert!(registry.generation_matches(1000, &new.installation_ref, &new.generation));
    assert_eq!(registry.list(1000, None, 10)[0].first_seen, 10);
}

#[test]
fn invalid_batch_does_not_partially_replace_inventory() {
    let mut registry = ApplicationRegistry::default();
    let old = seed(1000).identity(content_generation(b"old")).unwrap();
    registry.reconcile(1000, vec![old.clone()], 10).unwrap();
    let revision = registry.revision();
    let foreign = seed(1001).identity(content_generation(b"foreign")).unwrap();
    assert!(
        registry
            .reconcile(1000, vec![old.clone(), foreign], 20)
            .is_err()
    );
    assert_eq!(registry.revision(), revision);
    assert!(registry.generation_matches(1000, &old.installation_ref, &old.generation));
}

#[test]
fn duplicates_are_rejected_and_uninstalled_generation_is_not_authorized() {
    let mut registry = ApplicationRegistry::default();
    let entry = seed(1000).identity(content_generation(b"app")).unwrap();
    assert_eq!(
        registry.reconcile(1000, vec![entry.clone(), entry.clone()], 10),
        Err(RegistryError::DuplicateInstallation)
    );
    registry.reconcile(1000, vec![entry.clone()], 10).unwrap();
    let removed = registry.reconcile(1000, vec![], 20).unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(
        removed[0].obsolete_generation,
        Some(entry.generation.clone())
    );
    assert!(!registry.generation_matches(1000, &entry.installation_ref, &entry.generation));
}

#[test]
fn paths_and_credential_urls_are_not_persisted_as_identifiers() {
    for source in [
        "../../etc",
        "https://user:password@example",
        "repo\ncommand",
        "x".repeat(257).as_str(),
    ] {
        let mut identity = seed(1000);
        identity.source_id = source.into();
        assert!(identity.identity(content_generation(b"code")).is_err());
    }
}

#[test]
fn per_owner_inventory_cannot_leak_foreign_records() {
    let mut registry = ApplicationRegistry::default();
    for uid in [1000, 1001] {
        registry
            .reconcile(
                uid,
                vec![seed(uid).identity(content_generation(b"app")).unwrap()],
                10,
            )
            .unwrap();
    }
    assert!(
        registry
            .list(1000, None, 10)
            .iter()
            .all(|entry| entry.identity.owner_uid == 1000)
    );
    assert!(registry.list(9999, None, 10).is_empty());
}

#[test]
fn provider_refresh_preserves_other_providers_and_partial_absence() {
    let mut registry = ApplicationRegistry::default();
    let flatpak = seed(1000)
        .identity(content_generation(b"deployment"))
        .unwrap();
    let mut native_seed = seed(1000);
    native_seed.provider = ApplicationProvider::Rpm;
    let native = native_seed.identity(content_generation(b"native")).unwrap();
    registry
        .reconcile(1000, vec![flatpak.clone(), native.clone()], 10)
        .unwrap();
    let revision = registry.revision();
    assert!(
        registry
            .reconcile_provider(1000, ApplicationProvider::Flatpak, vec![], false, 20)
            .unwrap()
            .is_empty()
    );
    assert_eq!(registry.revision(), revision);
    assert_eq!(registry.list(1000, None, 10).len(), 2);
    let removed = registry
        .reconcile_provider(1000, ApplicationProvider::Flatpak, vec![], true, 20)
        .unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].installation_ref, flatpak.installation_ref);
    assert!(registry.generation_matches(1000, &native.installation_ref, &native.generation));
}

#[test]
fn provider_batch_cannot_overwrite_foreign_provider_identity() {
    let mut registry = ApplicationRegistry::default();
    let original = seed(1000)
        .identity(content_generation(b"original"))
        .unwrap();
    registry
        .reconcile(1000, vec![original.clone()], 10)
        .unwrap();
    let mut forged = original.clone();
    forged.provider = ApplicationProvider::Rpm;
    forged.generation = content_generation(b"changed");
    let revision = registry.revision();
    assert_eq!(
        registry.reconcile_provider(1000, ApplicationProvider::Rpm, vec![forged], true, 20),
        Err(RegistryError::InvalidMetadata)
    );
    assert!(
        registry
            .reconcile_provider(
                1000,
                ApplicationProvider::Rpm,
                vec![original.clone()],
                true,
                20
            )
            .is_err()
    );
    assert_eq!(registry.revision(), revision);
    assert_eq!(
        registry
            .get(1000, &original.installation_ref)
            .unwrap()
            .identity,
        original
    );
}
