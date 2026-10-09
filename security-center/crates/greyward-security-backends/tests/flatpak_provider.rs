//! Explicit installed-provider read test, no permission/package mutation.
use greyward_security_backends::{FlatpakAvailability, collect_flatpak_facts};

#[test]
#[ignore = "requires the pinned Fedora Flatpak provider and installed test applications"]
fn installed_flatpak_reads_bind_full_deployment_generations() {
    assert_ne!(rustix::process::getuid().as_raw(), 0);
    let facts = collect_flatpak_facts();
    assert_eq!(facts.availability, FlatpakAvailability::Available);
    assert!(!facts.apps.is_empty());
    for app in facts.apps {
        assert_eq!(app.identity_state, FlatpakAvailability::Available);
        assert_eq!(app.deployment_commit.unwrap().as_str().len(), 64);
        assert!(app.arch.is_some() && app.branch.is_some());
        assert_eq!(app.permissions_state, FlatpakAvailability::Available);
    }
}
