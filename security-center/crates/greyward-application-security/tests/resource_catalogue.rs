use greyward_application_security::{
    CatalogueDiscovery, CatalogueLimitation, ResourceSelectionError,
};
use greyward_security_domain::ResourceCoverage;
use rustix::fs::{CWD, Mode, OFlags, openat};
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from("/var/tmp")
            .join(format!("greyward-catalogue-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn descriptor(&self) -> OwnedFd {
        openat(
            CWD,
            &self.0,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }
    fn discover(&self) -> CatalogueDiscovery {
        CatalogueDiscovery::discover(
            self.descriptor(),
            rustix::process::getuid().as_raw(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn fixed_metadata_discovery_never_claims_protection_or_reads_contents() {
    let home = Home::new();
    fs::create_dir(home.0.join(".ssh")).unwrap();
    let secret = home.0.join(".ssh/private-key");
    fs::write(&secret, b"synthetic contents never needed by discovery").unwrap();
    fs::set_permissions(secret, fs::Permissions::from_mode(0o0)).unwrap();
    fs::write(home.0.join(".git-credentials"), b"synthetic content").unwrap();
    fs::create_dir(home.0.join("not-catalogued")).unwrap();
    let found = home.discover();
    assert_eq!(found.items().len(), 13);
    assert_eq!(
        found
            .items()
            .iter()
            .find(|item| item.catalogue_id() == "ssh")
            .unwrap()
            .coverage(),
        ResourceCoverage::Unknown
    );
    let file = found
        .items()
        .iter()
        .find(|item| item.catalogue_id() == "git-credentials")
        .unwrap();
    assert_eq!(file.coverage(), ResourceCoverage::Unavailable);
    assert_eq!(
        file.limitation(),
        Some(CatalogueLimitation::UnsupportedObject)
    );
    assert!(
        found
            .items()
            .iter()
            .filter(|item| !["ssh", "git-credentials"].contains(&item.catalogue_id()))
            .all(|item| item.coverage() == ResourceCoverage::NotPresent)
    );
    assert!(
        found
            .items()
            .iter()
            .all(|item| item.coverage() != ResourceCoverage::Protected)
    );
}

#[test]
fn aliases_are_unavailable_and_never_followed() {
    let home = Home::new();
    fs::create_dir(home.0.join("real")).unwrap();
    symlink("real", home.0.join(".ssh")).unwrap();
    symlink("/", home.0.join(".config")).unwrap();
    let found = home.discover();
    for id in ["ssh", "gcloud", "brave", "chromium"] {
        assert_eq!(
            found
                .items()
                .iter()
                .find(|item| item.catalogue_id() == id)
                .unwrap()
                .coverage(),
            ResourceCoverage::Unavailable
        );
    }
}

#[test]
fn expiry_changed_objects_and_unauthenticated_owner_invalidate_review() {
    let home = Home::new();
    let uid = rustix::process::getuid().as_raw();
    assert!(matches!(
        CatalogueDiscovery::discover(
            home.descriptor(),
            uid.wrapping_add(1),
            Instant::now() + Duration::from_secs(5)
        ),
        Err(ResourceSelectionError::Owner)
    ));
    assert!(matches!(
        CatalogueDiscovery::discover(home.descriptor(), uid, Instant::now()),
        Err(ResourceSelectionError::Expired)
    ));
    let found = home.discover();
    fs::create_dir(home.0.join(".aws")).unwrap();
    assert!(matches!(
        found.revalidate(),
        Err(ResourceSelectionError::Changed)
    ));
    let found = home.discover();
    fs::write(home.0.join(".aws/replaced"), b"synthetic").unwrap();
    assert!(matches!(
        found.revalidate(),
        Err(ResourceSelectionError::Changed)
    ));
}
