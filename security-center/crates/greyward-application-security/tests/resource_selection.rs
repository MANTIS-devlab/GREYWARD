use greyward_application_security::{DirectorySelection, ResourceSelectionError};
use rustix::fs::{CWD, Mode, OFlags, openat};
use std::fs::{self, File};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Fedora's /tmp is tmpfs, deliberately unsupported for persistent
        // protected directories. Use /var/tmp on the tested local filesystem.
        let path = PathBuf::from("/var/tmp")
            .join(format!("greyward-resource-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(path.join("selected")).unwrap();
        Self(path)
    }
    fn base(&self) -> File {
        File::open(&self.0).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn path_descriptor(path: &Path) -> OwnedFd {
    openat(
        CWD,
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap()
}

#[test]
fn selected_directory_has_an_opaque_metadata_lease_not_a_protected_claim() {
    let fixture = Fixture::new();
    let selection =
        DirectorySelection::beneath(fixture.base(), "selected", uid(), deadline()).unwrap();
    assert_eq!(selection.selection_ref().namespace(), "resource");
    assert!(!selection.selection_ref().as_str().contains("selected"));
    selection.revalidate().unwrap();
}

#[test]
fn changed_directory_requires_review_and_reused_path_does_not_retarget_lease() {
    let fixture = Fixture::new();
    let first = DirectorySelection::beneath(fixture.base(), "selected", uid(), deadline()).unwrap();
    fs::write(fixture.0.join("selected/new-child"), b"synthetic").unwrap();
    assert!(matches!(
        first.revalidate(),
        Err(ResourceSelectionError::Changed)
    ));
    fs::rename(fixture.0.join("selected"), fixture.0.join("previous")).unwrap();
    fs::create_dir(fixture.0.join("selected")).unwrap();
    let replacement =
        DirectorySelection::beneath(fixture.base(), "selected", uid(), deadline()).unwrap();
    assert_ne!(first.selection_ref(), replacement.selection_ref());
    assert!(matches!(
        first.revalidate(),
        Err(ResourceSelectionError::Changed)
    ));
}

#[test]
fn symlink_aliases_and_magic_links_are_not_followed() {
    let fixture = Fixture::new();
    symlink("selected", fixture.0.join("alias")).unwrap();
    symlink("/proc/self/fd", fixture.0.join("magic")).unwrap();
    assert!(DirectorySelection::beneath(fixture.base(), "alias", uid(), deadline()).is_err());
    assert!(DirectorySelection::beneath(fixture.base(), "magic/0", uid(), deadline()).is_err());
    assert!(matches!(
        DirectorySelection::capture(path_descriptor(&fixture.0.join("alias")), uid(), deadline()),
        Err(ResourceSelectionError::UnsupportedObject)
    ));
}

#[test]
fn traversal_absolute_control_and_unbounded_names_are_refused_before_resolution() {
    let fixture = Fixture::new();
    for path in [
        "",
        ".",
        "..",
        "../selected",
        "/selected",
        "selected/",
        "selected//x",
        "selected/./x",
        "selected\nx",
    ] {
        assert!(matches!(
            DirectorySelection::beneath(fixture.base(), path, uid(), deadline()),
            Err(ResourceSelectionError::InvalidPath)
        ));
    }
    for path in ["a".repeat(4097), vec!["a"; 33].join("/")] {
        assert!(matches!(
            DirectorySelection::beneath(fixture.base(), &path, uid(), deadline()),
            Err(ResourceSelectionError::InvalidPath)
        ));
    }
}

#[test]
fn regular_files_hardlinks_and_readable_directory_descriptors_are_unsupported() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("individual"), b"synthetic").unwrap();
    fs::hard_link(fixture.0.join("individual"), fixture.0.join("alias")).unwrap();
    for file in ["individual", "alias"] {
        assert!(matches!(
            DirectorySelection::capture(path_descriptor(&fixture.0.join(file)), uid(), deadline()),
            Err(ResourceSelectionError::UnsupportedObject)
        ));
    }
    assert!(matches!(
        DirectorySelection::capture(fixture.base().into(), uid(), deadline()),
        Err(ResourceSelectionError::InvalidDescriptor)
    ));
}

#[test]
fn owner_and_expiry_cannot_be_bypassed_with_a_valid_directory_descriptor() {
    let fixture = Fixture::new();
    assert!(matches!(
        DirectorySelection::beneath(fixture.base(), "selected", uid() + 1, deadline()),
        Err(ResourceSelectionError::Owner)
    ));
    assert!(matches!(
        DirectorySelection::beneath(fixture.base(), "selected", uid(), Instant::now()),
        Err(ResourceSelectionError::Expired)
    ));
    let selection = DirectorySelection::beneath(
        fixture.base(),
        "selected",
        uid(),
        Instant::now() + Duration::from_millis(20),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(30));
    assert!(matches!(
        selection.revalidate(),
        Err(ResourceSelectionError::Expired)
    ));
}

#[test]
fn unsupported_proc_filesystem_is_not_classified_as_protectable() {
    assert!(matches!(
        DirectorySelection::capture(path_descriptor(Path::new("/proc/self")), uid(), deadline()),
        Err(ResourceSelectionError::UnsupportedObject)
    ));
    // Resolve the selected directory explicitly; proc is still an unsupported FS.
    let descriptor = openat(
        CWD,
        "/proc/self/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    assert!(matches!(
        DirectorySelection::capture(descriptor, uid(), deadline()),
        Err(ResourceSelectionError::UnsupportedFilesystem)
    ));
}

#[test]
#[ignore = "Requires the bounded root/private-mount synthetic fixture"]
fn root_bind_alias_cannot_be_selected_as_a_descendant_mount() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let fixture =
        Path::new("/var/lib/greyward-development/application-security/resource-selection-probe");
    let base = File::open(fixture).unwrap();
    let selected = fs::metadata(fixture.join("selected")).unwrap();
    let alias = fs::metadata(fixture.join("alias")).unwrap();
    assert_eq!((selected.dev(), selected.ino()), (alias.dev(), alias.ino()));
    assert_eq!(selected.uid(), 1002);
    let lease = DirectorySelection::beneath(&base, "selected", 1002, deadline()).unwrap();
    lease.revalidate().unwrap();
    assert!(matches!(
        DirectorySelection::beneath(&base, "alias", 1002, deadline()),
        Err(ResourceSelectionError::Kernel(rustix::io::Errno::XDEV))
    ));
    assert!(
        fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| { line.split_whitespace().nth(4) == fixture.join("alias").to_str() })
    );
}
