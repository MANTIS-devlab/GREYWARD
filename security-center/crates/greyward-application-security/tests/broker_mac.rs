//! Exact root fixture under the experimental daemon domain, never a production
//! enrollment or generic file-reading command.
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

#[test]
#[ignore = "exact root transient unit with the separate synthetic SELinux policy"]
fn root_broker_installed_metadata_collection_retains_credential_denial() {
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let context = fs::read_to_string("/proc/self/attr/current").unwrap();
    assert_eq!(
        context.split(':').nth(2),
        Some("greyward_application_broker_t")
    );
    let path = greyward_security_domain::InstalledExecutablePath::try_from("/usr/bin/cat").unwrap();
    let collected = greyward_application_security::collect_installed_rpm_content(
        &path,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(collected.package_name(), "coreutils");
    assert_eq!(collected.generation().as_str().len(), 64);
    let identity = collected.observed_identity(1002).unwrap();
    assert_eq!(identity.owner_uid, 1002);
    assert_eq!(
        identity.provider,
        greyward_security_domain::ApplicationProvider::Rpm
    );
    assert_eq!(
        identity.provenance.state,
        greyward_security_domain::ProvenanceState::Unknown
    );
    assert!(identity.provenance.source_receipt.is_none());
    let mut store = greyward_application_security::PolicyStore::isolated_memory().unwrap();
    collected
        .reconcile_observation(&mut store, 1002, 0, 10)
        .unwrap();
    assert_eq!(
        store
            .get_application(1002, &identity.installation_ref)
            .unwrap()
            .unwrap()
            .identity,
        identity
    );
    assert!(store.list_applications(0, None, 10).unwrap().is_empty());
    assert_eq!(
        File::open("/home/greyward-guard-probe/protected/credential")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
#[ignore = "exact root transient unit with the separate synthetic SELinux policy"]
fn root_broker_domain_can_read_process_metadata_but_not_synthetic_credentials() {
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    assert_eq!(
        fs::read_to_string("/sys/fs/selinux/enforce")
            .unwrap()
            .trim(),
        "1"
    );
    let context = fs::read_to_string("/proc/self/attr/current").unwrap();
    assert_eq!(
        context.split(':').nth(2),
        Some("greyward_application_broker_t")
    );
    assert!(!fs::read_to_string("/proc/self/stat").unwrap().is_empty());
    let secret = "/home/greyward-guard-probe/protected/credential";
    let metadata = fs::metadata(secret).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), 1002);
    assert_eq!(metadata.mode() & 0o777, 0o644);
    assert_eq!(
        File::open(secret).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
#[ignore = "exact root transient unit with a pre-opened synthetic credential stdin"]
fn inherited_credential_descriptor_does_not_bypass_broker_mac() {
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let context = fs::read_to_string("/proc/self/attr/current").unwrap();
    assert_eq!(
        context.split(':').nth(2),
        Some("greyward_application_broker_t")
    );
    let selected = fs::metadata("/home/greyward-guard-probe/protected/credential").unwrap();
    let inherited = fs::metadata("/proc/self/fd/0").unwrap();
    // No contents are printed, including on an unexpected access result.
    let mut one_byte = [0_u8; 1];
    if (inherited.dev(), inherited.ino()) == (selected.dev(), selected.ino()) {
        assert_eq!(
            std::io::stdin().read(&mut one_byte).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    } else {
        // SELinux may sanitize forbidden inherited FDs during exec before the
        // child can read. Only the actual null device and EOF are acceptable.
        let null = fs::metadata("/dev/null").unwrap();
        // SELinux's internal null inode can be on a different filesystem from
        // /dev/null. Require a character device with the actual null rdev.
        assert!(inherited.file_type().is_char_device());
        assert_eq!(inherited.rdev(), null.rdev());
        assert_eq!(std::io::stdin().read(&mut one_byte).unwrap(), 0);
    }
}

#[test]
#[ignore = "exact recovery-side root fixture that passes only the synthetic credential FD"]
fn recovery_descriptor_is_denied_after_a_broker_domain_transition() {
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let source = File::open("/home/greyward-guard-probe/protected/credential").unwrap();
    let status =
        std::process::Command::new("/usr/local/libexec/greyward-application-security-mac-test")
            .args([
                "--ignored",
                "--exact",
                "inherited_credential_descriptor_does_not_bypass_broker_mac",
            ])
            .stdin(source)
            .status()
            .unwrap();
    assert!(status.success());
    let ordinary = File::open("/usr/bin/cat").unwrap();
    assert!(
        std::process::Command::new("/usr/local/libexec/greyward-application-security-mac-test")
            .args([
                "--ignored",
                "--exact",
                "inherited_ordinary_descriptor_retains_a_positive_control"
            ])
            .stdin(ordinary)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
#[ignore = "fixed positive-control child of the synthetic FD driver"]
fn inherited_ordinary_descriptor_retains_a_positive_control() {
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let context = fs::read_to_string("/proc/self/attr/current").unwrap();
    assert_eq!(
        context.split(':').nth(2),
        Some("greyward_application_broker_t")
    );
    let mut header = [0_u8; 4];
    std::io::stdin().read_exact(&mut header).unwrap();
    assert_eq!(&header, b"\x7fELF");
}
