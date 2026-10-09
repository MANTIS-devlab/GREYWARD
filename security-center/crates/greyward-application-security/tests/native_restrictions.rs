use greyward_application_security::*;
use rustix::fs::{Mode, OFlags, open};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;

fn descriptor(path: &str) -> std::os::fd::OwnedFd {
    open(
        path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap()
}

#[test]
fn readable_content_descriptors_and_wrong_object_classes_cannot_become_rules() {
    assert!(matches!(
        NativeDescriptorRule::capture(
            File::open("/usr/bin/cat").unwrap().into(),
            NativeRuleKind::SelectedReadFile
        ),
        Err(NativeRestrictionError::Descriptor)
    ));
    assert!(matches!(
        NativeDescriptorRule::capture(descriptor("/usr"), NativeRuleKind::SelectedReadFile),
        Err(NativeRestrictionError::Descriptor)
    ));
    assert!(matches!(
        NativeDescriptorRule::capture(descriptor("/usr/bin/cat"), NativeRuleKind::ReadCodeTree),
        Err(NativeRestrictionError::Descriptor)
    ));
    assert!(matches!(
        NativeDescriptorRule::capture(descriptor("/dev/zero"), NativeRuleKind::NullDevice),
        Err(NativeRestrictionError::Descriptor)
    ));
}

#[test]
fn inherited_descriptor_flags_and_scratch_sharing_fail_before_restriction() {
    let no_close = open("/usr", OFlags::PATH | OFlags::NOFOLLOW, Mode::empty()).unwrap();
    assert!(matches!(
        NativeDescriptorRule::capture(no_close, NativeRuleKind::ReadCodeTree),
        Err(NativeRestrictionError::Descriptor)
    ));
    assert!(matches!(
        NativeDescriptorRule::capture(descriptor("/tmp"), NativeRuleKind::PrivateScratch),
        Err(NativeRestrictionError::Descriptor)
    ));
}

#[test]
fn missing_required_rules_refuse_before_changing_the_test_process() {
    for rules in [
        vec![],
        vec![
            NativeDescriptorRule::capture(descriptor("/usr"), NativeRuleKind::ReadCodeTree)
                .unwrap(),
        ],
    ] {
        assert!(matches!(
            restrict_native_disconnected("invalid", rules),
            Err(NativeRestrictionError::Plan)
        ));
    }
    // The rejection did not install a network restriction into this harness.
    assert!(std::net::TcpListener::bind("127.0.0.1:0").is_ok());
}

#[test]
fn an_unprepared_process_cannot_receive_successful_restriction_evidence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "greyward-native-rule-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let rules = vec![
        NativeDescriptorRule::capture(descriptor("/usr"), NativeRuleKind::ReadCodeTree).unwrap(),
        NativeDescriptorRule::capture(
            descriptor(path.to_str().unwrap()),
            NativeRuleKind::PrivateScratch,
        )
        .unwrap(),
    ];
    assert!(matches!(
        restrict_native_disconnected("unconfined_u:unconfined_r:unconfined_t:s0", rules),
        Err(NativeRestrictionError::Worker)
    ));
    fs::remove_dir(&path).unwrap();
    assert!(std::net::TcpListener::bind("127.0.0.1:0").is_ok());
}
