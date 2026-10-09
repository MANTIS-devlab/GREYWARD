use greyward_application_security::{
    InstalledContentError, InstalledExecutable, RpmFileReceipt, RpmIdentityError,
    collect_installed_rpm_content,
};
use greyward_security_backends::read_installed_rpm_metadata;
use greyward_security_domain::InstalledExecutablePath;
use std::time::{Duration, Instant};

fn receipt(header: &str, path: &str, digest: &str, mode: u32, flags: &str) -> Vec<u8> {
    format!("sample\t0\t1.0\t1.fc44\tx86_64\t{header}\t8\n{path}\t{digest}\t{mode}\t{flags}\n")
        .into_bytes()
}

#[test]
fn only_full_unambiguous_file_evidence_is_accepted() {
    let valid = receipt(
        &"a".repeat(64),
        "/usr/bin/example",
        &"b".repeat(64),
        0o100_755,
        "0",
    );
    assert_eq!(
        RpmFileReceipt::parse(&valid, "/usr/bin/example")
            .unwrap()
            .package_name(),
        "sample"
    );
    for bytes in [
        valid[..valid.len() - 1].to_vec(),
        [valid.clone(), valid.clone()].concat(),
        String::from_utf8(valid.clone())
            .unwrap()
            .replace("\t8\n", "\t1\n")
            .into_bytes(),
        String::from_utf8(valid.clone())
            .unwrap()
            .replace("\t0\t1.0", "\t00\t1.0")
            .into_bytes(),
        receipt(
            &"a".repeat(63),
            "/usr/bin/example",
            &"b".repeat(64),
            0o100_755,
            "0",
        ),
        receipt(
            &"a".repeat(64),
            "/usr/bin/example",
            &"B".repeat(64),
            0o100_755,
            "0",
        ),
    ] {
        assert!(RpmFileReceipt::parse(&bytes, "/usr/bin/example").is_err());
    }
    let repeated_file = [
        valid.clone(),
        valid.split(|byte| *byte == b'\n').nth(1).unwrap().to_vec(),
        vec![b'\n'],
    ]
    .concat();
    assert!(RpmFileReceipt::parse(&repeated_file, "/usr/bin/example").is_err());
    assert!(RpmFileReceipt::parse(&valid, "/usr/bin/missing").is_err());
}

#[test]
fn unsafe_file_modes_flags_and_paths_never_bind() {
    for mode in [
        0o100_777, 0o104_755, 0o102_755, 0o101_755, 0o120_755, 0o100_644,
    ] {
        assert!(
            RpmFileReceipt::parse(
                &receipt(
                    &"a".repeat(64),
                    "/usr/bin/example",
                    &"b".repeat(64),
                    mode,
                    "0"
                ),
                "/usr/bin/example"
            )
            .is_err()
        );
    }
    for flags in ["1", "64", "01", "-1"] {
        assert!(
            RpmFileReceipt::parse(
                &receipt(
                    &"a".repeat(64),
                    "/usr/bin/example",
                    &"b".repeat(64),
                    0o100_755,
                    flags
                ),
                "/usr/bin/example"
            )
            .is_err()
        );
    }
    for path in [
        "/usr/bin/../example",
        "/usr//example",
        "/home/user/example",
        "--query",
        "/usr/bin/x\n",
    ] {
        assert!(
            RpmFileReceipt::parse(
                &receipt(&"a".repeat(64), path, &"b".repeat(64), 0o100_755, "0"),
                path
            )
            .is_err()
        );
    }
}

#[test]
fn copied_paths_cannot_acquire_installed_path_evidence() {
    assert_ne!(
        rustix::process::getuid().as_raw(),
        0,
        "Run ordinary tests unprivileged"
    );
    for path in ["/home/example/cat", "/tmp/cat", "/usr/bin/../bin/cat"] {
        assert!(matches!(
            InstalledExecutable::capture(path, Instant::now() + Duration::from_secs(5)),
            Err(InstalledContentError::InvalidPath)
        ));
    }
}

fn installed_cat() -> RpmFileReceipt {
    // Explicit integration only: outer systemd test unit enforces the hard
    // process deadline. No shell, verification scriptlet, download or sudo.
    let path = InstalledExecutablePath::try_from("/usr/bin/cat").unwrap();
    let bytes =
        read_installed_rpm_metadata(&path, Instant::now() + Duration::from_secs(5)).unwrap();
    RpmFileReceipt::parse(&bytes, path.as_str()).unwrap()
}

#[test]
#[ignore = "Explicit read-only Fedora integration in a bounded development unit"]
fn installed_rpm_generation_matches_held_elf_and_rejects_stale_collection() {
    let before = installed_cat();
    let candidate =
        InstalledExecutable::capture("/usr/bin/cat", Instant::now() + Duration::from_secs(5))
            .unwrap();
    let after = installed_cat();
    let binding = before.bind_content(&candidate, &after).unwrap();
    let collected = collect_installed_rpm_content(
        &InstalledExecutablePath::try_from("/usr/bin/cat").unwrap(),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(collected.generation(), binding.generation());
    assert_eq!(collected.package_name(), "coreutils");
    assert_eq!(
        binding.generation(),
        before
            .bind_content(&candidate, &after)
            .unwrap()
            .generation()
    );
    let wrong = RpmFileReceipt::parse(
        &receipt(
            &"a".repeat(64),
            "/usr/bin/cat",
            candidate.generation().as_str(),
            0o100_755,
            "0",
        ),
        "/usr/bin/cat",
    )
    .unwrap();
    assert!(matches!(
        before.bind_content(&candidate, &wrong),
        Err(RpmIdentityError::Changed)
    ));
    let changed = RpmFileReceipt::parse(
        &receipt(
            &"a".repeat(64),
            "/usr/bin/cat",
            &"b".repeat(64),
            0o100_755,
            "0",
        ),
        "/usr/bin/cat",
    )
    .unwrap();
    assert!(matches!(
        changed.bind_content(&candidate, &changed),
        Err(RpmIdentityError::Changed)
    ));
    let other_path = RpmFileReceipt::parse(
        &receipt(
            &"a".repeat(64),
            "/usr/bin/different",
            candidate.generation().as_str(),
            0o100_755,
            "0",
        ),
        "/usr/bin/different",
    )
    .unwrap();
    assert!(matches!(
        other_path.bind_content(&candidate, &other_path),
        Err(RpmIdentityError::UnsafeObject)
    ));
}
