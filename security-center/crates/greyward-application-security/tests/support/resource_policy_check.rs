//! Fixed synthetic CIL emitter, excluded from the installed RPM.
use greyward_application_security::{
    DevelopmentDenialReadback, ResourceDenialProgram, ResourceIntent,
};

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        arguments == ["--emit-development-fixture"]
            || arguments == ["--check-development-fixture"]
            || arguments == ["--expect-absent-development-fixture"]
            || arguments == ["--check-development-lifecycle"]
    );
    let reference = "d".repeat(64);
    let resource: ResourceIntent = serde_json::from_value(serde_json::json!({
        "resource": {"resource_ref": format!("resource_{reference}"), "owner_uid": 1002,
            "category": "CUSTOM", "label": "Synthetic policy fixture", "coverage": "UNKNOWN", "policy_revision": 2},
        "object": {"device": 1, "inode": 1, "owner_uid": 1002,
            "changed_seconds": 1, "changed_nanoseconds": 0},
        "reviewed_by": {"execution_ref": format!("execution_{reference}"),
            "installation_ref": null, "owner_uid": 1002,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "pid": 42, "start_ticks": 100, "selinux_context": "user_u:user_r:user_t:s0"},
        "operation_ref": format!("operation_{reference}")
    })).unwrap();
    let program =
        ResourceDenialProgram::prepare_development_baseline(2, 2, 1002, &[resource]).unwrap();
    if arguments == ["--emit-development-fixture"] {
        print!("{}", program.cil());
    } else if arguments == ["--expect-absent-development-fixture"] {
        let result = DevelopmentDenialReadback::read(
            &program,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        );
        assert!(
            matches!(result, Err(greyward_application_security::SelinuxReadbackError::Io(ref error)) if error.raw_os_error() == Some(libc::EINVAL))
        );
        println!(
            "{}",
            serde_json::json!({"schema": "greyward.application-security.policy-readback-probe/v1",
            "absent_policy_refused": true, "production_coverage_claimed": false})
        );
    } else if arguments == ["--check-development-lifecycle"] {
        use std::io::{BufRead, Read, Write};
        let receipt = DevelopmentDenialReadback::read(
            &program,
            std::time::Instant::now() + std::time::Duration::from_secs(20),
        )
        .unwrap();
        println!("POLICY_READBACK_READY");
        std::io::stdout().flush().unwrap();
        let mut handshake = String::new();
        std::io::stdin()
            .lock()
            .take(32)
            .read_line(&mut handshake)
            .unwrap();
        assert_eq!(handshake, "CHECK\n");
        let changed = receipt.revalidate(&program);
        assert!(
            matches!(
                changed,
                Err(greyward_application_security::SelinuxReadbackError::Changed)
            ) || matches!(changed, Err(greyward_application_security::SelinuxReadbackError::Io(ref error)) if error.raw_os_error() == Some(libc::EINVAL))
        );
        println!(
            "{}",
            serde_json::json!({"schema": "greyward.application-security.policy-readback-probe/v1",
            "policy_removal_invalidates_cached_readback": true, "production_coverage_claimed": false})
        );
    } else {
        let receipt = DevelopmentDenialReadback::read(
            &program,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .unwrap();
        receipt.revalidate(&program).unwrap();
        assert_eq!(receipt.labels_checked(), 1);
        println!(
            "{}",
            serde_json::json!({"schema": "greyward.application-security.policy-readback-probe/v1",
            "passed": true, "labels_checked": 1, "kernel_sequence": receipt.kernel_sequence(),
            "production_coverage_claimed": false})
        );
    }
}
