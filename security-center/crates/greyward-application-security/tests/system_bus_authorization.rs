//! Explicit private-agent test; only in-memory desired policy is changed.
use dbus::blocking::Connection;
use dbus::strings::BusName;
use greyward_application_security::*;
use greyward_security_domain::SecurityReference;
use std::io::{BufRead, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const BINARY: &str = "/usr/local/libexec/greyward-application-security-fresh-auth-test";
#[path = "support/critical_registration.rs"]
mod critical_registration;

fn subject() -> (Child, BusName<'static>, std::io::BufReader<ChildStdout>) {
    let mut command = if std::env::var_os("GREYWARD_REQUIRE_CONFINED_AUTH_PEER").is_some() {
        let mut command = Command::new("/usr/bin/systemd-run");
        command.args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--unit=greyward-appsec-auth-peer",
            "-p",
            "User=greyward-guard-probe",
            "-p",
            "Group=greyward-guard-probe",
            "-p",
            "SELinuxContext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0",
            "-p",
            "RuntimeMaxSec=150",
            "-p",
            "MemoryMax=64M",
            "-p",
            "TasksMax=16",
            "-E",
            "GREYWARD_AUTH_SUCCESS_CHILD=1",
        ]);
        command
    } else {
        let mut command = Command::new("/usr/sbin/runuser");
        command.args(["-u", "greyward-guard-probe", "--"]);
        command
    };
    if std::env::var_os("GREYWARD_CRITICAL_TRANSPORT").is_some() {
        command.args(["-E", "GREYWARD_TRANSPORT_CHILD=1"]);
    }
    let mut child = command
        .args([
            BINARY,
            "--ignored",
            "--exact",
            "fresh_owner_checks_require_two_actual_authentications",
            "--nocapture",
        ])
        .env("GREYWARD_AUTH_SUCCESS_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    for _ in 0..16 {
        let mut line = String::new();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        assert!(line.len() <= 4096);
        if let Some((_, sender)) = line.split_once("AUTH_PEER=") {
            return (
                child,
                BusName::new(sender.trim().to_owned()).unwrap(),
                output,
            );
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("Fixed probe peer did not connect");
}

fn review_registration(store: &PolicyStore, actor: &ExecutionHandle) -> PolicyIntentReview {
    let critical = std::env::var_os("GREYWARD_CRITICAL_REGISTRATION").is_some();
    let deadline = Instant::now() + Duration::from_secs(if critical { 110 } else { 12 });
    let descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        if critical {
            "/home/greyward-guard-probe/registration-critical"
        } else {
            "/home/greyward-guard-probe"
        },
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let selection = DirectorySelection::capture(descriptor, 1002, deadline).unwrap();
    PolicyIntentReview::register_directory(
        store,
        actor,
        DirectoryResourceReview {
            selection,
            category: greyward_security_domain::ProtectedCategory::Custom,
            label: "Synthetic metadata-only review".into(),
        },
        PolicyReviewLease {
            operation_ref: SecurityReference::try_from(format!("operation_{}", "c".repeat(64)))
                .unwrap(),
            expected_revision: 1,
            deadline,
        },
    )
    .unwrap()
}

#[test]
#[ignore = "exact root test via private terminal-agent development coordinator"]
#[allow(clippy::too_many_lines)] // Serialized peer/agent lifetime spans fresh review and readback.
fn fresh_owner_checks_require_two_actual_authentications() {
    if std::env::var_os("GREYWARD_AUTH_SUCCESS_CHILD").is_some() {
        assert_eq!(rustix::process::getuid().as_raw(), 1002);
        if std::env::var_os("GREYWARD_TRANSPORT_CHILD").is_some() {
            critical_registration::transport_client();
            return;
        }
        let bus = Connection::new_system().unwrap();
        println!("AUTH_PEER={}", bus.unique_name());
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut [0_u8]).unwrap();
        return;
    }
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let (mut child, sender, mut output) = subject();
    let resolver = SystemPeerResolver::connect().unwrap();
    let actor = resolver.resolve(&sender).unwrap();
    if std::env::var_os("GREYWARD_REQUIRE_CONFINED_AUTH_PEER").is_some() {
        assert_eq!(
            actor.identity().selinux_context,
            "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0"
        );
    }
    assert_eq!(actor.identity().owner_uid, 1002);
    println!(
        "AUTH_SUBJECT={sender},{}:{}",
        actor.identity().pid,
        actor.identity().start_ticks
    );
    std::io::stdout().flush().unwrap();
    // Coordinator starts a process-specific UID 1002 terminal agent first.
    std::io::stdin().read_exact(&mut [0_u8]).unwrap();
    let authority = SystemAuthorizer::connect().unwrap();
    if std::env::var_os("GREYWARD_CRITICAL_TRANSPORT").is_some() {
        critical_registration::run_transport(&actor, &mut child, &mut output);
        return;
    }
    let critical = std::env::var_os("GREYWARD_CRITICAL_REGISTRATION").is_some();
    let mut store = if critical {
        PolicyStore::open_development_registration_probe().unwrap()
    } else {
        PolicyStore::isolated_memory().unwrap()
    };
    let review = review_registration(&store, &actor);
    let mut commit = review
        .commit(&mut store, &actor, &sender, &authority, true)
        .unwrap();
    assert_eq!(commit.revision, 2);
    let registration = commit.take_registration().unwrap();
    assert!(commit.take_registration().is_none());
    registration.revalidate(&store, &actor).unwrap();
    let critical = std::env::var_os("GREYWARD_CRITICAL_REGISTRATION").is_some();
    assert_eq!(
        registration.current_label_type(&store, &actor).unwrap(),
        if critical {
            "user_home_t"
        } else {
            "user_home_dir_t"
        }
    );
    let program = registration.prepare_denial(&store, &actor).unwrap();
    assert!(
        program
            .resource_label(&registration.resource().resource_ref)
            .is_some()
    );
    assert_eq!(
        registration.resource().coverage,
        greyward_security_domain::ResourceCoverage::Unknown
    );
    let state = store.desired_policy().unwrap();
    assert_eq!(
        state.resources[0].resource().coverage,
        greyward_security_domain::ResourceCoverage::Unknown
    );
    let reference = state.resources[0].resource().resource_ref.clone();
    if std::env::var_os("GREYWARD_CRITICAL_GRANTS").is_some() {
        critical_registration::run(
            &mut store,
            &actor,
            &sender,
            &authority,
            registration,
            &program,
        );
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert!(child.wait().unwrap().success());
        return;
    }
    let review = PolicyIntentReview::remove_custom_resource(
        &store,
        &actor,
        reference,
        PolicyReviewLease {
            operation_ref: SecurityReference::try_from(format!("operation_{}", "d".repeat(64)))
                .unwrap(),
            expected_revision: 2,
            deadline: Instant::now() + Duration::from_secs(12),
        },
    )
    .unwrap();
    assert_eq!(
        review
            .commit(&mut store, &actor, &sender, &authority, true)
            .unwrap()
            .revision,
        3
    );
    assert!(store.desired_policy().unwrap().resources.is_empty());
    assert!(store.desired_policy().unwrap().grants.is_empty());
    assert!(registration.revalidate(&store, &actor).is_err());
    child.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert!(child.wait().unwrap().success());
}
