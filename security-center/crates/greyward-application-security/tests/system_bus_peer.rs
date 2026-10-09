use dbus::blocking::Connection;
use dbus::strings::BusName;
use greyward_application_security::SystemPeerResolver;
use greyward_application_security::{
    AuthorizationError, AuthorizationIntent, AuthorizationPurpose, SystemAuthorizer,
};
use greyward_security_domain::SecurityReference;
use std::time::{Duration, Instant};

#[test]
#[ignore = "Requires the packaged Fedora system bus with kernel ProcessFD credentials"]
fn real_system_bus_resolves_a_live_peer_and_rejects_disconnected_or_claimed_names() {
    let connection = Connection::new_system().unwrap();
    let name = BusName::new(connection.unique_name().to_string()).unwrap();
    let resolver = SystemPeerResolver::connect().unwrap();
    let handle = resolver.resolve(&name).unwrap();
    assert_eq!(handle.identity().pid, std::process::id());
    assert_eq!(
        handle.identity().owner_uid,
        rustix::process::getuid().as_raw()
    );
    assert!(handle.identity().installation_ref.is_none());
    assert!(
        resolver
            .resolve(&BusName::new("org.freedesktop.DBus").unwrap())
            .is_err()
    );
    drop(connection);
    assert!(resolver.resolve(&name).is_err());
}

#[test]
#[ignore = "Requires the fixed root-owned Fedora system bus socket"]
fn an_environment_override_cannot_select_the_peer_authority() {
    if std::env::var_os("GREYWARD_PEER_TEST_CHILD").is_some() {
        SystemPeerResolver::connect().unwrap();
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "an_environment_override_cannot_select_the_peer_authority",
        ])
        .env("GREYWARD_PEER_TEST_CHILD", "1")
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            "unix:path=/nonexistent/claimed-system-bus",
        )
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "Requires the fixed experimental Polkit actions and a non-root Fedora test user"]
fn unprivileged_calls_cannot_supply_authorization_details() {
    assert_ne!(rustix::process::getuid().as_raw(), 0);
    let connection = Connection::new_system().unwrap();
    let sender = BusName::new(connection.unique_name().to_string()).unwrap();
    let resolver = SystemPeerResolver::connect().unwrap();
    let actor = resolver.resolve(&sender).unwrap();
    assert!(resolver.resolve_until(&sender, Instant::now()).is_err());
    let authority = SystemAuthorizer::connect().unwrap();
    for (purpose, digit) in [
        (AuthorizationPurpose::OwnerGrant, "c"),
        (AuthorizationPurpose::SystemPolicy, "d"),
    ] {
        let intent = AuthorizationIntent {
            purpose,
            operation_ref: SecurityReference::try_from(format!("operation_{}", digit.repeat(64)))
                .unwrap(),
            expected_revision: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            interactive: false,
        };
        match authority.authorize(&intent, &sender, &actor) {
            Err(AuthorizationError::Bus(error)) => assert_eq!(
                error.name(),
                Some("org.freedesktop.PolicyKit1.Error.NotAuthorized")
            ),
            Err(error) => panic!("Unexpected authority result: {error:?}"),
            Ok(_) => panic!("An unprivileged detailed check was unexpectedly authorized"),
        }
    }
}

#[test]
#[ignore = "Requires root, the enrolled probe account, root-owned auth-test binary and fixed Polkit actions"]
fn root_broker_checks_do_not_authorize_an_unauthenticated_subject() {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::process::{Command, Stdio};
    if std::env::var_os("GREYWARD_AUTH_PEER_CHILD").is_some() {
        assert_eq!(rustix::process::getuid().as_raw(), 1002);
        let bus = Connection::new_system().unwrap();
        println!("GREYWARD_AUTH_PEER={}", bus.unique_name());
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut [0_u8]).unwrap();
        return;
    }
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let binary = "/usr/local/libexec/greyward-application-security-auth-test";
    let metadata = std::fs::symlink_metadata(binary).unwrap();
    assert!(metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0);
    let mut child = Command::new("/usr/sbin/runuser")
        .args([
            "-u",
            "greyward-guard-probe",
            "--",
            binary,
            "--ignored",
            "--exact",
            "root_broker_checks_do_not_authorize_an_unauthenticated_subject",
            "--nocapture",
        ])
        .env("GREYWARD_AUTH_PEER_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut sender = None;
    for _ in 0..16 {
        let mut line = String::new();
        if output.read_line(&mut line).unwrap() == 0 {
            break;
        }
        assert!(line.len() <= 4096);
        if let Some((_, name)) = line.split_once("GREYWARD_AUTH_PEER=") {
            sender = Some(BusName::new(name.trim().to_owned()).unwrap());
            break;
        }
    }
    let sender = sender.expect("The fixed unprivileged child did not connect");
    let resolver = SystemPeerResolver::connect().unwrap();
    let actor = resolver.resolve(&sender).unwrap();
    assert_eq!(actor.identity().owner_uid, 1002);
    let authority = SystemAuthorizer::connect().unwrap();
    for (purpose, digit) in [
        (AuthorizationPurpose::OwnerGrant, "e"),
        (AuthorizationPurpose::SystemPolicy, "f"),
    ] {
        let intent = AuthorizationIntent {
            purpose,
            operation_ref: SecurityReference::try_from(format!("operation_{}", digit.repeat(64)))
                .unwrap(),
            expected_revision: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            interactive: false,
        };
        match authority.authorize(&intent, &sender, &actor) {
            Err(AuthorizationError::AuthenticationRequired | AuthorizationError::NotAuthorized) => {
            }
            Err(error) => panic!("Root check did not reach an authorization decision: {error:?}"),
            Ok(_) => panic!("An unauthenticated subject acquired a weakening ticket"),
        }
    }
    assert_unauthenticated_intent_refused(&actor, &sender, &authority);
    child.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert!(child.wait().unwrap().success());
}

fn assert_unauthenticated_intent_refused(
    actor: &greyward_application_security::ExecutionHandle,
    sender: &BusName<'_>,
    authority: &SystemAuthorizer,
) {
    let descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        "/home/greyward-guard-probe",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let selection =
        greyward_application_security::DirectorySelection::capture(descriptor, 1002, deadline)
            .unwrap();
    let mut store = greyward_application_security::PolicyStore::isolated_memory().unwrap();
    let review = greyward_application_security::PolicyIntentReview::register_directory(
        &store,
        actor,
        greyward_application_security::DirectoryResourceReview {
            selection,
            category: greyward_security_domain::ProtectedCategory::Custom,
            label: "Synthetic metadata-only review".into(),
        },
        greyward_application_security::PolicyReviewLease {
            operation_ref: SecurityReference::try_from(format!("operation_{}", "9".repeat(64)))
                .unwrap(),
            expected_revision: 1,
            deadline,
        },
    )
    .unwrap();
    assert!(matches!(
        review.commit(&mut store, actor, sender, authority, false),
        Err(
            greyward_application_security::PolicyIntentError::Authorization(
                AuthorizationError::AuthenticationRequired | AuthorizationError::NotAuthorized
            )
        )
    ));
    assert_eq!(store.desired_policy().unwrap().revision, 1);
    assert!(store.desired_policy().unwrap().resources.is_empty());
}
