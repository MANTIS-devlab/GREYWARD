//! Explicit isolated Fedora root test. No production policy database is opened.
use dbus::blocking::Connection;
use greyward_application_security::*;
use greyward_security_domain::*;
use std::process::Command;
use std::time::Duration;

fn record(uid: u32) -> ApplicationIdentity {
    IdentitySeed {
        provider: ApplicationProvider::Rpm,
        logical_id: "broker-probe".into(),
        installation_id: "system".into(),
        source_id: "synthetic-source".into(),
        owner_uid: uid,
    }
    .identity(content_generation(b"synthetic application"))
    .unwrap()
}

#[test]
#[ignore = "requires fixed probe UID 1002 and temporary reviewed system bus policy"]
fn client_reads_are_bound_to_actual_sender() {
    assert_eq!(rustix::process::getuid().as_raw(), 1002);
    let connection = Connection::new_system().unwrap();
    let proxy = connection.with_proxy(BROKER_BUS, BROKER_PATH, Duration::from_secs(8));
    let (encoded,): (String,) = proxy
        .method_call(
            BROKER_INTERFACE,
            "ListApplications",
            (10u32, false, 0u64, ""),
        )
        .unwrap();
    let page: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(page["schema"], APPLICATION_SECURITY_SCHEMA);
    assert_eq!(page["inventory_health"], "UNKNOWN");
    assert_eq!(page["applications"].as_array().unwrap().len(), 1);
    assert_eq!(
        page["applications"][0]["record"]["identity"]["owner_uid"],
        1002
    );
    assert!(page["applications"][0]["protection"]["effective_profile"].is_null());
    let (own,): (String,) = proxy
        .method_call(
            BROKER_INTERFACE,
            "GetApplication",
            (record(1002).installation_ref.as_str(),),
        )
        .unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&own).unwrap()["application"].is_object());
    let (foreign,): (String,) = proxy
        .method_call(
            BROKER_INTERFACE,
            "GetApplication",
            (record(0).installation_ref.as_str(),),
        )
        .unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&foreign).unwrap()["application"].is_null());
    let (coverage,): (String,) = proxy
        .method_call(BROKER_INTERFACE, "GetCoverage", ())
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&coverage).unwrap()["protection"]["health"],
        "UNKNOWN"
    );
    let stale: Result<(String,), dbus::Error> = proxy.method_call(
        BROKER_INTERFACE,
        "ListApplications",
        (10u32, true, 999u64, ""),
    );
    assert_eq!(
        stale.unwrap_err().name(),
        Some("systems.mantis.greyward.ApplicationSecurity1.RevisionChanged")
    );
    let spoof: Result<(String,), dbus::Error> =
        proxy.method_call(BROKER_INTERFACE, "GetCoverage", (0u32,));
    assert_eq!(
        spoof.unwrap_err().name(),
        Some("org.freedesktop.DBus.Error.InvalidArgs")
    );
    let oversized: Result<(String,), dbus::Error> = proxy.method_call(
        BROKER_INTERFACE,
        "ListApplications",
        (101u32, false, 0u64, ""),
    );
    assert_eq!(
        oversized.unwrap_err().name(),
        Some("org.freedesktop.DBus.Error.InvalidArgs")
    );
    let mutation: Result<(String,), dbus::Error> =
        proxy.method_call(BROKER_INTERFACE, "ApplyPolicyChange", ("forged",));
    assert_eq!(
        mutation.unwrap_err().name(),
        Some("org.freedesktop.DBus.Error.AccessDenied")
    );
    assert!(
        connection
            .request_name(BROKER_BUS, false, true, true)
            .is_err()
    );
}

#[test]
#[ignore = "run only exact root test in a bounded development transient unit"]
fn root_read_transport_enforces_scope_without_enforcement_claims() {
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let mut store = PolicyStore::isolated_memory().unwrap();
    store
        .reconcile_applications(0, vec![record(0)], 0, 10)
        .unwrap();
    store
        .reconcile_applications(1002, vec![record(1002)], 1, 10)
        .unwrap();
    let connection = Connection::new_system().unwrap();
    let proxy = connection.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        Duration::from_secs(2),
    );
    let (exists,): (bool,) = proxy
        .method_call("org.freedesktop.DBus", "NameHasOwner", (BROKER_BUS,))
        .unwrap();
    assert!(
        !exists,
        "An existing broker must not be replaced by this test"
    );
    let _server = std::thread::spawn(move || serve_reads(store).unwrap());
    let mut ready = false;
    for _ in 0..40 {
        let (exists,): (bool,) = proxy
            .method_call("org.freedesktop.DBus", "NameHasOwner", (BROKER_BUS,))
            .unwrap();
        if exists {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready);
    let status = Command::new("/usr/sbin/runuser")
        .args([
            "-u",
            "greyward-guard-probe",
            "--",
            "/usr/local/libexec/greyward-application-security-broker-test",
            "--ignored",
            "--exact",
            "client_reads_are_bound_to_actual_sender",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    // The bounded transient test process exits, releasing the bus name/thread.
    // No service, database or workload is left active by this fixture.
}
