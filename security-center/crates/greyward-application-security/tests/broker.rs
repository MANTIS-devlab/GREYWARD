use dbus::Message;
use greyward_application_security::*;
use greyward_security_domain::*;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::time::{Duration, Instant};

fn call(member: &str) -> Message {
    Message::new_method_call(BROKER_BUS, BROKER_PATH, BROKER_INTERFACE, member).unwrap()
}

#[test]
fn development_transport_rejects_root_command_shaped_and_wrong_namespace_requests() {
    let request = Message::new_method_call(
        DEVELOPMENT_BROKER_BUS,
        BROKER_PATH,
        BROKER_INTERFACE,
        "PrepareLaunch",
    )
    .unwrap()
    .append3(
        format!("grant_{}", "a".repeat(64)),
        "/usr/bin/cat",
        vec!["$(literal-not-shell)"],
    );
    assert!(matches!(
        WorkflowRequest::decode(&request),
        Ok(WorkflowRequest::Prepare { .. })
    ));
    let request = Message::new_method_call(
        DEVELOPMENT_BROKER_BUS,
        BROKER_PATH,
        BROKER_INTERFACE,
        "PrepareLaunch",
    )
    .unwrap()
    .append3(
        format!("grant_{}", "a".repeat(64)),
        "/tmp/untrusted",
        Vec::<String>::new(),
    );
    assert!(matches!(
        WorkflowRequest::decode(&request),
        Err(BrokerError::InvalidRequest)
    ));
    let request = Message::new_method_call(
        DEVELOPMENT_BROKER_BUS,
        BROKER_PATH,
        BROKER_INTERFACE,
        "ApplyPolicyChange",
    )
    .unwrap()
    .append2(format!("installation_{}", "a".repeat(64)), true);
    assert!(matches!(
        WorkflowRequest::decode(&request),
        Err(BrokerError::InvalidRequest)
    ));
    let request = Message::new_method_call(
        DEVELOPMENT_BROKER_BUS,
        BROKER_PATH,
        BROKER_INTERFACE,
        "PreviewResourceRegistration",
    )
    .unwrap()
    .append3("/home/claimed", "CUSTOM", "Claimed directory")
    .append1(1_u64);
    assert!(matches!(
        WorkflowRequest::decode(&request),
        Err(BrokerError::InvalidRequest)
    ));
}

fn actor() -> ExecutionHandle {
    let pid = std::process::id();
    ExecutionHandle::capture(BusPeerCredentials {
        uid: rustix::process::getuid().as_raw(),
        pid,
        selinux_label: std::fs::read_to_string("/proc/self/attr/current")
            .unwrap()
            .trim_end_matches(['\0', '\n'])
            .to_owned(),
        process_fd: pidfd_open(
            Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
            PidfdFlags::NONBLOCK,
        )
        .unwrap(),
    })
    .unwrap()
}

#[test]
fn typed_queries_reject_extra_identity_fields_paths_and_unbounded_queries() {
    assert_eq!(
        ReadRequest::decode(
            &call("ListProtectedResources")
                .append3(10u32, false, 0u64)
                .append1("")
        )
        .unwrap(),
        ReadRequest::Resources {
            limit: 10,
            revision: None,
            after: None
        }
    );
    assert_eq!(
        ReadRequest::decode(
            &call("ListApplications")
                .append3(10u32, false, 0u64)
                .append1("")
        )
        .unwrap(),
        ReadRequest::List {
            limit: 10,
            revision: None,
            after: None
        }
    );
    for query in [
        call("ListApplications")
            .append3(101u32, false, 0u64)
            .append1(""),
        call("ListApplications")
            .append3(1u32, false, 9u64)
            .append1(""),
        call("ListApplications")
            .append3(1u32, false, 0u64)
            .append1("installation_forged"),
        call("ListApplications")
            .append3(1u32, true, 0u64)
            .append1("/home/other"),
        call("GetApplication").append1("/usr/bin/browser"),
        call("GetApplication").append2(format!("installation_{}", "a".repeat(64)), 1002u32),
        call("GetCoverage").append1(1002u32),
        call("GetProtectedResource").append1("/home/user/.ssh"),
        call("ListProtectedResources")
            .append3(10u32, true, 1u64)
            .append1(format!("installation_{}", "a".repeat(64))),
    ] {
        assert!(matches!(
            ReadRequest::decode(&query),
            Err(BrokerError::InvalidRequest)
        ));
    }
}

#[test]
fn unsupported_mutation_and_other_interfaces_have_no_dispatch_fallback() {
    for member in [
        "PrepareLaunch",
        "ApplyPolicyChange",
        "RevokeGrant",
        "RunCommand",
    ] {
        assert!(matches!(
            ReadRequest::decode(&call(member)),
            Err(BrokerError::UnknownMethod)
        ));
    }
    let wrong_path =
        Message::new_method_call(BROKER_BUS, "/other", BROKER_INTERFACE, "GetCoverage").unwrap();
    let wrong_interface = Message::new_method_call(
        BROKER_BUS,
        BROKER_PATH,
        "org.example.Untrusted",
        "GetCoverage",
    )
    .unwrap();
    assert!(matches!(
        ReadRequest::decode(&wrong_path),
        Err(BrokerError::UnknownMethod)
    ));
    assert!(matches!(
        ReadRequest::decode(&wrong_interface),
        Err(BrokerError::UnknownMethod)
    ));
}

#[test]
fn absent_enrollment_is_unavailable_empty_inventory_is_unknown_and_expired_work_fails() {
    let store = PolicyStore::isolated_memory().unwrap();
    let actor = actor();
    let deadline = Instant::now() + Duration::from_secs(2);
    let coverage: serde_json::Value = serde_json::from_str(
        &project_read(&store, &actor, ReadRequest::Coverage, deadline).unwrap(),
    )
    .unwrap();
    assert_eq!(coverage["schema"], APPLICATION_SECURITY_SCHEMA);
    assert_eq!(coverage["inventory_health"], "UNKNOWN");
    assert_eq!(coverage["protection"]["health"], "UNAVAILABLE");
    assert!(coverage["protection"]["effective_profile"].is_null());
    assert_eq!(coverage["protection"]["policy_revision"], 1);
    assert!(
        coverage["protection"]["coverage"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v == false)
    );
    let page: serde_json::Value = serde_json::from_str(
        &project_read(
            &store,
            &actor,
            ReadRequest::List {
                limit: 10,
                revision: None,
                after: None,
            },
            deadline,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(page["inventory_health"], "UNKNOWN");
    assert_eq!(page["applications"].as_array().unwrap().len(), 0);
    let resources: serde_json::Value = serde_json::from_str(
        &project_read(
            &store,
            &actor,
            ReadRequest::Resources {
                limit: 10,
                revision: None,
                after: None,
            },
            deadline,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(resources["inventory_health"], "UNKNOWN");
    assert_eq!(resources["resources"].as_array().unwrap().len(), 0);
    assert_eq!(resources["policy_revision"], 1);
    assert!(matches!(
        project_read(&store, &actor, ReadRequest::Coverage, Instant::now()),
        Err(BrokerError::Deadline)
    ));
}
