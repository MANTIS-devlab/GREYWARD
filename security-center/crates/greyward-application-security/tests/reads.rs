use greyward_application_security::*;
use greyward_security_domain::*;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::process::Command;

fn actor(pid: u32) -> ExecutionHandle {
    ExecutionHandle::capture(BusPeerCredentials {
        uid: rustix::process::getuid().as_raw(),
        pid,
        selinux_label: std::fs::read_to_string(format!("/proc/{pid}/attr/current"))
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

fn identity(uid: u32, name: &str) -> ApplicationIdentity {
    IdentitySeed {
        provider: ApplicationProvider::Rpm,
        logical_id: name.into(),
        installation_id: "system".into(),
        source_id: "test-source".into(),
        owner_uid: uid,
    }
    .identity(content_generation(name.as_bytes()))
    .unwrap()
}

#[test]
#[ignore = "Explicit bounded Fedora profiling of synthetic source reads, not production acceptance"]
fn profile_two_thousand_records_without_protection_claims() {
    use std::time::Instant;
    fn summary(mut values: Vec<u64>) -> serde_json::Value {
        values.sort_unstable();
        serde_json::json!({"samples":30, "median_us":u64::midpoint(values[14],values[15]),
                          "p95_us":values[28], "min_us":values[0], "max_us":values[29]})
    }
    let caller = actor(std::process::id());
    let uid = caller.identity().owner_uid;
    let identities: Vec<_> = (0..2000)
        .map(|index| identity(uid, &format!("profile-{index}")))
        .collect();
    let target = identities.last().unwrap().installation_ref.clone();
    let mut registry = ApplicationRegistry::default();
    registry.reconcile(uid, identities.clone(), 10).unwrap();
    let mut store = PolicyStore::isolated_memory().unwrap();
    store
        .reconcile_applications(uid, identities, 0, 10)
        .unwrap();
    let reads = ApplicationReads::new(&store);
    let mut lookup = Vec::new();
    let mut list = Vec::new();
    let mut detail = Vec::new();
    for _ in 0..30 {
        let start = Instant::now();
        assert!(std::hint::black_box(registry.get(uid, &target)).is_some());
        lookup.push(u64::try_from(start.elapsed().as_micros()).unwrap());
        let start = Instant::now();
        let page = reads.list(&caller, None, None, 100).unwrap();
        assert_eq!(page.applications.len(), 100);
        assert_eq!(page.inventory_health, EnforcementHealth::Unknown);
        assert!(
            page.applications
                .iter()
                .all(|application| application.protection.effective_profile.is_none())
        );
        let encoded = serde_json::to_string(&page).unwrap();
        assert!(encoded.len() < 256 * 1024);
        std::hint::black_box(encoded);
        list.push(u64::try_from(start.elapsed().as_micros()).unwrap());
        let start = Instant::now();
        let application = reads.get(&caller, &target).unwrap().unwrap();
        assert_eq!(application.protection.health, EnforcementHealth::Unknown);
        std::hint::black_box(serde_json::to_string(&application).unwrap());
        detail.push(u64::try_from(start.elapsed().as_micros()).unwrap());
    }
    let lookup = summary(lookup);
    let list = summary(list);
    let detail = summary(detail);
    println!(
        "{}",
        serde_json::json!({"schema":"greyward.application-security.source-read-profile/v1",
        "records":2000, "lookup":lookup, "list":list, "detail":detail,
        "transport_included":false, "production_acceptance_claimed":false})
    );
    assert!(lookup["p95_us"].as_u64().unwrap() <= 2000);
    assert!(list["p95_us"].as_u64().unwrap() <= 200_000);
    assert!(detail["p95_us"].as_u64().unwrap() <= 300_000);
}

#[test]
fn records_and_verified_provenance_cannot_establish_protection_or_inventory_completeness() {
    let caller = actor(std::process::id());
    let uid = caller.identity().owner_uid;
    let mut store = PolicyStore::isolated_memory().unwrap();
    let mut record = identity(uid, "browser");
    record.provenance = ProvenanceSnapshot {
        state: ProvenanceState::Verified,
        source_receipt: Some(content_generation(b"test receipt")),
    };
    store
        .reconcile_applications(uid, vec![record.clone()], 0, 10)
        .unwrap();
    let reads = ApplicationReads::new(&store);
    let page = reads.list(&caller, None, None, 10).unwrap();
    assert_eq!(page.schema, APPLICATION_SECURITY_SCHEMA);
    assert_eq!(page.inventory_health, EnforcementHealth::Unknown);
    assert_eq!(page.applications.len(), 1);
    let detail = reads
        .get(&caller, &record.installation_ref)
        .unwrap()
        .unwrap();
    assert_eq!(detail.protection.health, EnforcementHealth::Unknown);
    assert_eq!(detail.protection.effective_profile, None);
    detail.protection.validate().unwrap();
    assert!(
        serde_json::to_string(&page)
            .unwrap()
            .contains("\"effective_profile\":null")
    );
}

#[test]
fn caller_scope_and_revision_are_enforced_across_pagination_and_detail() {
    let caller = actor(std::process::id());
    let uid = caller.identity().owner_uid;
    let mut store = PolicyStore::isolated_memory().unwrap();
    let records = vec![identity(uid, "first"), identity(uid, "second")];
    let foreign = identity(uid + 1, "foreign");
    store.reconcile_applications(uid, records, 0, 10).unwrap();
    store
        .reconcile_applications(uid + 1, vec![foreign.clone()], 1, 20)
        .unwrap();
    let reads = ApplicationReads::new(&store);
    let first = reads.list(&caller, None, None, 1).unwrap();
    let cursor = first.next_cursor.as_ref().unwrap();
    assert_eq!(first.applications[0].record.identity.owner_uid, uid);
    let second = reads
        .list(&caller, Some(cursor), Some(first.inventory_revision), 1)
        .unwrap();
    assert_ne!(
        first.applications[0].record.identity,
        second.applications[0].record.identity
    );
    assert!(
        reads
            .get(&caller, &foreign.installation_ref)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        reads.list(&caller, Some(&foreign.installation_ref), Some(2), 1),
        Err(ReadError::InvalidQuery)
    ));
    assert!(reads.list(&caller, Some(cursor), None, 1).is_err());
    assert!(reads.list(&caller, None, None, 0).is_err());
    assert!(reads.list(&caller, None, None, 101).is_err());
    store.reconcile_applications(uid, vec![], 2, 30).unwrap();
    let reads = ApplicationReads::new(&store);
    assert!(matches!(
        reads.list(&caller, Some(cursor), Some(first.inventory_revision), 1),
        Err(ReadError::RevisionChanged)
    ));
    let empty = reads.list(&caller, None, None, 10).unwrap();
    assert!(empty.applications.is_empty());
    assert_eq!(empty.inventory_health, EnforcementHealth::Unknown);
}

#[test]
fn an_exited_caller_does_not_receive_an_empty_successful_projection() {
    let mut child = Command::new("/usr/bin/sleep").arg("30").spawn().unwrap();
    let caller = actor(child.id());
    child.kill().unwrap();
    child.wait().unwrap();
    let store = PolicyStore::isolated_memory().unwrap();
    let reads = ApplicationReads::new(&store);
    assert!(matches!(
        reads.list(&caller, None, None, 10),
        Err(ReadError::Execution(_))
    ));
}
