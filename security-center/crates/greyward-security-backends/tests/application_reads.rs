use chrono::{Duration, Utc};
use greyward_security_backends::*;
use greyward_security_domain::*;
use serde_json::{Value, json};

fn reference(namespace: &str, index: u64) -> SecurityReference {
    SecurityReference::try_from(format!("{namespace}_{index:064x}")).unwrap()
}

fn unknown() -> ProtectionSnapshot {
    ProtectionSnapshot::from_evidence(
        ProtectionProfile::Protected,
        &EnforcementEvidence::default(),
    )
}

fn app(index: u64) -> ApplicationReadDetails {
    ApplicationReadDetails {
        record: ApplicationInventoryRecord {
            identity: ApplicationIdentity {
                display_name: None,
                application_ref: reference("application", index),
                installation_ref: reference("installation", index),
                generation: ContentGeneration::try_from("a".repeat(64)).unwrap(),
                provider: ApplicationProvider::Rpm,
                owner_uid: rustix::process::getuid().as_raw(),
                provenance: ProvenanceSnapshot::default(),
            },
            first_seen: 1,
            last_seen: 2,
        },
        protection: unknown(),
    }
}

fn envelope(projection: &Value) -> Value {
    let now = Utc::now();
    json!({"schema":APPLICATION_SECURITY_SCHEMA, "source_state":{"state":"AVAILABLE","reason":null},
           "observed_at":now,"fresh_until":now+Duration::seconds(5),"projection":projection})
}

fn coverage() -> Value {
    envelope(&json!(ApplicationCoverage {
        schema: APPLICATION_SECURITY_SCHEMA.into(),
        inventory_health: EnforcementHealth::Unknown,
        protection: unknown(),
    }))
}

fn query(limit: u32) -> ApplicationPageQuery {
    ApplicationPageQuery {
        limit,
        revision: Some(1),
        after: None,
    }
}

fn page() -> Value {
    envelope(&json!(ApplicationInventoryPage {
        schema: APPLICATION_SECURITY_SCHEMA.into(),
        inventory_revision: 1,
        inventory_health: EnforcementHealth::Unknown,
        applications: vec![app(1), app(2)],
        next_cursor: Some(reference("installation", 2)),
    }))
}

#[test]
fn available_transport_keeps_unknown_inventory_and_protection_explicit() {
    let value = decode_application_coverage(&coverage().to_string(), Utc::now()).unwrap();
    let projection = value.projection.unwrap();
    assert_eq!(projection.inventory_health, EnforcementHealth::Unknown);
    assert_eq!(projection.protection.health, EnforcementHealth::Unknown);
    assert_eq!(projection.protection.effective_profile, None);
    let value = decode_application_page(&page().to_string(), &query(2), Utc::now()).unwrap();
    assert_eq!(value.projection.unwrap().applications.len(), 2);
}

fn resource_page() -> Value {
    envelope(
        &json!({"schema":APPLICATION_SECURITY_SCHEMA,"policy_revision":1,
        "inventory_health":"UNKNOWN","next_cursor":reference("resource",1),"resources":[{
            "resource_ref":reference("resource",1),"owner_uid":rustix::process::getuid().as_raw(),
            "category":"CREDENTIALS","label":"SSH credentials","coverage":"UNKNOWN","policy_revision":1
        }]}),
    )
}

#[test]
fn resources_are_owner_scoped_revision_bound_authoritative_projections() {
    let query = ProtectedResourcePageQuery {
        limit: 1,
        revision: Some(1),
        after: None,
    };
    let value = resource_page();
    let page = decode_protected_resource_page(&value.to_string(), &query, Utc::now()).unwrap();
    assert_eq!(
        page.projection.unwrap().resources[0].coverage,
        ResourceCoverage::Unknown
    );
    for (field, bad) in [
        ("owner_uid", json!(rustix::process::getuid().as_raw() + 1)),
        ("coverage", json!("INVALID")),
        ("policy_revision", json!(2)),
    ] {
        let mut value = resource_page();
        value["projection"]["resources"][0][field] = bad;
        assert!(decode_protected_resource_page(&value.to_string(), &query, Utc::now()).is_err());
    }
    let stale = ProtectedResourcePageQuery {
        revision: Some(2),
        ..query.clone()
    };
    assert!(decode_protected_resource_page(&value.to_string(), &stale, Utc::now()).is_err());
    let invalid = ProtectedResourcePageQuery {
        after: Some(reference("installation", 1)),
        ..query.clone()
    };
    assert!(invalid.validate().is_err());
    let mut value = resource_page();
    value["projection"]["next_cursor"] = Value::Null;
    assert!(decode_protected_resource_page(&value.to_string(), &query, Utc::now()).is_err());
    let object = resource_page()["projection"]["resources"][0].clone();
    let lookup = envelope(
        &json!({"schema":APPLICATION_SECURITY_SCHEMA,"policy_revision":1,"resource":object}),
    );
    assert!(
        decode_protected_resource_lookup(
            &lookup.to_string(),
            &reference("resource", 1),
            Utc::now()
        )
        .is_ok()
    );
    assert!(
        decode_protected_resource_lookup(
            &lookup.to_string(),
            &reference("resource", 2),
            Utc::now()
        )
        .is_err()
    );
}

#[test]
fn live_resource_coverage_reaches_page_and_detail_but_expired_claims_refuse() {
    let query = ProtectedResourcePageQuery {
        limit: 1,
        revision: Some(1),
        after: None,
    };
    for coverage in ["PROTECTED", "UNAVAILABLE", "UNKNOWN"] {
        let mut value = resource_page();
        value["projection"]["resources"][0]["coverage"] = json!(coverage);
        assert!(decode_protected_resource_page(&value.to_string(), &query, Utc::now()).is_ok());
        let object = value["projection"]["resources"][0].clone();
        let mut lookup = envelope(&json!({"schema":APPLICATION_SECURITY_SCHEMA,
            "policy_revision":1,"resource":object}));
        assert!(
            decode_protected_resource_lookup(
                &lookup.to_string(),
                &reference("resource", 1),
                Utc::now()
            )
            .is_ok()
        );
        let expired = Utc::now() - Duration::seconds(10);
        for projection in [&mut value, &mut lookup] {
            projection["observed_at"] = json!(expired);
            projection["fresh_until"] = json!(expired + Duration::seconds(5));
        }
        assert!(decode_protected_resource_page(&value.to_string(), &query, Utc::now()).is_err());
        assert!(
            decode_protected_resource_lookup(
                &lookup.to_string(),
                &reference("resource", 1),
                Utc::now()
            )
            .is_err()
        );
    }
}

#[test]
fn contradictory_profile_and_stale_or_future_leases_are_refused() {
    let now = Utc::now();
    let mut value = coverage();
    value["projection"]["protection"]["health"] = json!("AVAILABLE");
    value["projection"]["protection"]["effective_profile"] = json!("PROTECTED");
    assert!(decode_application_coverage(&value.to_string(), now).is_err());
    for (observed, fresh) in [
        (now - Duration::seconds(10), now - Duration::seconds(5)),
        (now + Duration::seconds(10), now + Duration::seconds(11)),
        (now, now + Duration::seconds(6)),
    ] {
        let mut value = coverage();
        value["observed_at"] = json!(observed);
        value["fresh_until"] = json!(fresh);
        assert!(decode_application_coverage(&value.to_string(), now).is_err());
    }
}

#[test]
fn enforcement_age_includes_the_facade_wait_even_with_a_remaining_source_lease() {
    let now = Utc::now();
    let mut value = coverage();
    let p = &mut value["projection"]["protection"];
    p["health"] = json!("AVAILABLE");
    p["effective_profile"] = json!("PROTECTED");
    p["policy_revision"] = json!(1);
    p["evidence_age_ms"] = json!(29_950);
    for gate in p["coverage"].as_object_mut().unwrap().values_mut() {
        *gate = json!(true);
    }
    value["observed_at"] = json!(now);
    value["fresh_until"] = json!(now + Duration::seconds(5));
    assert!(decode_application_coverage(&value.to_string(), now).is_ok());
    assert!(
        decode_application_coverage(&value.to_string(), now + Duration::milliseconds(51)).is_err()
    );
}

#[test]
fn query_and_page_revision_order_cursor_and_ownership_are_enforced() {
    for limit in [0, 101] {
        assert!(query(limit).validate().is_err());
    }
    let mut cursor = query(2);
    cursor.after = Some(reference("installation", 1));
    cursor.revision = None;
    assert!(cursor.validate().is_err());
    let now = Utc::now();
    let mut value = page();
    value["projection"]["inventory_revision"] = json!(2);
    assert!(decode_application_page(&value.to_string(), &query(2), now).is_err());
    let mut value = page();
    value["projection"]["next_cursor"] = Value::Null;
    assert!(decode_application_page(&value.to_string(), &query(2), now).is_err());
    let mut value = page();
    value["projection"]["applications"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(decode_application_page(&value.to_string(), &query(2), now).is_err());
    let mut value = page();
    value["projection"]["applications"][1] = value["projection"]["applications"][0].clone();
    assert!(decode_application_page(&value.to_string(), &query(2), now).is_err());
    let mut value = page();
    value["projection"]["applications"][0]["record"]["identity"]["owner_uid"] =
        json!(rustix::process::getuid().as_raw() + 1);
    assert!(decode_application_page(&value.to_string(), &query(2), now).is_err());
}

#[test]
fn detail_matches_the_requested_installation_without_inferring_absence_as_safety() {
    let reference = reference("installation", 1);
    let value = envelope(&json!(ApplicationLookup {
        schema: APPLICATION_SECURITY_SCHEMA.into(),
        application: Some(app(1))
    }));
    assert!(decode_application_detail(&value.to_string(), &reference, Utc::now()).is_ok());
    assert!(
        decode_application_detail(
            &value.to_string(),
            &self::reference("installation", 2),
            Utc::now()
        )
        .is_err()
    );
    let value = envelope(&json!(ApplicationLookup {
        schema: APPLICATION_SECURITY_SCHEMA.into(),
        application: None
    }));
    assert!(
        decode_application_detail(&value.to_string(), &reference, Utc::now())
            .unwrap()
            .projection
            .unwrap()
            .application
            .is_none()
    );
}

#[test]
fn unavailable_transport_has_no_projection_and_no_fresh_protection_lease() {
    let now = Utc::now();
    let mut value = json!({"schema":APPLICATION_SECURITY_SCHEMA,
        "source_state":{"state":"UNAVAILABLE","reason":"BROKER_UNAVAILABLE"},
        "observed_at":now,"fresh_until":now,"projection":null});
    assert!(
        decode_application_coverage(&value.to_string(), now)
            .unwrap()
            .projection
            .is_none()
    );
    value["source_state"]["reason"] = json!("/private/untrusted/path");
    assert!(decode_application_coverage(&value.to_string(), now).is_err());
    value["source_state"]["reason"] = json!("BROKER_UNAVAILABLE");
    value["projection"] = coverage()["projection"].clone();
    assert!(decode_application_coverage(&value.to_string(), now).is_err());
}

#[test]
fn malformed_generations_unknown_fields_duplicates_and_oversized_responses_fail_closed() {
    let mut value = page();
    value["projection"]["applications"][0]["record"]["identity"]["generation"] =
        json!("A".repeat(64));
    assert!(decode_application_page(&value.to_string(), &query(2), Utc::now()).is_err());
    let mut value = coverage();
    value["command"] = json!("unreviewed");
    assert!(decode_application_coverage(&value.to_string(), Utc::now()).is_err());
    let raw = coverage()
        .to_string()
        .replacen('{', "{\"schema\":\"duplicate\",", 1);
    assert!(decode_application_coverage(&raw, Utc::now()).is_err());
    assert!(
        decode_application_coverage(&"x".repeat(MAX_APPLICATION_READ_BYTES + 1), Utc::now())
            .is_err()
    );
}
