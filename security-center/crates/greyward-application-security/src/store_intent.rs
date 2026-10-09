//! Schema-two desired policy storage. SQL commits never establish kernel access.
use crate::policy_intent::{DesiredPolicyState, GrantIntent, IntentChange, ResourceIntent};
use crate::{MAX_POLICY_GRANTS, MAX_POLICY_RESOURCES, PolicyStore, StoreError};
use greyward_security_domain::ProtectedCategory;
use rusqlite::{Connection, TransactionBehavior};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

const MAX_INTENT_BYTES: usize = 16_384;

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        PolicyStore::read_registry(&transaction)?;
        let revision: u64 = transaction.query_row(
            "SELECT policy_revision FROM metadata WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        if revision == 0 {
            return Err(StoreError::Corrupt);
        }
        transaction.execute_batch(
            "CREATE TABLE resource_intents (
                resource_ref TEXT PRIMARY KEY, owner_uid INTEGER NOT NULL,
                record_json TEXT NOT NULL CHECK(length(record_json)<=16384));
             CREATE TABLE grant_intents (
                grant_ref TEXT PRIMARY KEY, owner_uid INTEGER NOT NULL,
                record_json TEXT NOT NULL CHECK(length(record_json)<=16384));
             PRAGMA user_version=2;",
        )?;
        transaction.commit()?;
    } else if ![2, 3, 4].contains(&version) {
        return Err(StoreError::UnsupportedSchema);
    }
    Ok(())
}

fn decode<T: DeserializeOwned>(encoded: &str) -> Result<T, StoreError> {
    if encoded.len() > MAX_INTENT_BYTES {
        return Err(StoreError::Corrupt);
    }
    serde_json::from_str(encoded).map_err(|_| StoreError::Corrupt)
}

fn encode<T: Serialize>(value: &T) -> Result<String, StoreError> {
    let encoded = serde_json::to_string(value).map_err(|_| StoreError::Corrupt)?;
    if encoded.len() > MAX_INTENT_BYTES {
        return Err(StoreError::InvalidPolicyIntent);
    }
    Ok(encoded)
}

fn read_state(connection: &Connection) -> Result<DesiredPolicyState, StoreError> {
    let revision: u64 = connection.query_row(
        "SELECT policy_revision FROM metadata WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    if revision == 0 {
        return Err(StoreError::Corrupt);
    }
    let resource_count: usize =
        connection.query_row("SELECT count(*) FROM resource_intents", [], |row| {
            row.get(0)
        })?;
    let grant_count: usize =
        connection.query_row("SELECT count(*) FROM grant_intents", [], |row| row.get(0))?;
    if resource_count > MAX_POLICY_RESOURCES || grant_count > MAX_POLICY_GRANTS {
        return Err(StoreError::Corrupt);
    }
    let mut resources = Vec::with_capacity(resource_count);
    let mut statement = connection.prepare(
        "SELECT resource_ref,owner_uid,record_json FROM resource_intents ORDER BY resource_ref",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (reference, uid, encoded) = row?;
        let record: ResourceIntent = decode(&encoded)?;
        if !record.validate(revision)
            || record.resource.resource_ref.as_str() != reference
            || record.resource.owner_uid != uid
        {
            return Err(StoreError::Corrupt);
        }
        resources.push(record);
    }
    let mut grants = Vec::with_capacity(grant_count);
    let mut statement = connection
        .prepare("SELECT grant_ref,owner_uid,record_json FROM grant_intents ORDER BY grant_ref")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (reference, uid, encoded) = row?;
        let record: GrantIntent = decode(&encoded)?;
        if !record.validate(revision)
            || record.grant.grant_ref.as_str() != reference
            || record.grant.owner_uid != uid
        {
            return Err(StoreError::Corrupt);
        }
        grants.push(record);
    }
    let state = DesiredPolicyState {
        revision,
        resources,
        grants,
    };
    validate_relations(&state)?;
    Ok(state)
}

fn validate_relations(state: &DesiredPolicyState) -> Result<(), StoreError> {
    let resources: BTreeMap<_, _> = state
        .resources
        .iter()
        .map(|record| (&record.resource.resource_ref, record.resource.owner_uid))
        .collect();
    let mut objects = BTreeSet::new();
    for record in &state.resources {
        if !objects.insert((
            &record.reviewed_by.boot_id,
            record.object.device,
            record.object.inode,
            record.object.owner_uid,
        )) {
            return Err(StoreError::Corrupt);
        }
    }
    let mut counts = BTreeMap::new();
    for record in &state.grants {
        let count = counts
            .entry(&record.grant.installation_ref)
            .or_insert(0usize);
        *count += 1;
        if *count > 32
            || record
                .grant
                .resources
                .iter()
                .any(|reference| resources.get(reference) != Some(&record.grant.owner_uid))
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

fn validate_change(
    connection: &Connection,
    owner_uid: u32,
    expected: u64,
    change: &IntentChange,
) -> Result<u64, StoreError> {
    let state = read_state(connection)?;
    if state.revision != expected {
        return Err(StoreError::StaleRevision);
    }
    let next = expected
        .checked_add(1)
        .filter(|value| i64::try_from(*value).is_ok())
        .ok_or(StoreError::InvalidPolicyIntent)?;
    let valid = match change {
        IntentChange::Register(record) => {
            record.validate(next)
                && record.resource.owner_uid == owner_uid
                && record.resource.policy_revision == next
                && state.resources.len() < MAX_POLICY_RESOURCES
                && !state.resources.iter().any(|existing| {
                    existing.resource.resource_ref == record.resource.resource_ref
                        || (existing.reviewed_by.boot_id == record.reviewed_by.boot_id
                            && existing.object.device == record.object.device
                            && existing.object.inode == record.object.inode
                            && existing.object.owner_uid == record.object.owner_uid)
                })
                && encode(record).is_ok()
        }
        IntentChange::ProposeGrant(record) => {
            let registry = PolicyStore::read_registry(connection)?;
            record.validate(next)
                && record.grant.owner_uid == owner_uid
                && record.grant.policy_revision == next
                && registry
                    .get(owner_uid, &record.grant.installation_ref)
                    .is_some_and(|entry| entry.identity == record.installation)
                && state.grants.len() < MAX_POLICY_GRANTS
                && state
                    .grants
                    .iter()
                    .filter(|existing| {
                        existing.grant.installation_ref == record.grant.installation_ref
                    })
                    .count()
                    < 32
                && !state
                    .grants
                    .iter()
                    .any(|existing| existing.grant.grant_ref == record.grant.grant_ref)
                && record.grant.resources.iter().all(|reference| {
                    state.resources.iter().any(|resource| {
                        &resource.resource.resource_ref == reference
                            && resource.resource.owner_uid == owner_uid
                    })
                })
                && encode(record).is_ok()
        }
        IntentChange::RevokeGrant(reference) => {
            reference.namespace() == "grant"
                && state.grants.iter().any(|existing| {
                    &existing.grant.grant_ref == reference && existing.grant.owner_uid == owner_uid
                })
        }
        IntentChange::RemoveCustomResource(reference) => {
            reference.namespace() == "resource"
                && state.resources.iter().any(|existing| {
                    &existing.resource.resource_ref == reference
                        && existing.resource.owner_uid == owner_uid
                        && existing.resource.category == ProtectedCategory::Custom
                })
                && !state
                    .grants
                    .iter()
                    .any(|grant| grant.grant.resources.contains(reference))
        }
    };
    if !valid {
        return Err(StoreError::InvalidPolicyIntent);
    }
    Ok(next)
}

impl PolicyStore {
    /// Read root-owned intentions, including stale generation reviews. They
    /// never establish current coverage, active access or revocation readback.
    /// # Errors
    /// Corrupt, foreign, oversized or false-protection records remain unavailable.
    pub fn desired_policy(&self) -> Result<DesiredPolicyState, StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let state = read_state(&transaction)?;
        transaction.commit()?;
        Ok(state)
    }

    pub(crate) fn validate_intent_change(
        &self,
        owner_uid: u32,
        expected: u64,
        change: &IntentChange,
    ) -> Result<(), StoreError> {
        validate_change(&self.connection, owner_uid, expected, change).map(|_| ())
    }

    // Only PolicyIntentReview can reach this after consuming fresh authorization.
    // Unit tests below bypass transport to exercise transactional storage faults.
    pub(crate) fn commit_intent_change(
        &mut self,
        owner_uid: u32,
        expected: u64,
        change: &IntentChange,
    ) -> Result<u64, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let next = validate_change(&transaction, owner_uid, expected, change)?;
        match change {
            IntentChange::Register(record) => {
                transaction.execute(
                    "INSERT INTO resource_intents VALUES(?1,?2,?3)",
                    rusqlite::params![
                        record.resource.resource_ref.as_str(),
                        owner_uid,
                        encode(record)?
                    ],
                )?;
            }
            IntentChange::ProposeGrant(record) => {
                transaction.execute(
                    "INSERT INTO grant_intents VALUES(?1,?2,?3)",
                    rusqlite::params![record.grant.grant_ref.as_str(), owner_uid, encode(record)?],
                )?;
            }
            IntentChange::RevokeGrant(reference) => {
                transaction.execute(
                    "DELETE FROM grant_intents WHERE grant_ref=?1 AND owner_uid=?2",
                    rusqlite::params![reference.as_str(), owner_uid],
                )?;
            }
            IntentChange::RemoveCustomResource(reference) => {
                transaction.execute(
                    "DELETE FROM resource_intents WHERE resource_ref=?1 AND owner_uid=?2",
                    rusqlite::params![reference.as_str(), owner_uid],
                )?;
            }
        }
        transaction.execute("UPDATE metadata SET policy_revision=?1 WHERE id=1", [next])?;
        let readback = read_state(&transaction)?;
        if readback.revision != next {
            return Err(StoreError::Corrupt);
        }
        transaction.commit()?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_selection::DirectoryObjectReceipt;
    use crate::{IdentitySeed, content_generation};
    use greyward_security_domain::{
        AccessGrant, ApplicationIdentity, ApplicationProvider, ExecutionIdentity, GrantLifetime,
        ProtectedResource, ResourceAccess, ResourceCoverage, SecurityReference,
    };

    fn reference(namespace: &str, number: u64) -> SecurityReference {
        SecurityReference::try_from(format!("{namespace}_{number:064x}")).unwrap()
    }

    fn actor(uid: u32) -> ExecutionIdentity {
        ExecutionIdentity {
            execution_ref: reference("execution", 1),
            installation_ref: None,
            owner_uid: uid,
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            pid: 42,
            start_ticks: 100,
            selinux_context: "user_u:user_r:user_t:s0".into(),
        }
    }

    fn resource(uid: u32, number: u64, revision: u64) -> ResourceIntent {
        ResourceIntent {
            resource: ProtectedResource {
                resource_ref: reference("resource", number),
                owner_uid: uid,
                category: ProtectedCategory::Custom,
                label: "Synthetic resource".into(),
                coverage: ResourceCoverage::Unknown,
                policy_revision: revision,
            },
            object: DirectoryObjectReceipt {
                device: 1,
                inode: number,
                owner_uid: uid,
                changed_seconds: 100,
                changed_nanoseconds: 0,
            },
            reviewed_by: actor(uid),
            operation_ref: reference("operation", number),
        }
    }

    fn install(store: &mut PolicyStore, uid: u32, content: &[u8]) -> ApplicationIdentity {
        let identity = IdentitySeed {
            provider: ApplicationProvider::Manual,
            logical_id: "reviewed-tool".into(),
            installation_id: "managed".into(),
            source_id: "unknown".into(),
            owner_uid: uid,
        }
        .identity(content_generation(content))
        .unwrap();
        store
            .reconcile_applications(
                uid,
                vec![identity.clone()],
                store.inventory_revision().unwrap(),
                10,
            )
            .unwrap();
        identity
    }

    fn grant(installation: ApplicationIdentity, revision: u64) -> GrantIntent {
        GrantIntent {
            grant: AccessGrant {
                grant_ref: reference("grant", 1),
                owner_uid: installation.owner_uid,
                installation_ref: installation.installation_ref.clone(),
                generation: installation.generation.clone(),
                resources: vec![reference("resource", 1)],
                access: vec![ResourceAccess::Read],
                lifetime: GrantLifetime::Persistent,
                policy_revision: revision,
            },
            reviewed_by: actor(installation.owner_uid),
            installation,
            operation_ref: reference("operation", 3),
            tool_profile: None,
        }
    }

    #[test]
    fn schema_one_migration_retains_inventory_and_both_revisions() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let identity = install(&mut store, 1000, b"original");
        store.connection.execute_batch("DROP TABLE grant_intents; DROP TABLE resource_intents; PRAGMA user_version=1; UPDATE metadata SET policy_revision=7;").unwrap();
        migrate(&mut store.connection).unwrap();
        assert_eq!(store.inventory_revision().unwrap(), 1);
        assert_eq!(store.desired_policy().unwrap().revision, 7);
        assert_eq!(
            store
                .get_application(1000, &identity.installation_ref)
                .unwrap()
                .unwrap()
                .identity,
            identity
        );
        assert_eq!(
            store
                .connection
                .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn failed_migration_does_not_commit_a_partial_table_or_new_version() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA user_version=1;
            CREATE TABLE metadata (id INTEGER PRIMARY KEY,inventory_revision INTEGER,policy_revision INTEGER);
            INSERT INTO metadata VALUES(1,0,1);
            CREATE TABLE applications (installation_ref TEXT PRIMARY KEY,owner_uid INTEGER,entry_json TEXT);
            CREATE TABLE grant_intents (sentinel INTEGER); INSERT INTO grant_intents VALUES(42);").unwrap();
        assert!(migrate(&mut connection).is_err());
        assert_eq!(
            connection
                .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row::<u32, _, _>("SELECT sentinel FROM grant_intents", [], |row| row.get(0))
                .unwrap(),
            42
        );
        assert_eq!(
            connection
                .query_row::<u32, _, _>(
                    "SELECT count(*) FROM sqlite_master WHERE name='resource_intents'",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn intent_transactions_keep_coverage_unknown_and_inventory_independent() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let identity = install(&mut store, 1000, b"original");
        assert_eq!(
            store
                .commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 1, 2)))
                .unwrap(),
            2
        );
        let proposal = grant(identity, 3);
        assert_eq!(
            store
                .commit_intent_change(1000, 2, &IntentChange::ProposeGrant(proposal.clone()))
                .unwrap(),
            3
        );
        let state = store.desired_policy().unwrap();
        assert_eq!(
            state.resources[0].resource.coverage,
            ResourceCoverage::Unknown
        );
        assert_eq!(state.grants[0], proposal);
        assert_eq!(store.inventory_revision().unwrap(), 1);
        assert_eq!(
            store
                .commit_intent_change(1000, 3, &IntentChange::RevokeGrant(reference("grant", 1)))
                .unwrap(),
            4
        );
        assert!(store.desired_policy().unwrap().grants.is_empty());
    }

    #[test]
    fn corrupt_old_inventory_cannot_be_committed_as_a_new_schema() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        install(&mut store, 1000, b"original");
        store
            .connection
            .execute_batch(
                "DROP TABLE grant_intents; DROP TABLE resource_intents;
            PRAGMA user_version=1; UPDATE applications SET owner_uid=1001;",
            )
            .unwrap();
        assert!(matches!(
            migrate(&mut store.connection),
            Err(StoreError::Corrupt)
        ));
        assert_eq!(
            store
                .connection
                .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .connection
                .query_row::<u32, _, _>("SELECT owner_uid FROM applications", [], |row| row.get(0))
                .unwrap(),
            1001
        );
        assert_eq!(store.inventory_revision().unwrap(), 1);
    }

    #[test]
    fn stale_generation_or_revision_cannot_commit_new_intentions() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let old = install(&mut store, 1000, b"old");
        store
            .commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 1, 2)))
            .unwrap();
        let proposal = grant(old, 3);
        install(&mut store, 1000, b"new");
        assert!(matches!(
            store.commit_intent_change(1000, 2, &IntentChange::ProposeGrant(proposal)),
            Err(StoreError::InvalidPolicyIntent)
        ));
        assert!(matches!(
            store.commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 2, 3))),
            Err(StoreError::StaleRevision)
        ));
        assert_eq!(store.desired_policy().unwrap().revision, 2);
        assert!(store.desired_policy().unwrap().grants.is_empty());
    }

    #[test]
    fn old_reviews_remain_visible_without_transferring_to_updated_code() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let old = install(&mut store, 1000, b"old");
        store
            .commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 1, 2)))
            .unwrap();
        store
            .commit_intent_change(1000, 2, &IntentChange::ProposeGrant(grant(old.clone(), 3)))
            .unwrap();
        let new = install(&mut store, 1000, b"new");
        let state = store.desired_policy().unwrap();
        assert_eq!(state.grants[0].installation, old);
        assert_ne!(state.grants[0].grant.generation, new.generation);
        assert_eq!(state.revision, 3);
    }

    #[test]
    fn foreign_objects_and_timed_or_false_protection_records_are_refused() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let identity = install(&mut store, 1000, b"code");
        assert!(
            store
                .commit_intent_change(1000, 1, &IntentChange::Register(resource(1001, 1, 2)))
                .is_err()
        );
        let mut protected = resource(1000, 1, 2);
        protected.resource.coverage = ResourceCoverage::Protected;
        assert!(
            store
                .commit_intent_change(1000, 1, &IntentChange::Register(protected))
                .is_err()
        );
        store
            .commit_intent_change(1001, 1, &IntentChange::Register(resource(1001, 1, 2)))
            .unwrap();
        assert!(
            store
                .commit_intent_change(
                    1000,
                    2,
                    &IntentChange::ProposeGrant(grant(identity.clone(), 3))
                )
                .is_err()
        );
        store
            .commit_intent_change(1000, 2, &IntentChange::Register(resource(1000, 2, 3)))
            .unwrap();
        let mut timed = grant(identity, 4);
        timed.grant.resources = vec![reference("resource", 2)];
        timed.grant.lifetime = GrantLifetime::ThisRun {
            execution_ref: reference("execution", 1),
        };
        assert!(
            store
                .commit_intent_change(1000, 3, &IntentChange::ProposeGrant(timed))
                .is_err()
        );
        assert_eq!(store.desired_policy().unwrap().revision, 3);
    }

    #[test]
    fn dependent_or_fixed_resources_require_a_separate_reviewed_path() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let identity = install(&mut store, 1000, b"code");
        store
            .commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 1, 2)))
            .unwrap();
        store
            .commit_intent_change(1000, 2, &IntentChange::ProposeGrant(grant(identity, 3)))
            .unwrap();
        assert!(
            store
                .commit_intent_change(
                    1000,
                    3,
                    &IntentChange::RemoveCustomResource(reference("resource", 1))
                )
                .is_err()
        );
        assert!(
            store
                .commit_intent_change(1001, 3, &IntentChange::RevokeGrant(reference("grant", 1)))
                .is_err()
        );
        store
            .commit_intent_change(1000, 3, &IntentChange::RevokeGrant(reference("grant", 1)))
            .unwrap();
        store
            .commit_intent_change(
                1000,
                4,
                &IntentChange::RemoveCustomResource(reference("resource", 1)),
            )
            .unwrap();
        let mut fixed = resource(1000, 2, 6);
        fixed.resource.category = ProtectedCategory::Credentials;
        store
            .commit_intent_change(1000, 5, &IntentChange::Register(fixed))
            .unwrap();
        assert!(
            store
                .commit_intent_change(
                    1000,
                    6,
                    &IntentChange::RemoveCustomResource(reference("resource", 2))
                )
                .is_err()
        );
    }

    #[test]
    fn storage_failure_rolls_back_record_and_revision_together() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        store.connection.execute_batch("CREATE TRIGGER deny_revision BEFORE UPDATE OF policy_revision ON metadata BEGIN SELECT RAISE(ABORT, 'synthetic storage fault'); END;").unwrap();
        assert!(
            store
                .commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 1, 2)))
                .is_err()
        );
        let state = store.desired_policy().unwrap();
        assert_eq!(state.revision, 1);
        assert!(state.resources.is_empty());
    }

    #[test]
    fn reused_object_and_corrupted_owner_or_coverage_never_become_safe_policy() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        store
            .commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 1, 2)))
            .unwrap();
        let mut alias = resource(1000, 2, 3);
        alias.object.inode = 1;
        assert!(
            store
                .commit_intent_change(1000, 2, &IntentChange::Register(alias))
                .is_err()
        );
        store
            .connection
            .execute("UPDATE resource_intents SET owner_uid=1001", [])
            .unwrap();
        assert!(matches!(store.desired_policy(), Err(StoreError::Corrupt)));
        store
            .connection
            .execute("UPDATE resource_intents SET owner_uid=1000", [])
            .unwrap();
        let mut corrupted = resource(1000, 1, 2);
        corrupted.resource.coverage = ResourceCoverage::Protected;
        store
            .connection
            .execute(
                "UPDATE resource_intents SET record_json=?1",
                [encode(&corrupted).unwrap()],
            )
            .unwrap();
        assert!(matches!(store.desired_policy(), Err(StoreError::Corrupt)));
    }

    #[test]
    fn resource_capacity_remains_bounded_at_two_thousand() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        {
            let transaction = store.connection.transaction().unwrap();
            for number in 1..=2000 {
                let record = resource(1000, number, 1);
                transaction
                    .execute(
                        "INSERT INTO resource_intents VALUES(?1,1000,?2)",
                        rusqlite::params![
                            record.resource.resource_ref.as_str(),
                            encode(&record).unwrap()
                        ],
                    )
                    .unwrap();
            }
            transaction.commit().unwrap();
        }
        assert_eq!(store.desired_policy().unwrap().resources.len(), 2000);
        assert!(
            store
                .commit_intent_change(1000, 1, &IntentChange::Register(resource(1000, 2001, 2)))
                .is_err()
        );
        assert_eq!(store.desired_policy().unwrap().revision, 1);
    }
}
