//! One policy/operational database, never a second event history.
//! Provider collection and peer authorization belong to the broker boundary.
use crate::{ApplicationRegistry, InventoryChange, MAX_APPLICATIONS, RegistryEntry, RegistryError};
use greyward_security_domain::{ApplicationIdentity, SecurityReference};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

const SYSTEM_DATABASE: &str = "/var/lib/greyward/application-security/policy.sqlite3";
const SCHEMA_VERSION: u32 = 4;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Policy storage requires a root-owned private directory and file")]
    UnsafeStorage,
    #[error("Unsupported policy database schema")]
    UnsupportedSchema,
    #[error("Policy database is corrupt or inconsistent")]
    Corrupt,
    #[error("Policy inventory revision changed")]
    StaleRevision,
    #[error("Invalid, foreign, conflicting or unsupported desired policy change")]
    InvalidPolicyIntent,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

pub struct PolicyStore {
    pub(crate) connection: Connection,
    pub(crate) production: bool,
    pub(crate) live_resources: std::collections::BTreeMap<
        SecurityReference,
        crate::resource_labeling::LiveRegisteredDirectory,
    >,
}

impl PolicyStore {
    /// Open the single installed database. The package creates its directory.
    /// # Errors
    /// Refuses non-root callers, symlinks, writable parents and incompatible data.
    pub fn open_system() -> Result<Self, StoreError> {
        Self::open_private(Path::new(SYSTEM_DATABASE))
    }

    /// Fixed root-owned development fixture; no caller path override and no
    /// production fallback. This is never exposed through the installed broker.
    /// # Errors
    /// Uses the same ownership, transaction and corruption checks as production.
    #[doc(hidden)]
    pub fn open_development_registration_probe() -> Result<Self, StoreError> {
        Self::open_private(Path::new(
            "/var/lib/greyward-development/application-security/registration-critical/policy.sqlite3",
        ))
    }

    // No public path override. Private test fixtures exercise the same ownership
    // checks without writing the production database or installing a daemon.
    fn open_private(path: &Path) -> Result<Self, StoreError> {
        if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
            return Err(StoreError::UnsafeStorage);
        }
        for directory in path.parent().ok_or(StoreError::UnsafeStorage)?.ancestors() {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(StoreError::UnsafeStorage);
            }
        }
        if fs::metadata(path.parent().ok_or(StoreError::UnsafeStorage)?)?.mode() & 0o777 != 0o700 {
            return Err(StoreError::UnsafeStorage);
        }
        let created = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => {
                file.sync_all()?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.into()),
        };
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(StoreError::UnsafeStorage);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        if path == Path::new(SYSTEM_DATABASE) && !created {
            // Production schema activation belongs to the offline lifecycle
            // coordinator after a verified rollback snapshot. Opening the read
            // broker must never silently make an older package's database
            // incompatible. That coordinator is not activated in this source.
            require_current_production_schema(&connection)?;
        }
        Self::initialize(connection, created).and_then(|mut store| {
            store.production = path == Path::new(SYSTEM_DATABASE);
            store.reopen_registered_directories()?;
            Ok(store)
        })
    }

    /// Isolated store for tests; never used as a production fallback.
    /// # Errors
    /// Reports SQLite initialization errors rather than an empty safe inventory.
    pub fn isolated_memory() -> Result<Self, StoreError> {
        Self::initialize(Connection::open_in_memory()?, true)
    }

    fn initialize(mut connection: Connection, created: bool) -> Result<Self, StoreError> {
        connection.busy_timeout(Duration::from_millis(250))?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        // A truncated existing database or interrupted initial creation needs
        // explicit recovery, never automatic replacement with an empty policy.
        if version == 0 && !created {
            return Err(StoreError::Corrupt);
        }
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;
            PRAGMA temp_store=MEMORY; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            PRAGMA secure_delete=ON;",
        )?;
        if version == 0 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch("CREATE TABLE metadata (
                id INTEGER PRIMARY KEY CHECK(id=1), inventory_revision INTEGER NOT NULL CHECK(inventory_revision>=0),
                policy_revision INTEGER NOT NULL CHECK(policy_revision>=1));
                INSERT INTO metadata VALUES(1,0,1);
                CREATE TABLE applications (installation_ref TEXT PRIMARY KEY, owner_uid INTEGER NOT NULL,
                entry_json TEXT NOT NULL CHECK(length(entry_json)<=8192));
                PRAGMA user_version=1;")?;
            transaction.commit()?;
        } else if version > SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema);
        }
        crate::store_intent::migrate(&mut connection)?;
        crate::resource_labeling::migrate(&mut connection)?;
        crate::enrollment::migrate(&mut connection)?;
        let store = Self {
            live_resources: std::collections::BTreeMap::new(),
            connection,
            production: false,
        };
        store.registry()?;
        store.desired_policy()?;
        Ok(store)
    }

    /// # Errors
    /// Reports corrupt/missing revision state.
    pub fn inventory_revision(&self) -> Result<u64, StoreError> {
        Ok(self.connection.query_row(
            "SELECT inventory_revision FROM metadata WHERE id=1",
            [],
            |row| row.get(0),
        )?)
    }

    fn registry(&self) -> Result<ApplicationRegistry, StoreError> {
        Self::read_registry(&self.connection)
    }

    pub(crate) fn read_registry(
        connection: &Connection,
    ) -> Result<ApplicationRegistry, StoreError> {
        let count: usize =
            connection.query_row("SELECT count(*) FROM applications", [], |row| row.get(0))?;
        if count > MAX_APPLICATIONS {
            return Err(StoreError::Corrupt);
        }
        let mut statement =
            connection.prepare("SELECT installation_ref,owner_uid,entry_json FROM applications")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut entries = Vec::with_capacity(count);
        for row in rows {
            let (reference, uid, encoded) = row?;
            if encoded.len() > 8192 {
                return Err(StoreError::Corrupt);
            }
            let entry: RegistryEntry =
                serde_json::from_str(&encoded).map_err(|_| StoreError::Corrupt)?;
            if entry.identity.installation_ref.as_str() != reference
                || entry.identity.owner_uid != uid
            {
                return Err(StoreError::Corrupt);
            }
            entries.push(entry);
        }
        let revision: u64 = connection.query_row(
            "SELECT inventory_revision FROM metadata WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        Ok(ApplicationRegistry::restore(entries, revision)?)
    }

    /// A complete owner inventory, committed atomically with its revision.
    /// # Errors
    /// Rejects stale/concurrent, invalid or oversized updates without mutation.
    pub fn reconcile_applications(
        &mut self,
        owner_uid: u32,
        identities: Vec<ApplicationIdentity>,
        expected_revision: u64,
        now: u64,
    ) -> Result<Vec<InventoryChange>, StoreError> {
        self.reconcile_scope(owner_uid, (None, true), identities, expected_revision, now)
    }

    /// A provider refresh cannot erase other providers. Incomplete discovery
    /// never means uninstall; removals require a complete provider inventory.
    /// # Errors
    /// Rejects stale revisions, conflicting identities and invalid batches.
    pub fn reconcile_provider(
        &mut self,
        owner_uid: u32,
        provider: greyward_security_domain::ApplicationProvider,
        identities: Vec<ApplicationIdentity>,
        complete: bool,
        expected_revision: u64,
        now: u64,
    ) -> Result<Vec<InventoryChange>, StoreError> {
        self.reconcile_scope(
            owner_uid,
            (Some(provider), complete),
            identities,
            expected_revision,
            now,
        )
    }

    fn reconcile_scope(
        &mut self,
        owner_uid: u32,
        scope: (Option<greyward_security_domain::ApplicationProvider>, bool),
        identities: Vec<ApplicationIdentity>,
        expected_revision: u64,
        now: u64,
    ) -> Result<Vec<InventoryChange>, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let observed: u64 = transaction.query_row(
            "SELECT inventory_revision FROM metadata WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        if observed != expected_revision {
            return Err(StoreError::StaleRevision);
        }
        // The transaction owns the same connection. Decode once while holding
        // the write lock, and validate before replacing any row.
        let mut registry = Self::read_registry(&transaction)?;
        let changes = registry.reconcile_scope(owner_uid, scope.0, identities, scope.1, now)?;
        transaction.execute("DELETE FROM applications WHERE owner_uid=?1", [owner_uid])?;
        // Pagination is also used internally: no owner loses records after 100.
        let mut cursor: Option<SecurityReference> = None;
        loop {
            let page = registry.list(owner_uid, cursor.as_ref(), 100);
            if page.is_empty() {
                break;
            }
            for entry in &page {
                let encoded = serde_json::to_string(entry).map_err(|_| StoreError::Corrupt)?;
                transaction.execute(
                    "INSERT INTO applications VALUES(?1,?2,?3)",
                    rusqlite::params![entry.identity.installation_ref.as_str(), owner_uid, encoded],
                )?;
            }
            cursor = page
                .last()
                .map(|entry| entry.identity.installation_ref.clone());
        }
        transaction.execute(
            "UPDATE metadata SET inventory_revision=?1 WHERE id=1",
            [registry.revision()],
        )?;
        transaction.commit()?;
        Ok(changes)
    }

    /// # Errors
    /// Corrupt database content remains unavailable, never an empty safe result.
    pub fn list_applications(
        &self,
        owner_uid: u32,
        after: Option<&SecurityReference>,
        limit: usize,
    ) -> Result<Vec<RegistryEntry>, StoreError> {
        let registry = self.registry()?;
        Ok(registry
            .list(owner_uid, after, limit)
            .into_iter()
            .cloned()
            .collect())
    }

    /// # Errors
    /// Invalid storage remains an error. Unknown and other-owner records are
    /// indistinguishable; the broker derives `owner_uid` from its kernel-bound peer.
    pub fn get_application(
        &self,
        owner_uid: u32,
        reference: &SecurityReference,
    ) -> Result<Option<RegistryEntry>, StoreError> {
        Ok(self.registry()?.get(owner_uid, reference).cloned())
    }
}

fn require_current_production_schema(connection: &Connection) -> Result<(), StoreError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema);
    }
    Ok(())
}

#[cfg(test)]
mod enrollment_schema_tests {
    use super::*;

    #[test]
    fn opening_an_older_production_schema_cannot_mutate_or_discard_rollback_inputs() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE retained_policy (value TEXT); INSERT INTO retained_policy VALUES('retained'); PRAGMA user_version=3;")
            .unwrap();
        assert!(matches!(
            require_current_production_schema(&connection),
            Err(StoreError::UnsupportedSchema)
        ));
        assert_eq!(
            connection
                .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            3
        );
        assert_eq!(
            connection
                .query_row::<String, _, _>("SELECT value FROM retained_policy", [], |row| row
                    .get(0))
                .unwrap(),
            "retained"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_schema_is_refused_without_downgrading_it() {
        let connection = Connection::open_in_memory().unwrap();
        connection.pragma_update(None, "user_version", 5).unwrap();
        assert!(matches!(
            PolicyStore::initialize(connection, false),
            Err(StoreError::UnsupportedSchema)
        ));
    }

    #[test]
    fn mismatched_owner_columns_are_not_silently_repaired() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let identity = crate::IdentitySeed {
            provider: greyward_security_domain::ApplicationProvider::Manual,
            logical_id: "test".into(),
            installation_id: "managed".into(),
            source_id: "unknown".into(),
            owner_uid: 1000,
        }
        .identity(crate::content_generation(b"code"))
        .unwrap();
        store
            .reconcile_applications(1000, vec![identity], 0, 10)
            .unwrap();
        store
            .connection
            .execute("UPDATE applications SET owner_uid=1001", [])
            .unwrap();
        assert!(matches!(
            store.list_applications(1000, None, 10),
            Err(StoreError::Corrupt)
        ));
        assert!(matches!(
            store.reconcile_applications(1000, vec![], 1, 20),
            Err(StoreError::Corrupt)
        ));
        assert_eq!(store.inventory_revision().unwrap(), 1);
    }

    #[test]
    fn incompatible_initial_schema_leaves_migration_version_uncommitted() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE applications (bad TEXT);")
            .unwrap();
        assert!(PolicyStore::initialize(connection, true).is_err());
    }

    #[test]
    fn an_existing_zero_schema_database_does_not_become_empty_safe_policy() {
        let connection = Connection::open_in_memory().unwrap();
        assert!(matches!(
            PolicyStore::initialize(connection, false),
            Err(StoreError::Corrupt)
        ));
    }

    #[test]
    #[ignore = "Requires root and the private development receipt directory; never opens production storage"]
    fn root_filesystem_store_rejects_unsafe_owners_modes_links_and_corruption() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
        assert_eq!(rustix::process::getuid().as_raw(), 0);
        let base = Path::new("/var/lib/greyward-development/application-security");
        let metadata = fs::symlink_metadata(base).unwrap();
        assert!(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o777 == 0o700);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = base.join(format!("storage-probe-{}-{unique}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("policy.sqlite3");
        let store = PolicyStore::open_private(&path).unwrap();
        assert_eq!(store.inventory_revision().unwrap(), 0);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        drop(store);
        filesystem_intent_roundtrip(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            PolicyStore::open_private(&path),
            Err(StoreError::UnsafeStorage)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        rustix::fs::chown(&path, Some(rustix::process::Uid::from_raw(1002)), None).unwrap();
        assert!(matches!(
            PolicyStore::open_private(&path),
            Err(StoreError::UnsafeStorage)
        ));
        rustix::fs::chown(&path, Some(rustix::process::Uid::ROOT), None).unwrap();
        let alias = directory.join("hardlink.sqlite3");
        fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(
            PolicyStore::open_private(&path),
            Err(StoreError::UnsafeStorage)
        ));
        fs::remove_file(&alias).unwrap();
        symlink(&path, &alias).unwrap();
        assert!(matches!(
            PolicyStore::open_private(&alias),
            Err(StoreError::UnsafeStorage)
        ));
        fs::remove_file(&alias).unwrap();
        let parent_alias = directory.join("parent-alias");
        symlink(&directory, &parent_alias).unwrap();
        assert!(matches!(
            PolicyStore::open_private(&parent_alias.join("policy.sqlite3")),
            Err(StoreError::UnsafeStorage)
        ));
        fs::remove_file(&parent_alias).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            PolicyStore::open_private(&path),
            Err(StoreError::UnsafeStorage)
        ));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(PolicyStore::open_private(&path).is_ok());
        fs::write(&path, b"invalid database fixture").unwrap();
        assert!(PolicyStore::open_private(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"invalid database fixture");
        fs::write(&path, b"").unwrap();
        assert!(matches!(
            PolicyStore::open_private(&path),
            Err(StoreError::Corrupt)
        ));
        assert!(fs::read(&path).unwrap().is_empty());
        fs::remove_dir_all(&directory).unwrap();
    }

    fn filesystem_intent_roundtrip(path: &Path) {
        use crate::policy_intent::{IntentChange, ResourceIntent};
        use crate::resource_selection::DirectoryObjectReceipt;
        use greyward_security_domain::{
            ExecutionIdentity, ProtectedCategory, ProtectedResource, ResourceCoverage,
        };
        // Synthetic review identity tests storage only. The real fresh-Polkit
        // path is exercised independently by system_bus_authorization.
        let reference =
            |kind: &str| SecurityReference::try_from(format!("{kind}_{}", "a".repeat(64))).unwrap();
        let record = ResourceIntent {
            resource: ProtectedResource {
                resource_ref: reference("resource"),
                owner_uid: 1002,
                category: ProtectedCategory::Custom,
                label: "Synthetic storage object".into(),
                coverage: ResourceCoverage::Unknown,
                policy_revision: 2,
            },
            object: DirectoryObjectReceipt {
                device: 1,
                inode: 1,
                owner_uid: 1002,
                changed_seconds: 1,
                changed_nanoseconds: 0,
            },
            reviewed_by: ExecutionIdentity {
                execution_ref: reference("execution"),
                installation_ref: None,
                owner_uid: 1002,
                boot_id: "12345678-1234-1234-1234-123456789abc".into(),
                pid: 42,
                start_ticks: 100,
                selinux_context: "user_u:user_r:user_t:s0".into(),
            },
            operation_ref: reference("operation"),
        };
        let mut first = PolicyStore::open_private(path).unwrap();
        let mut second = PolicyStore::open_private(path).unwrap();
        first
            .commit_intent_change(1002, 1, &IntentChange::Register(record.clone()))
            .unwrap();
        assert!(matches!(
            second.commit_intent_change(
                1002,
                1,
                &IntentChange::RemoveCustomResource(reference("resource"))
            ),
            Err(StoreError::StaleRevision)
        ));
        drop(first);
        drop(second);
        let mut reopened = PolicyStore::open_private(path).unwrap();
        let state = reopened.desired_policy().unwrap();
        assert_eq!(state.revision, 2);
        assert_eq!(state.resources, vec![record]);
        assert!(state.grants.is_empty());
        reopened
            .commit_intent_change(
                1002,
                2,
                &IntentChange::RemoveCustomResource(reference("resource")),
            )
            .unwrap();
        drop(reopened);
        let final_store = PolicyStore::open_private(path).unwrap();
        assert_eq!(final_store.desired_policy().unwrap().revision, 3);
        assert!(final_store.desired_policy().unwrap().resources.is_empty());
    }
}
