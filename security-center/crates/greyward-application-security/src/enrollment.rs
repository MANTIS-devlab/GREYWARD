//! Root-owned enrollment lifecycle in the existing policy database.
//! Enrollment metadata never establishes live coverage or an effective profile.
use crate::{PolicyStore, StoreError, content_generation};
use greyward_security_domain::{ContentGeneration, SecurityReference};
use rusqlite::{Connection, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const ENROLLMENT_SCHEMA: &str = "greyward.application-enrollment/v1";
const MAX_ACCOUNTS: usize = 256;
const ACCOUNT_ORIGINS: &str = "/var/lib/greyward/application-security/account-origins";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountOrigin {
    Installer,
    AccountManagement,
    ExplicitMigration,
}

/// Root-issued provenance for a deliberately selected local account. This is
/// admission input, never a protection receipt or a scan of all normal UIDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountOriginReceipt {
    pub schema: String,
    pub account: LocalAccount,
    pub origin: AccountOrigin,
}

impl AccountOriginReceipt {
    fn matches(&self, record: &EnrollmentRecord) -> bool {
        self.schema == "greyward.account-origin/v1"
            && self.account.validate()
            && self.account == record.account
            && self.origin == record.origin
    }

    /// Root's installer/account workflow selects exactly one local passwd
    /// record. Existing receipts cannot be replaced or transferred to a reused
    /// UID; migration/repair must reconcile them at its offline boundary.
    /// # Errors
    /// Non-root, unsafe ancestry, stale local identity or an existing receipt
    /// refuses. This does not change mappings, labels or running sessions.
    pub fn issue(account: LocalAccount, origin: AccountOrigin) -> Result<Self, StoreError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
            return Err(StoreError::UnsafeStorage);
        }
        account.revalidate_local()?;
        let parent = Path::new(ACCOUNT_ORIGINS);
        private_origin_directory(parent)?;
        let receipt = Self {
            schema: "greyward.account-origin/v1".into(),
            account,
            origin,
        };
        let data = serde_json::to_vec(&receipt).map_err(|_| StoreError::Corrupt)?;
        let temporary = parent.join(format!(
            ".{}.{}.pending",
            receipt.account.uid,
            std::process::id()
        ));
        let destination = parent.join(format!("{}.json", receipt.account.uid));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let result = (|| -> Result<(), StoreError> {
            file.write_all(&data)?;
            file.sync_all()?;
            // Publish complete bytes without replacing an existing UID receipt.
            // An interrupted extra link fails readback rather than transferring
            // authority; only offline reconciliation can repair that condition.
            std::fs::hard_link(&temporary, &destination)?;
            std::fs::remove_file(&temporary)?;
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        Ok(receipt)
    }
}

fn private_origin_directory(parent: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;
    for path in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(StoreError::UnsafeStorage);
        }
    }
    if std::fs::symlink_metadata(parent)?.mode() & 0o777 != 0o700 {
        return Err(StoreError::UnsafeStorage);
    }
    Ok(())
}

fn require_account_origin(record: &EnrollmentRecord) -> Result<(), StoreError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = Path::new(ACCOUNT_ORIGINS);
    private_origin_directory(parent)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent.join(format!("{}.json", record.account.uid)))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 16384
    {
        return Err(StoreError::UnsafeStorage);
    }
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    let receipt: AccountOriginReceipt =
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
    if !receipt.matches(record) {
        return Err(StoreError::InvalidPolicyIntent);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnrollmentPhase {
    Prepared,
    MappingApplied,
    PendingSession,
    Enrolled,
    RecoveryRequired,
    Unenrolled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAccount {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub generation: ContentGeneration,
}

impl LocalAccount {
    /// Local passwd records only. NSS/domain observations are never enrollment
    /// origins; unknown/system accounts and aliases cannot enter automatically.
    /// # Errors
    /// Refuses malformed, unsupported or ambiguous local account definitions.
    pub fn from_passwd(line: &str) -> Result<Self, StoreError> {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let uid = fields[2]
            .parse()
            .map_err(|_| StoreError::InvalidPolicyIntent)?;
        let gid = fields[3]
            .parse()
            .map_err(|_| StoreError::InvalidPolicyIntent)?;
        let account = Self {
            name: fields[0].into(),
            uid,
            gid,
            home: fields[5].into(),
            shell: fields[6].into(),
            generation: content_generation(
                format!("{}:{uid}:{gid}:{}:{}", fields[0], fields[5], fields[6]).as_bytes(),
            ),
        };
        if !account.validate() {
            return Err(StoreError::InvalidPolicyIntent);
        }
        Ok(account)
    }

    pub fn validate(&self) -> bool {
        let name = self.name.as_bytes();
        !name.is_empty()
            && name.len() <= 32
            && (name[0].is_ascii_lowercase() || name[0] == b'_')
            && name
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
            && (1000..60000).contains(&self.uid)
            && (1000..60000).contains(&self.gid)
            && self.home == format!("/home/{}", self.name)
            && [
                "/bin/bash",
                "/usr/bin/bash",
                "/bin/zsh",
                "/usr/bin/zsh",
                "/bin/sh",
                "/usr/bin/fish",
            ]
            .contains(&self.shell.as_str())
            && self.generation
                == content_generation(
                    format!(
                        "{}:{}:{}:{}:{}",
                        self.name, self.uid, self.gid, self.home, self.shell
                    )
                    .as_bytes(),
                )
    }

    /// # Errors
    /// Reused UIDs/names, changed home/shell, symlinks and unsafe home ancestry
    /// invalidate an old enrollment rather than transferring its privileges.
    pub fn revalidate_local(&self) -> Result<(), StoreError> {
        use std::os::unix::fs::MetadataExt;
        let passwd = std::fs::read_to_string("/etc/passwd")?;
        if passwd.len() > 1024 * 1024 || !self.validate() {
            return Err(StoreError::UnsafeStorage);
        }
        let matching: Vec<_> = passwd
            .lines()
            .filter(|line| {
                let f: Vec<_> = line.split(':').collect();
                f.len() == 7 && (f[0] == self.name || f[2].parse::<u32>() == Ok(self.uid))
            })
            .collect();
        if matching.len() != 1 || Self::from_passwd(matching[0])? != *self {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let home = std::fs::symlink_metadata(&self.home)?;
        let parent = std::fs::symlink_metadata("/home")?;
        if !home.is_dir()
            || home.uid() != self.uid
            || !parent.is_dir()
            || parent.uid() != 0
            || parent.mode() & 0o022 != 0
        {
            return Err(StoreError::UnsafeStorage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginMapping {
    pub seuser: String,
    pub range: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRecord {
    pub schema: String,
    pub account: LocalAccount,
    pub origin: AccountOrigin,
    pub phase: EnrollmentPhase,
    pub transaction_ref: SecurityReference,
    pub policy_generation: ContentGeneration,
    pub revision: u64,
    pub previous_mapping: Option<LoginMapping>,
}

impl EnrollmentRecord {
    pub fn validate(&self) -> bool {
        self.schema == ENROLLMENT_SCHEMA
            && self.account.validate()
            && self.revision > 0
            && self.transaction_ref.as_str().starts_with("operation_")
            && self.previous_mapping.as_ref().is_none_or(|m| {
                !m.seuser.is_empty()
                    && m.seuser.len() <= 64
                    && m.seuser
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && !m.range.is_empty()
                    && m.range.len() <= 128
                    && m.range.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b',' | b'-')
                    })
            })
    }

    pub fn permits_provider(&self) -> bool {
        self.validate()
            && matches!(
                self.phase,
                EnrollmentPhase::PendingSession | EnrollmentPhase::Enrolled
            )
    }

    fn follows(&self, previous: &Self) -> bool {
        use EnrollmentPhase::{
            Enrolled, MappingApplied, PendingSession, Prepared, RecoveryRequired, Unenrolled,
        };
        self.account == previous.account
            && self.origin == previous.origin
            && self.transaction_ref == previous.transaction_ref
            && self.policy_generation == previous.policy_generation
            && self.previous_mapping == previous.previous_mapping
            && (self.phase == RecoveryRequired
                || matches!(
                    (previous.phase, self.phase),
                    (Prepared, MappingApplied)
                        | (MappingApplied | Enrolled, PendingSession)
                        | (PendingSession, Enrolled)
                        | (
                            Prepared
                                | MappingApplied
                                | PendingSession
                                | Enrolled
                                | RecoveryRequired,
                            Unenrolled
                        )
                ))
    }
}

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == 3 {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE enrollment_accounts (
            owner_uid INTEGER PRIMARY KEY, account_name TEXT UNIQUE NOT NULL,
            revision INTEGER NOT NULL CHECK(revision>0), record_json TEXT NOT NULL CHECK(length(record_json)<=16384));
            PRAGMA user_version=4;")?;
        tx.commit()?;
    } else if version != 4 {
        return Err(StoreError::UnsupportedSchema);
    }
    let count: usize =
        connection.query_row("SELECT count(*) FROM enrollment_accounts", [], |r| r.get(0))?;
    if count > MAX_ACCOUNTS {
        return Err(StoreError::Corrupt);
    }
    let mut statement = connection
        .prepare("SELECT owner_uid,account_name,revision,record_json FROM enrollment_accounts")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u64>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (uid, name, revision, json) = row?;
        let record: EnrollmentRecord =
            serde_json::from_str(&json).map_err(|_| StoreError::Corrupt)?;
        if !record.validate()
            || record.account.uid != uid
            || record.account.name != name
            || record.revision != revision
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

impl PolicyStore {
    /// Root's deliberately selected migration transaction; no live coverage is
    /// inferred. Mapping and admission are separate verified stages.
    ///
    /// # Errors
    /// Rejects non-root callers, unsupported accounts, unsafe receipts or failed journal I/O.
    pub fn prepare_account(&mut self, name: &str) -> Result<(), StoreError> {
        use std::os::unix::fs::MetadataExt;
        if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
            return Err(StoreError::UnsafeStorage);
        }
        let passwd = std::fs::read_to_string("/etc/passwd")?;
        let account = passwd
            .lines()
            .find_map(|line| {
                LocalAccount::from_passwd(line)
                    .ok()
                    .filter(|a| a.name == name)
            })
            .ok_or(StoreError::InvalidPolicyIntent)?;
        account.revalidate_local()?;
        if self.enrollment(account.uid)?.is_some() {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let path = Path::new("/usr/lib/greyward/application-security/desktop/desktop.json");
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(StoreError::UnsafeStorage);
        }
        let bytes = std::fs::read(path)?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        let previous: LoginMapping = serde_json::from_value(
            manifest["accounts"][account.uid.to_string()]["previousMapping"].clone(),
        )
        .map_err(|_| StoreError::InvalidPolicyIntent)?;
        let generation = content_generation(&bytes);
        AccountOriginReceipt::issue(account.clone(), AccountOrigin::ExplicitMigration)?;
        self.journal_enrollment(
            &EnrollmentRecord {
                schema: ENROLLMENT_SCHEMA.into(),
                account,
                origin: AccountOrigin::ExplicitMigration,
                phase: EnrollmentPhase::Prepared,
                transaction_ref: SecurityReference::try_from(format!(
                    "operation_{}",
                    generation.as_str()
                ))
                .map_err(|_| StoreError::InvalidPolicyIntent)?,
                policy_generation: generation,
                revision: 1,
                previous_mapping: Some(previous),
            },
            None,
        )
    }

    /// Fixed root-only lifecycle continuation. This journal is never proof of
    /// enforcement; live admission/readback controls the public coverage.
    ///
    /// # Errors
    /// Rejects non-root callers, invalid transitions or failed admission/journal readback.
    pub fn advance_account(
        &mut self,
        name: &str,
        phase: EnrollmentPhase,
    ) -> Result<(), StoreError> {
        if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
            return Err(StoreError::UnsafeStorage);
        }
        let passwd = std::fs::read_to_string("/etc/passwd")?;
        let account = passwd
            .lines()
            .find_map(|line| {
                LocalAccount::from_passwd(line)
                    .ok()
                    .filter(|a| a.name == name)
            })
            .ok_or(StoreError::InvalidPolicyIntent)?;
        let mut record = self
            .enrollment(account.uid)?
            .ok_or(StoreError::InvalidPolicyIntent)?;
        if record.account != account {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let previous = record.revision;
        record.revision = previous
            .checked_add(1)
            .ok_or(StoreError::InvalidPolicyIntent)?;
        record.phase = phase;
        self.journal_enrollment(&record, Some(previous))
    }
    /// Fresh prerequisite evidence for the authenticated requester. This does
    /// not establish seat, user-manager, label or deputy coverage. In particular,
    /// a database enrollment row cannot produce an effective PROTECTED profile.
    /// # Errors
    /// Corrupt enrollment/policy state is an error, never a safe default.
    pub(crate) fn protection_prerequisites(
        &self,
        actor: &crate::ExecutionHandle,
    ) -> Result<greyward_security_domain::EnforcementEvidence, StoreError> {
        let started = std::time::Instant::now();
        let record = self.enrollment(actor.identity().owner_uid)?;
        let prepared_policy = record.as_ref().is_some_and(|record| {
            record.permits_provider()
                && record.account.revalidate_local().is_ok()
                && require_account_origin(record).is_ok()
                && crate::selinux_readback::enrollment_boundary_readback().is_ok()
        });
        let seat = self.production
            && prepared_policy
            && crate::desktop::verified(actor.identity().owner_uid);
        let resources = self.desired_policy()?.resources;
        let scoped: Vec<_> = resources
            .into_iter()
            .filter(|r| r.resource().owner_uid == actor.identity().owner_uid)
            .collect();
        let labels =
            seat && scoped.iter().all(|r| {
                self.resource_labels_verified(
                    &r.resource().resource_ref,
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                )
            }) && (scoped.is_empty()
                || ProviderBinding::production(self, actor.identity().owner_uid).is_ok_and(
                    |binding| {
                        crate::ResourceDenialProgram::prepare_bound(
                            &binding,
                            self.desired_policy().map_or(0, |s| s.revision),
                            self.desired_policy().map_or(0, |s| s.revision),
                            &scoped,
                        )
                        .is_ok_and(|program| {
                            crate::DevelopmentDenialReadback::read(
                                &program,
                                std::time::Instant::now() + std::time::Duration::from_secs(1),
                            )
                            .is_ok()
                        })
                    },
                ));
        Ok(greyward_security_domain::EnforcementEvidence {
            selinux_enforcing: crate::selinux_readback::enforcing_state(),
            production_policy_loaded: Some(prepared_policy),
            subject_confined: Some(
                actor.identity().selinux_context
                    == "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0",
            ),
            coverage: greyward_security_domain::SessionCoverage {
                graphical_session: seat,
                user_manager: seat,
                direct_exec: seat,
                services_and_scheduled_jobs: seat,
                enrolled_remote_sessions: seat,
                protected_resource_labels: labels,
                deputies_and_portals: false,
            },
            policy_revision: self.desired_policy()?.revision,
            evidence_age_ms: Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
            ..greyward_security_domain::EnforcementEvidence::default()
        })
    }

    /// Root configuration only; caller identity and kernel proof remain separate.
    /// # Errors
    /// Corrupt or foreign database records fail instead of granting enrollment.
    pub fn enrollment(&self, uid: u32) -> Result<Option<EnrollmentRecord>, StoreError> {
        use rusqlite::OptionalExtension;
        let row:Option<(String,u64,String)>=self.connection.query_row(
            "SELECT account_name,revision,record_json FROM enrollment_accounts WHERE owner_uid=?1",[uid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((name, revision, json)) = row else {
            return Ok(None);
        };
        let record: EnrollmentRecord =
            serde_json::from_str(&json).map_err(|_| StoreError::Corrupt)?;
        if !record.validate()
            || record.account.uid != uid
            || record.account.name != name
            || record.revision != revision
        {
            return Err(StoreError::Corrupt);
        }
        Ok(Some(record))
    }

    /// Journal a new/continued configuration transaction. No kernel operation or
    /// protection claim occurs here; only the fixed privileged coordinator uses it.
    /// # Errors
    /// Stale revision, UID reuse and conflicting transactions are rejected.
    pub fn journal_enrollment(
        &mut self,
        record: &EnrollmentRecord,
        expected: Option<u64>,
    ) -> Result<(), StoreError> {
        if !record.validate() || Some(record.revision) != expected.unwrap_or(0).checked_add(1) {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let encoded = serde_json::to_string(record).map_err(|_| StoreError::Corrupt)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(u64, String)> = {
            use rusqlite::OptionalExtension;
            tx.query_row(
                "SELECT revision,record_json FROM enrollment_accounts WHERE owner_uid=?1",
                [record.account.uid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
        };
        if current.as_ref().map(|row| row.0) != expected {
            return Err(StoreError::StaleRevision);
        }
        if let Some((_, json)) = current {
            let previous: EnrollmentRecord =
                serde_json::from_str(&json).map_err(|_| StoreError::Corrupt)?;
            if !previous.validate() || !record.follows(&previous) {
                return Err(StoreError::InvalidPolicyIntent);
            }
        } else if record.phase != EnrollmentPhase::Prepared {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let count: usize =
            tx.query_row("SELECT count(*) FROM enrollment_accounts", [], |r| r.get(0))?;
        if expected.is_none() && count >= MAX_ACCOUNTS {
            return Err(StoreError::InvalidPolicyIntent);
        }
        tx.execute("INSERT INTO enrollment_accounts VALUES(?1,?2,?3,?4) ON CONFLICT(owner_uid) DO UPDATE SET account_name=excluded.account_name,revision=excluded.revision,record_json=excluded.record_json",
            params![record.account.uid,record.account.name,record.revision,encoded])?;
        tx.commit()?;
        Ok(())
    }
}

/// Private construction prevents client-supplied paths/roles/modules. Provider
/// identity is validated root enrollment plus live peer identity, not its UID alone.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProviderBinding {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: String,
    pub(crate) base: String,
    pub(crate) production: bool,
    pub(crate) isolation_only: bool,
}
impl ProviderBinding {
    pub(crate) fn development() -> Self {
        Self {
            uid: 1002,
            gid: 1002,
            home: "/home/greyward-guard-probe".into(),
            base: "/var/lib/greyward-development/application-security/registration-critical".into(),
            production: false,
            isolation_only: false,
        }
    }
    pub(crate) fn production(store: &PolicyStore, uid: u32) -> Result<Self, StoreError> {
        // A ptrace boolean alone does not deny PTRACE_MODE_READ /proc access.
        // The inherited same-domain template is not a production boundary.
        // This necessary check is not a session/admission coverage receipt.
        crate::selinux_readback::enrollment_boundary_readback()
            .map_err(|_| StoreError::InvalidPolicyIntent)?;
        let record = store
            .enrollment(uid)?
            .filter(EnrollmentRecord::permits_provider)
            .ok_or(StoreError::InvalidPolicyIntent)?;
        record.account.revalidate_local()?;
        require_account_origin(&record)?;
        Ok(Self {
            uid,
            gid: record.account.gid,
            home: record.account.home,
            base: format!("/var/lib/greyward/application-security/enforcement/uid-{uid}"),
            production: true,
            isolation_only: false,
        })
    }
    /// Isolation adds restrictions without enrolling an account or granting data.
    pub(crate) fn isolation(uid: u32) -> Result<Self, StoreError> {
        use std::os::unix::fs::DirBuilderExt;
        let passwd = std::fs::read_to_string("/etc/passwd")?;
        let accounts: Vec<_> = passwd
            .lines()
            .filter_map(|line| LocalAccount::from_passwd(line).ok())
            .filter(|account| account.uid == uid)
            .collect();
        if accounts.len() != 1 {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let account = &accounts[0];
        account.revalidate_local()?;
        let binding = Self {
            uid,
            gid: account.gid,
            home: account.home.clone(),
            base: format!("/var/lib/greyward/application-security/enforcement/uid-{uid}"),
            production: true,
            isolation_only: true,
        };
        let content = binding.path().join("content");
        for path in [
            Path::new("/var/lib/greyward/application-security/enforcement"),
            binding.path(),
            &content,
        ] {
            match std::fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.into()),
            }
            private_origin_directory(path)?;
        }
        Ok(binding)
    }
    pub(crate) fn permits_isolation_actor(&self, actor: &crate::ExecutionHandle) -> bool {
        actor.revalidate().is_ok()
            && actor.identity().owner_uid == self.uid
            && (if self.isolation_only {
                Self::isolation(self.uid).is_ok_and(|current| current == *self)
            } else {
                actor.identity().selinux_context == Self::subject_context()
            })
    }
    pub(crate) fn for_actor(
        store: &PolicyStore,
        actor: &crate::ExecutionHandle,
    ) -> Result<Self, StoreError> {
        actor
            .revalidate()
            .map_err(|_| StoreError::InvalidPolicyIntent)?;
        let binding = if store.production {
            Self::production(store, actor.identity().owner_uid)?
        } else {
            if actor.identity().owner_uid != 1002 {
                return Err(StoreError::InvalidPolicyIntent);
            }
            Self::development()
        };
        if actor.identity().selinux_context != Self::subject_context() {
            return Err(StoreError::InvalidPolicyIntent);
        }
        if binding.production && !crate::desktop::verified(binding.uid) {
            return Err(StoreError::InvalidPolicyIntent);
        }
        Ok(binding)
    }
    pub(crate) fn subject_context() -> &'static str {
        "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0"
    }
    pub(crate) fn grant_context(&self, digest: &str) -> String {
        format!(
            "{}:greyward_as_grant_{digest}_t:s0",
            if self.production {
                "system_u:system_r"
            } else {
                "greyward_guard_u:greyward_guard_owner_r"
            }
        )
    }
    pub(crate) fn module(&self, kind: &str) -> String {
        if self.production {
            format!("greyward_as_{kind}_u{}", self.uid)
        } else {
            match kind {
                "resource" => "greyward_registration_critical",
                "context" => "greyward_grant_context_critical",
                _ => "greyward_grant_access_critical",
            }
            .into()
        }
    }
    pub(crate) fn path(&self) -> &Path {
        Path::new(&self.base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn account() -> LocalAccount {
        LocalAccount::from_passwd("alice:x:1003:1003::/home/alice:/bin/bash").unwrap()
    }
    fn record() -> EnrollmentRecord {
        EnrollmentRecord {
            schema: ENROLLMENT_SCHEMA.into(),
            account: account(),
            origin: AccountOrigin::ExplicitMigration,
            phase: EnrollmentPhase::Prepared,
            transaction_ref: SecurityReference::try_from(format!("operation_{}", "a".repeat(64)))
                .unwrap(),
            policy_generation: content_generation(b"policy"),
            revision: 1,
            previous_mapping: None,
        }
    }
    #[test]
    fn excluded_accounts_and_reused_identity_do_not_acquire_enrollment() {
        for line in [
            "daemon:x:999:999::/home/daemon:/bin/bash",
            "alice@domain:x:1003:1003::/home/alice@domain:/bin/bash",
            "alice:x:1003:1003::/tmp/alice:/bin/bash",
            "alice:x:1003:1003::/home/alice:/usr/sbin/nologin",
        ] {
            assert!(LocalAccount::from_passwd(line).is_err());
        }
        let mut a = account();
        a.uid = 1004;
        assert!(!a.validate());
    }
    #[test]
    fn interrupted_or_journaled_activation_cannot_supply_protection() {
        let mut r = record();
        assert!(!r.permits_provider());
        r.phase = EnrollmentPhase::MappingApplied;
        assert!(!r.permits_provider());
        r.phase = EnrollmentPhase::RecoveryRequired;
        assert!(!r.permits_provider());
    }
    #[test]
    fn stale_concurrent_journals_fail_without_overwriting_owner() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let mut r = record();
        store.journal_enrollment(&r, None).unwrap();
        r.phase = EnrollmentPhase::MappingApplied;
        r.revision = 2;
        assert!(matches!(
            store.journal_enrollment(&r, None),
            Err(StoreError::InvalidPolicyIntent)
        ));
        store.journal_enrollment(&r, Some(1)).unwrap();
        assert!(matches!(
            store.journal_enrollment(&r, Some(1)),
            Err(StoreError::StaleRevision)
        ));
        assert_eq!(store.enrollment(1003).unwrap(), Some(r));
        assert!(store.enrollment(1004).unwrap().is_none());
    }

    #[test]
    fn a_valid_record_cannot_transfer_identity_or_skip_activation_stages() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        let mut r = record();
        store.journal_enrollment(&r, None).unwrap();
        r.revision = 2;
        r.phase = EnrollmentPhase::Enrolled;
        assert!(store.journal_enrollment(&r, Some(1)).is_err());
        r.phase = EnrollmentPhase::MappingApplied;
        r.account = LocalAccount::from_passwd("bob:x:1003:1003::/home/bob:/bin/bash").unwrap();
        assert!(store.journal_enrollment(&r, Some(1)).is_err());
        assert_eq!(store.enrollment(1003).unwrap(), Some(record()));
    }

    #[test]
    fn corrupt_enrollment_rows_are_rejected_when_the_store_reopens() {
        let mut store = PolicyStore::isolated_memory().unwrap();
        store.journal_enrollment(&record(), None).unwrap();
        store
            .connection
            .execute("UPDATE enrollment_accounts SET account_name='other'", [])
            .unwrap();
        assert!(matches!(
            migrate(&mut store.connection),
            Err(StoreError::Corrupt)
        ));
    }

    #[test]
    fn system_contexts_do_not_import_the_development_owner_role() {
        let context = crate::managed_grant::grant_context_cil(&"a".repeat(64), true).unwrap();
        assert!(context.contains("(roletype system_r"));
        assert!(!context.contains("greyward_guard_owner_r"));
        let previous = record();
        let mut following = previous.clone();
        following.phase = EnrollmentPhase::RecoveryRequired;
        following.revision = 2;
        assert!(following.follows(&previous));
        assert!(!following.permits_provider());
    }

    #[test]
    fn account_origins_cannot_transfer_or_silently_enroll_existing_accounts() {
        let record = record();
        let mut receipt = AccountOriginReceipt {
            schema: "greyward.account-origin/v1".into(),
            account: record.account.clone(),
            origin: AccountOrigin::ExplicitMigration,
        };
        assert!(receipt.matches(&record));
        receipt.origin = AccountOrigin::Installer;
        assert!(!receipt.matches(&record));
        receipt.origin = record.origin;
        receipt.account =
            LocalAccount::from_passwd("bob:x:1003:1003::/home/bob:/bin/bash").unwrap();
        assert!(!receipt.matches(&record));
        assert!(serde_json::from_str::<AccountOriginReceipt>(
            r#"{"schema":"greyward.account-origin/v1","account":{},"origin":"INSTALLER","protected":true}"#
        ).is_err());
    }
}
