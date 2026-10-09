//! Descriptor-bound, metadata-only label application. Object readback is not
//! whole-session coverage; incomplete/crashed journals never establish PROTECTED.
use crate::{
    DevelopmentDenialReadback, ExecutionHandle, PolicyStore, ResourceDenialProgram,
    ResourceRegistrationError, ResourceRegistrationLease, StoreError,
};
use greyward_security_domain::{ExecutionIdentity, SecurityReference};
use rusqlite::{Connection, TransactionBehavior, params};
use rustix::fs::{Mode, OFlags, ResolveFlags, XattrFlags, openat2};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, Metadata};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Instant;

const MAX_OBJECTS: usize = 1024;
const MAX_JOURNAL: usize = 512 * 1024;
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

#[cfg(test)]
mod filesystem_reopen_tests {
    use super::*;

    #[test]
    fn stable_filesystem_replaces_only_mount_device_number() {
        let root = File::open("/").unwrap();
        let identity = FilesystemIdentity::read(&root).unwrap();
        let actual = root.metadata().unwrap().dev();
        assert_eq!(
            reopened_device(&root, Some(&identity), actual ^ 1).unwrap(),
            actual
        );
        assert_eq!(
            reopened_device(&root, None, actual ^ 1).unwrap(),
            actual ^ 1
        );
    }

    #[test]
    fn another_filesystem_is_not_admitted_by_matching_path() {
        let root = File::open("/").unwrap();
        let mut identity = FilesystemIdentity::read(&root).unwrap();
        identity.id.push('x');
        assert!(reopened_device(&root, Some(&identity), root.metadata().unwrap().dev()).is_err());
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectStamp {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl From<Metadata> for ObjectStamp {
    fn from(m: Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            size: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}
struct HeldObject {
    file: File,
    relative: PathBuf,
    stamp: ObjectStamp,
    original: String,
}
impl HeldObject {
    fn proxy(&self) -> String {
        format!("/proc/self/fd/{}", self.file.as_raw_fd())
    }
    fn unchanged(&self) -> Result<(), ResourceRegistrationError> {
        if ObjectStamp::from(self.file.metadata()?) != self.stamp {
            return Err(ResourceRegistrationError::Changed);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalObject {
    stamp: ObjectStamp,
    original: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelJournal {
    resource: SecurityReference,
    revision: u64,
    target: String,
    phase: String,
    objects: Vec<JournalObject>,
    // Root-private reopening hint. Object identity and fresh kernel/label
    // readback, never this pathname, decide whether coverage is available.
    #[serde(default)]
    root_locator: Option<String>,
    // Btrfs st_dev is allocated at mount time. The kernel filesystem ID,
    // inode, owner and root-only SELinux label jointly identify a reopened tree.
    #[serde(default)]
    filesystem: Option<FilesystemIdentity>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemIdentity {
    kind: i64,
    id: String,
}

impl FilesystemIdentity {
    fn read(file: &File) -> Result<Self, ResourceRegistrationError> {
        let info = rustix::fs::fstatfs(file)?;
        Ok(Self {
            kind: info.f_type as i64,
            id: format!("{:?}", info.f_fsid),
        })
    }
}

fn reopened_device(
    root: &File,
    expected: Option<&FilesystemIdentity>,
    legacy: u64,
) -> Result<u64, ResourceRegistrationError> {
    match expected {
        Some(expected) if &FilesystemIdentity::read(root)? == expected => {
            Ok(root.metadata()?.dev())
        }
        Some(_) => Err(ResourceRegistrationError::Changed),
        None => Ok(legacy),
    }
}

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == 2 {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE resource_label_journal (
            resource_ref TEXT PRIMARY KEY, revision INTEGER NOT NULL,
            record_json TEXT NOT NULL CHECK(length(record_json)<=524288));
            PRAGMA user_version=3;",
        )?;
        tx.commit()?;
    } else if ![3, 4].contains(&version) {
        return Err(StoreError::UnsupportedSchema);
    }
    let (count, bytes): (usize, usize) = connection.query_row(
        "SELECT count(*), coalesce(sum(length(record_json)),0) FROM resource_label_journal",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count > 2000 || bytes > 32 * 1024 * 1024 {
        return Err(StoreError::Corrupt);
    }
    let mut stmt = connection
        .prepare("SELECT resource_ref,revision,record_json FROM resource_label_journal")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (reference, revision, json) = row?;
        let value: LabelJournal = serde_json::from_str(&json).map_err(|_| StoreError::Corrupt)?;
        if value.resource.as_str() != reference
            || value.revision != revision
            || !valid_journal(&value)
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}
fn valid_context(text: &str) -> bool {
    let fields: Vec<_> = text.split(':').collect();
    text.len() <= 1024
        && fields.len() >= 4
        && fields[1] == "object_r"
        && fields.iter().all(|f| !f.is_empty())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:.,-".contains(&b))
}
fn valid_journal(j: &LabelJournal) -> bool {
    j.resource.namespace() == "resource"
        && j.revision > 0
        && valid_context(&j.target)
        && j.target
            == format!(
                "system_u:object_r:greyward_as_resource_{}_t:s0",
                j.resource.as_str().trim_start_matches("resource_")
            )
        && ["PREPARED", "APPLIED", "VERIFIED", "FAILED"].contains(&j.phase.as_str())
        && !j.objects.is_empty()
        && j.objects.len() <= MAX_OBJECTS
        && j.root_locator
            .as_ref()
            .is_none_or(|p| p.starts_with('/') && p.len() <= 4096 && !p.contains('\0'))
        && j.filesystem.as_ref().is_none_or(|f| {
            [0x9123_683e, 0x0000_ef53, 0x5846_5342].contains(&f.kind)
                && !f.id.is_empty()
                && f.id.len() <= 128
                && !f.id.contains('\0')
        })
        && j.objects
            .iter()
            .all(|o| o.stamp.inode != 0 && o.stamp.links > 0 && valid_context(&o.original))
}
fn context(proxy: &str) -> Result<String, ResourceRegistrationError> {
    let mut buffer = [0u8; 1025];
    let size = rustix::fs::getxattr(proxy, "security.selinux", &mut buffer[..])?;
    let text = std::str::from_utf8(&buffer[..size])
        .map_err(|_| ResourceRegistrationError::LabelMetadata)?;
    let text = text.strip_suffix('\0').unwrap_or(text);
    if !valid_context(text) {
        return Err(ResourceRegistrationError::LabelMetadata);
    }
    Ok(text.to_owned())
}
fn check(deadline: Instant) -> Result<(), ResourceRegistrationError> {
    if Instant::now() >= deadline {
        Err(ResourceRegistrationError::Changed)
    } else {
        Ok(())
    }
}
fn collect(
    root: File,
    uid: u32,
    deadline: Instant,
) -> Result<Vec<HeldObject>, ResourceRegistrationError> {
    let mut objects = Vec::new();
    let mut pending = vec![(root, PathBuf::new(), 0usize)];
    while let Some((file, relative, depth)) = pending.pop() {
        check(deadline)?;
        if objects.len() + pending.len() >= MAX_OBJECTS || depth > 16 {
            return Err(ResourceRegistrationError::UnsupportedTree);
        }
        let before = file.metadata()?;
        if before.uid() != uid || before.nlink() == 0 || !(before.is_dir() || before.is_file()) {
            return Err(ResourceRegistrationError::UnsupportedTree);
        }
        let object = HeldObject {
            original: context(&format!("/proc/self/fd/{}", file.as_raw_fd()))?,
            file,
            relative,
            stamp: ObjectStamp::from(before),
        };
        if object.file.metadata()?.is_dir() {
            for entry in fs::read_dir(object.proxy())? {
                check(deadline)?;
                let name = entry?.file_name();
                let child = File::from(openat2(
                    &object.file,
                    &name,
                    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    RESOLVE,
                )?);
                pending.push((child, object.relative.join(name), depth + 1));
                if objects.len() + pending.len() > MAX_OBJECTS {
                    return Err(ResourceRegistrationError::UnsupportedTree);
                }
            }
        }
        object.unchanged()?;
        objects.push(object);
    }
    objects.sort_by_key(|object| object.relative.components().count());
    Ok(objects)
}

impl PolicyStore {
    pub(crate) fn reopen_registered_directories(&mut self) -> Result<(), StoreError> {
        let records: Vec<String> = {
            let mut query = self
                .connection
                .prepare("SELECT record_json FROM resource_label_journal")?;
            query
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?
        };
        for encoded in records {
            let journal: LabelJournal =
                serde_json::from_str(&encoded).map_err(|_| StoreError::Corrupt)?;
            if journal.phase != "VERIFIED" {
                continue;
            }
            let Some(locator) = journal.root_locator else {
                continue;
            };
            let Some(stamp) = journal.objects.first().map(|o| &o.stamp) else {
                continue;
            };
            let reopened = (|| -> Result<LiveRegisteredDirectory, ResourceRegistrationError> {
                let base = rustix::fs::open(
                    "/",
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                let root = File::from(openat2(
                    base,
                    locator.trim_start_matches('/'),
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
                )?);
                // Older receipts retain the original strict device check;
                // only a separately verified migration can upgrade them.
                let device = reopened_device(&root, journal.filesystem.as_ref(), stamp.device)?;
                let live = LiveRegisteredDirectory {
                    root,
                    resource: journal.resource.clone(),
                    target: journal.target,
                    device,
                    inode: stamp.inode,
                    uid: stamp.uid,
                };
                live.verify(Instant::now() + std::time::Duration::from_secs(2))?;
                Ok(live)
            })();
            // A missing/replaced/unsupported directory stays unavailable. Never
            // relabel replacement content or silently register the new object.
            if let Ok(live) = reopened {
                self.live_resources.insert(journal.resource, live);
            }
        }
        Ok(())
    }
    fn write_label_journal(&mut self, j: &LabelJournal, insert: bool) -> Result<(), StoreError> {
        if !valid_journal(j) {
            return Err(StoreError::Corrupt);
        }
        let encoded = serde_json::to_string(j).map_err(|_| StoreError::Corrupt)?;
        if encoded.len() > MAX_JOURNAL {
            return Err(StoreError::InvalidPolicyIntent);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision: u64 =
            tx.query_row("SELECT policy_revision FROM metadata WHERE id=1", [], |r| {
                r.get(0)
            })?;
        if revision != j.revision {
            return Err(StoreError::StaleRevision);
        }
        let bytes: usize = tx.query_row(
            "SELECT coalesce(sum(length(record_json)),0) FROM resource_label_journal",
            [],
            |r| r.get(0),
        )?;
        if bytes.saturating_add(encoded.len()) > 32 * 1024 * 1024 {
            return Err(StoreError::InvalidPolicyIntent);
        }
        if insert {
            tx.execute("INSERT INTO resource_label_journal VALUES (?1,?2,?3)",params![j.resource.as_str(),j.revision,encoded])?;
        } else if tx.execute("UPDATE resource_label_journal SET record_json=?3 WHERE resource_ref=?1 AND revision=?2",
            params![j.resource.as_str(),j.revision,encoded])?!=1 {return Err(StoreError::Corrupt);}
        tx.commit()?;
        Ok(())
    }
}

/// A process-private object-label receipt, never an application PROTECTED
/// snapshot. Restart, policy changes and tree changes require new verification.
pub struct RegisteredDirectory {
    resource: SecurityReference,
    revision: u64,
    actor: ExecutionIdentity,
    objects: Vec<HeldObject>,
    target: String,
    deadline: Instant,
}
pub(crate) struct LiveRegisteredDirectory {
    root: File,
    resource: SecurityReference,
    target: String,
    device: u64,
    inode: u64,
    uid: u32,
}
impl LiveRegisteredDirectory {
    pub(crate) fn verify(&self, deadline: Instant) -> Result<(), ResourceRegistrationError> {
        check(deadline)?;
        let metadata = self.root.metadata()?;
        if metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.nlink() == 0
        {
            return Err(ResourceRegistrationError::Changed);
        }
        // Fresh metadata-only tree readback includes newly inherited objects.
        // The held root, rather than a mutable pathname, remains the authority.
        for object in collect(self.root.try_clone()?, self.uid, deadline)? {
            if context(&object.proxy())? != self.target {
                return Err(ResourceRegistrationError::LabelMetadata);
            }
        }
        check(deadline)
    }
}
impl RegisteredDirectory {
    pub(crate) fn retain(&self) -> Result<LiveRegisteredDirectory, ResourceRegistrationError> {
        let object = self
            .objects
            .first()
            .ok_or(ResourceRegistrationError::Changed)?;
        Ok(LiveRegisteredDirectory {
            root: object.file.try_clone()?,
            resource: self.resource.clone(),
            target: self.target.clone(),
            device: object.stamp.device,
            inode: object.stamp.inode,
            uid: object.stamp.uid,
        })
    }
    pub fn resource_ref(&self) -> &SecurityReference {
        &self.resource
    }
    pub fn objects_labeled(&self) -> usize {
        self.objects.len()
    }
    /// # Errors
    /// Stale policy, actor, labels, membership or metadata refuse actual coverage.
    pub fn revalidate(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        program: &ResourceDenialProgram,
        readback: &DevelopmentDenialReadback,
    ) -> Result<(), ResourceRegistrationError> {
        check(self.deadline)?;
        actor.revalidate().map_err(crate::PolicyIntentError::from)?;
        if actor.identity() != &self.actor || store.desired_policy()?.revision != self.revision {
            return Err(ResourceRegistrationError::Changed);
        }
        readback.revalidate(program)?;
        self.verify_objects()?;
        check(self.deadline)
    }
    fn verify_objects(&self) -> Result<(), ResourceRegistrationError> {
        let root = &self
            .objects
            .first()
            .ok_or(ResourceRegistrationError::Changed)?
            .file;
        for object in &self.objects {
            check(self.deadline)?;
            object.unchanged()?;
            if context(&object.proxy())? != self.target {
                return Err(ResourceRegistrationError::LabelMetadata);
            }
            if !object.relative.as_os_str().is_empty() {
                let member = File::from(openat2(
                    root,
                    &object.relative,
                    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    RESOLVE,
                )?);
                let metadata = member.metadata()?;
                if metadata.dev() != object.stamp.device || metadata.ino() != object.stamp.inode {
                    return Err(ResourceRegistrationError::Changed);
                }
            }
        }
        Ok(())
    }
}
impl PolicyStore {
    pub(crate) fn resource_labels_verified(
        &self,
        resource: &SecurityReference,
        deadline: Instant,
    ) -> bool {
        self.live_resources
            .get(resource)
            .is_some_and(|r| &r.resource == resource && r.verify(deadline).is_ok())
    }
}
impl ResourceRegistrationLease {
    /// Label the freshly authorized held tree only after live mandatory denial
    /// readback. Journal original metadata before the first mutation. Any error
    /// leaves an unresolved journal and UNKNOWN coverage, never an unrestricted
    /// launch or an automatic weakening rollback. A hard-bounded root worker is
    /// required. Existing object contents are never opened/read.
    /// # Errors
    /// Changed authorization/object/policy, unsupported trees, journal or label
    /// failures refuse completion; an explicit recovery operation is required.
    pub fn apply_labels(
        self,
        store: &mut PolicyStore,
        actor: &ExecutionHandle,
        program: &ResourceDenialProgram,
        readback: &DevelopmentDenialReadback,
    ) -> Result<RegisteredDirectory, ResourceRegistrationError> {
        self.revalidate(store, actor)?;
        readback.revalidate(program)?;
        if program.revision() != self.revision {
            return Err(ResourceRegistrationError::Changed);
        }
        let label = program
            .resource_label(&self.record.resource().resource_ref)
            .ok_or(ResourceRegistrationError::LabelMetadata)?;
        let target = format!("system_u:object_r:{label}:s0");
        let mut objects = collect(
            self.selection.duplicate_object()?,
            self.actor.owner_uid,
            self.deadline,
        )?;
        self.revalidate(store, actor)?;
        let mut journal = LabelJournal {
            resource: self.record.resource().resource_ref.clone(),
            revision: self.revision,
            target: target.clone(),
            phase: "PREPARED".into(),
            filesystem: Some(FilesystemIdentity::read(
                &objects
                    .first()
                    .ok_or(ResourceRegistrationError::Changed)?
                    .file,
            )?),
            root_locator: fs::read_link(
                objects
                    .first()
                    .ok_or(ResourceRegistrationError::Changed)?
                    .proxy(),
            )?
            .to_str()
            .filter(|p| p.starts_with('/') && !p.ends_with(" (deleted)"))
            .map(str::to_owned),
            objects: objects
                .iter()
                .map(|o| JournalObject {
                    stamp: o.stamp.clone(),
                    original: o.original.clone(),
                })
                .collect(),
        };
        store.write_label_journal(&journal, true)?;
        let outcome = (|| {
            for object in &mut objects {
                check(self.deadline)?;
                actor.revalidate().map_err(crate::PolicyIntentError::from)?;
                readback.revalidate(program)?;
                if store.desired_policy()?.revision != self.revision {
                    return Err(ResourceRegistrationError::Changed);
                }
                object.unchanged()?;
                rustix::fs::setxattr(
                    object.proxy(),
                    "security.selinux",
                    target.as_bytes(),
                    XattrFlags::REPLACE,
                )?;
                let mut after = ObjectStamp::from(object.file.metadata()?);
                let changed = after.changed;
                after.changed = object.stamp.changed;
                if after != object.stamp {
                    return Err(ResourceRegistrationError::Changed);
                }
                object.stamp.changed = changed;
                if context(&object.proxy())? != target {
                    return Err(ResourceRegistrationError::LabelMetadata);
                }
            }
            journal.phase = "APPLIED".into();
            store.write_label_journal(&journal, false)?;
            let receipt = RegisteredDirectory {
                resource: journal.resource.clone(),
                revision: self.revision,
                actor: self.actor,
                objects,
                target,
                deadline: self.deadline,
            };
            receipt.revalidate(store, actor, program, readback)?;
            journal.phase = "VERIFIED".into();
            store.write_label_journal(&journal, false)?;
            Ok(receipt)
        })();
        if outcome.is_err() {
            journal.phase = "FAILED".into();
            let _ = store.write_label_journal(&journal, false);
        }
        outcome
    }
}
