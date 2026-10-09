//! Retain reviewed objects across persistence and journaled label application.
//! The process-private object receipt is separate from whole-session coverage;
//! restart reconciliation and production enrollment remain distinct gates.
use crate::{
    DirectorySelection, ExecutionHandle, PolicyIntentError, PolicyStore, ResourceDenialProgram,
    ResourceIntent, ResourcePolicyError,
};
use greyward_security_domain::{ExecutionIdentity, ProtectedResource};
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceRegistrationError {
    #[error("Root registration preparation is required")]
    NotRoot,
    #[error("Selected object label metadata is missing or unsupported")]
    LabelMetadata,
    #[error("Selected resource tree changed during label application")]
    Changed,
    #[error("Resource tree is unbounded or contains unsupported objects")]
    UnsupportedTree,
    #[error(transparent)]
    Storage(#[from] crate::StoreError),
    #[error(transparent)]
    Readback(#[from] crate::SelinuxReadbackError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Selection(#[from] crate::ResourceSelectionError),
    #[error(transparent)]
    Review(#[from] PolicyIntentError),
    #[error(transparent)]
    Policy(#[from] ResourcePolicyError),
    #[error(transparent)]
    Syscall(#[from] rustix::io::Errno),
}

/// Non-cloneable, non-serializable continuation produced only by the freshly
/// authorized commit. Database inode metadata cannot recreate this authority.
pub struct ResourceRegistrationLease {
    pub(crate) record: ResourceIntent,
    pub(crate) selection: DirectorySelection,
    pub(crate) actor: ExecutionIdentity,
    pub(crate) revision: u64,
    pub(crate) deadline: Instant,
}

impl ResourceRegistrationLease {
    pub(crate) fn committed(
        record: ResourceIntent,
        selection: DirectorySelection,
        actor: ExecutionIdentity,
        revision: u64,
        deadline: Instant,
    ) -> Self {
        Self {
            record,
            selection,
            actor,
            revision,
            deadline,
        }
    }

    pub fn resource(&self) -> &ProtectedResource {
        self.record.resource()
    }

    /// # Errors
    /// Expired/exited/replaced actors, changed descriptors, changed root policy
    /// or removed/modified intentions refuse; no pathname is resolved again.
    pub fn revalidate(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
    ) -> Result<(), PolicyIntentError> {
        if Instant::now() >= self.deadline {
            return Err(PolicyIntentError::Deadline);
        }
        actor.revalidate()?;
        if actor.identity() != &self.actor {
            return Err(PolicyIntentError::Changed);
        }
        self.selection.revalidate()?;
        let state = store.desired_policy()?;
        if state.revision != self.revision
            || !state.resources.iter().any(|record| record == &self.record)
            || self.selection.object_receipt()? != self.record.object
        {
            return Err(PolicyIntentError::Changed);
        }
        if Instant::now() >= self.deadline {
            return Err(PolicyIntentError::Deadline);
        }
        Ok(())
    }

    fn root() -> Result<(), ResourceRegistrationError> {
        if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
            return Err(ResourceRegistrationError::NotRoot);
        }
        Ok(())
    }

    /// Prepare the owning user's current development-denial program, not an
    /// arbitrary caller payload. Compilation and kernel readback remain separate.
    /// # Errors
    /// Non-root, stale review/policy and malformed or oversized intentions refuse.
    pub fn prepare_denial(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
    ) -> Result<ResourceDenialProgram, ResourceRegistrationError> {
        Self::root()?;
        self.revalidate(store, actor)?;
        let state = store.desired_policy().map_err(PolicyIntentError::from)?;
        let resources: Vec<_> = state
            .resources
            .into_iter()
            .filter(|record| record.resource().owner_uid == self.actor.owner_uid)
            .collect();
        let program = ResourceDenialProgram::prepare_development_baseline(
            self.revision,
            state.revision,
            self.actor.owner_uid,
            &resources,
        )?;
        self.revalidate(store, actor)?;
        Ok(program)
    }

    /// Metadata-only inspection through this process's still-held descriptor.
    /// The result is an object-label fact, not evidence of an access decision.
    /// # Errors
    /// Non-root, changed review/object/policy, absent or malformed labels refuse.
    pub fn current_label_type(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
    ) -> Result<String, ResourceRegistrationError> {
        Self::root()?;
        self.revalidate(store, actor)?;
        let proxy = self
            .selection
            .held_metadata_path()
            .map_err(PolicyIntentError::from)?;
        let mut buffer = [0u8; 1025];
        let size = rustix::fs::getxattr(&proxy, "security.selinux", &mut buffer[..])?;
        if size == 0 || size > 1024 {
            return Err(ResourceRegistrationError::LabelMetadata);
        }
        let text = std::str::from_utf8(&buffer[..size])
            .map_err(|_| ResourceRegistrationError::LabelMetadata)?;
        let text = text.strip_suffix('\0').unwrap_or(text);
        let fields: Vec<_> = text.split(':').collect();
        if fields.len() < 4
            || fields[1] != "object_r"
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_:.,-".contains(&byte))
            || fields.iter().any(|part| part.is_empty())
        {
            return Err(ResourceRegistrationError::LabelMetadata);
        }
        self.revalidate(store, actor)?;
        Ok(fields[2].to_owned())
    }
}
