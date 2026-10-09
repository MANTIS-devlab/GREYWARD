//! Generation-bound reviewed read grants for the separate-account provider.
//! Installation and launch remain privileged bounded operations. No caller-
//! supplied policy, context or executable acquires a grant through this type.
use crate::{
    ExecutionHandle, InstalledExecutable, PolicyStore, ResourceDenialProgram, ResourcePolicyError,
    SelinuxReadbackError, StoreError, policy_intent::GrantIntent,
};
use greyward_security_domain::{
    ApplicationProvider, ContentGeneration, ExecutionIdentity, InstalledExecutablePath,
    ResourceAccess, SecurityReference,
};
use std::fmt::Write;
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManagedGrantError {
    #[error("Reviewed grant is missing, stale, foreign or unsupported")]
    Changed,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Execution(#[from] crate::ExecutionError),
    #[error(transparent)]
    Content(#[from] crate::InstalledContentError),
    #[error(transparent)]
    Policy(#[from] ResourcePolicyError),
    #[error(transparent)]
    Kernel(#[from] SelinuxReadbackError),
}

/// Only a root-held, freshly reviewed policy record and validated executable
/// can prepare this context. Ordinary subjects have no transition into it.
/// Persistent grants intentionally include in-process code/extensions.
pub struct ReviewedReadGrant {
    record: GrantIntent,
    code_generation: ContentGeneration,
    rpm_bound: bool,
    actor: ExecutionIdentity,
    revision: u64,
    context: String,
    context_cil: String,
    access_cil: String,
    labels: Vec<String>,
    deadline: Instant,
}

/// Root-recorded access may only preserve an already active kernel grant or
/// withdraw it. It cannot prepare code or authorize a launch. In particular,
/// revocation does not depend on an old executable still being installed.
pub(crate) struct RecordedReadAccess {
    reference: SecurityReference,
    actor: ExecutionIdentity,
    revision: u64,
    context: String,
    access_cil: String,
    labels: Vec<String>,
    deadline: Instant,
}

impl RecordedReadAccess {
    pub(crate) fn prepare(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        deadline: Instant,
    ) -> Result<Self, ManagedGrantError> {
        if rustix::process::getuid().as_raw() != 0
            || rustix::process::geteuid().as_raw() != 0
            || Instant::now() >= deadline
        {
            return Err(ManagedGrantError::Changed);
        }
        actor.revalidate()?;
        let binding = crate::enrollment::ProviderBinding::for_actor(store, actor)?;
        let state = store.desired_policy()?;
        let record = state
            .grants
            .iter()
            .find(|r| &r.grant.grant_ref == reference)
            .ok_or(ManagedGrantError::Changed)?;
        if record.grant.owner_uid != actor.identity().owner_uid
            || record.grant.access != [ResourceAccess::Read]
        {
            return Err(ManagedGrantError::Changed);
        }
        let resources: Vec<_> = state
            .resources
            .iter()
            .filter(|r| r.resource().owner_uid == record.grant.owner_uid)
            .cloned()
            .collect();
        let denial = ResourceDenialProgram::prepare_bound(
            &binding,
            state.revision,
            state.revision,
            &resources,
        )?;
        let digest = reference
            .as_str()
            .strip_prefix("grant_")
            .ok_or(ManagedGrantError::Changed)?;
        grant_context_cil(digest, binding.production).ok_or(ManagedGrantError::Changed)?;
        let subject = format!("greyward_as_grant_{digest}_t");
        let mut access_cil = String::new();
        let mut labels = Vec::new();
        for resource in &record.grant.resources {
            let label = denial
                .resource_label(resource)
                .ok_or(ManagedGrantError::Changed)?
                .to_owned();
            writeln!(
                access_cil,
                "(allow {subject} {label} (file (open read getattr)))"
            )
            .expect("String formatting");
            writeln!(
                access_cil,
                "(allow {subject} {label} (dir (open read search getattr)))"
            )
            .expect("String formatting");
            labels.push(label);
        }
        Ok(Self {
            reference: reference.clone(),
            actor: actor.identity().clone(),
            revision: state.revision,
            context: binding.grant_context(digest),
            access_cil,
            labels,
            deadline,
        })
    }

    pub(crate) fn access_cil(&self) -> &str {
        &self.access_cil
    }

    pub(crate) fn verify(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        active: bool,
    ) -> Result<u32, ManagedGrantError> {
        actor.revalidate()?;
        crate::enrollment::ProviderBinding::for_actor(store, actor)?;
        let state = store.desired_policy()?;
        if Instant::now() >= self.deadline
            || actor.identity() != &self.actor
            || (active && state.revision != self.revision)
            || (!active && state.revision <= self.revision)
            || state
                .grants
                .iter()
                .any(|g| g.grant.grant_ref == self.reference)
                != active
        {
            return Err(ManagedGrantError::Changed);
        }
        let mut sequence = None;
        for label in &self.labels {
            let actual =
                crate::selinux_readback::reviewed_read_decision(&self.context, label, active)?;
            if sequence.is_some_and(|old| old != actual) {
                return Err(ManagedGrantError::Changed);
            }
            sequence = Some(actual);
        }
        sequence.ok_or(ManagedGrantError::Changed)
    }
}
impl ReviewedReadGrant {
    pub(crate) fn revocation_access(&self) -> RecordedReadAccess {
        RecordedReadAccess {
            reference: self.record.grant.grant_ref.clone(),
            actor: self.actor.clone(),
            revision: self.revision,
            context: self.context.clone(),
            access_cil: self.access_cil.clone(),
            labels: self.labels.clone(),
            deadline: self.deadline,
        }
    }
    /// # Errors
    /// Refuse absent/foreign reviews, changed installed generation, unsupported
    /// access and incomplete resource inputs. This does not install a module.
    pub fn prepare(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        code: &InstalledExecutable,
        deadline: Instant,
    ) -> Result<Self, ManagedGrantError> {
        Self::prepare_bound(store, actor, reference, code, deadline, false)
    }

    /// Bind the reviewed RPM installation generation to independently validated
    /// file bytes. Package metadata is not replaced by a raw file digest, and
    /// a shared executable digest cannot transfer a grant between packages.
    /// # Errors
    /// Changed package/member metadata, forged installation or stale code refuse.
    pub fn prepare_rpm(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        code: &InstalledExecutable,
        deadline: Instant,
    ) -> Result<Self, ManagedGrantError> {
        Self::prepare_bound(store, actor, reference, code, deadline, true)
    }

    fn prepare_bound(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        code: &InstalledExecutable,
        deadline: Instant,
        rpm_bound: bool,
    ) -> Result<Self, ManagedGrantError> {
        if rustix::process::getuid().as_raw() != 0
            || rustix::process::geteuid().as_raw() != 0
            || Instant::now() >= deadline
        {
            return Err(ManagedGrantError::Changed);
        }
        actor.revalidate()?;
        crate::enrollment::ProviderBinding::for_actor(store, actor)?;
        code.revalidate()?;
        let binding = crate::enrollment::ProviderBinding::for_actor(store, actor)?;
        let state = store.desired_policy()?;
        let record = state
            .grants
            .into_iter()
            .find(|r| &r.grant.grant_ref == reference)
            .ok_or(ManagedGrantError::Changed)?;
        if record.grant.owner_uid != actor.identity().owner_uid
            || record.grant.access != [ResourceAccess::Read]
        {
            return Err(ManagedGrantError::Changed);
        }
        if rpm_bound {
            if record.installation.provider != ApplicationProvider::Rpm {
                return Err(ManagedGrantError::Changed);
            }
            verify_rpm_identity(&record, code, deadline)?;
        } else if record.installation.provider == ApplicationProvider::Rpm
            || record.grant.generation != *code.generation()
        {
            return Err(ManagedGrantError::Changed);
        }
        // Legacy generic development records can still be withdrawn, but may
        // never activate or be reused as a caller-selected credential deputy.
        if record.grant.policy_revision != state.revision
            || record.tool_profile.is_none_or(|profile| {
                !profile.accepts_code(code.selected_path(), code.generation())
            })
        {
            return Err(ManagedGrantError::Changed);
        }
        let current = store
            .get_application(record.grant.owner_uid, &record.grant.installation_ref)?
            .ok_or(ManagedGrantError::Changed)?;
        if current.identity != record.installation {
            return Err(ManagedGrantError::Changed);
        }
        let resources: Vec<_> = state
            .resources
            .into_iter()
            .filter(|r| r.resource().owner_uid == record.grant.owner_uid)
            .collect();
        let denial = ResourceDenialProgram::prepare_bound(
            &binding,
            state.revision,
            state.revision,
            &resources,
        )?;
        let digest = reference
            .as_str()
            .strip_prefix("grant_")
            .ok_or(ManagedGrantError::Changed)?;
        let subject = format!("greyward_as_grant_{digest}_t");
        let context = binding.grant_context(digest);
        let context_cil =
            grant_context_cil(digest, binding.production).ok_or(ManagedGrantError::Changed)?;
        let mut access_cil = String::new();
        let mut labels = Vec::new();
        for reference in &record.grant.resources {
            let label = denial
                .resource_label(reference)
                .ok_or(ManagedGrantError::Changed)?
                .to_owned();
            writeln!(
                access_cil,
                "(allow {subject} {label} (file (open read getattr)))"
            )
            .expect("String formatting");
            writeln!(
                access_cil,
                "(allow {subject} {label} (dir (open read search getattr)))"
            )
            .expect("String formatting");
            labels.push(label);
        }
        let program = Self {
            record,
            code_generation: code.generation().clone(),
            rpm_bound,
            actor: actor.identity().clone(),
            revision: state.revision,
            context,
            context_cil,
            access_cil,
            labels,
            deadline,
        };
        program.revalidate(store, actor, code)?;
        Ok(program)
    }
    pub fn context(&self) -> &str {
        &self.context
    }
    pub(crate) fn tool_profile(&self) -> Option<crate::ReviewedToolProfile> {
        self.record.tool_profile
    }
    pub fn context_cil(&self) -> &str {
        &self.context_cil
    }
    pub fn access_cil(&self) -> &str {
        &self.access_cil
    }
    /// # Errors
    /// Changed policy, caller or generation invalidates a prepared launch.
    pub fn revalidate(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        code: &InstalledExecutable,
    ) -> Result<(), ManagedGrantError> {
        actor.revalidate()?;
        crate::enrollment::ProviderBinding::for_actor(store, actor)?;
        code.revalidate()?;
        let state = store.desired_policy()?;
        let current =
            store.get_application(self.actor.owner_uid, &self.record.grant.installation_ref)?;
        if Instant::now() >= self.deadline
            || actor.identity() != &self.actor
            || state.revision != self.revision
            || !state.grants.iter().any(|g| g == &self.record)
            || current.is_none_or(|entry| entry.identity != self.record.installation)
            || code.generation() != &self.code_generation
        {
            return Err(ManagedGrantError::Changed);
        }
        if self.rpm_bound {
            verify_rpm_identity(&self.record, code, self.deadline)?;
        }
        Ok(())
    }
    /// Verify actual kernel read permissions and absence of write permissions.
    /// # Errors
    /// Stale policy, absent/permissive kernel state or partial decisions refuse.
    pub fn verify_active(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        code: &InstalledExecutable,
    ) -> Result<u32, ManagedGrantError> {
        self.revalidate(store, actor, code)?;
        self.kernel_decisions(true)
    }
    /// The domain must remain installed while its access rules are withdrawn.
    /// Existing mappings/already-read data require workload termination; this
    /// proves new reads are denied, not recall of information already delivered.
    /// # Errors
    /// A remaining grant record/allow, stale actor or missing kernel proof refuse.
    pub fn verify_revoked(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
    ) -> Result<u32, ManagedGrantError> {
        actor.revalidate()?;
        crate::enrollment::ProviderBinding::for_actor(store, actor)?;
        let state = store.desired_policy()?;
        if Instant::now() >= self.deadline
            || actor.identity() != &self.actor
            || state.revision <= self.revision
            || state
                .grants
                .iter()
                .any(|g| g.grant.grant_ref == self.record.grant.grant_ref)
        {
            return Err(ManagedGrantError::Changed);
        }
        self.kernel_decisions(false)
    }
    fn kernel_decisions(&self, active: bool) -> Result<u32, ManagedGrantError> {
        let mut sequence = None;
        for label in &self.labels {
            if Instant::now() >= self.deadline {
                return Err(ManagedGrantError::Changed);
            }
            let actual =
                crate::selinux_readback::reviewed_read_decision(&self.context, label, active)?;
            if sequence.is_some_and(|old| old != actual) {
                return Err(ManagedGrantError::Changed);
            }
            sequence = Some(actual);
        }
        sequence.ok_or(ManagedGrantError::Changed)
    }
}

#[cfg(test)]
pub(crate) fn development_grant_context(digest: &str) -> Option<String> {
    grant_context_cil(digest, false)
}
pub(crate) fn grant_context_cil(digest: &str, production: bool) -> Option<String> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let subject = format!("greyward_as_grant_{digest}_t");
    let mut cil = format!("(type {subject})\n");
    for attribute in [
        "domain",
        "process_user_target",
        "ubac_constrained_type",
        "greyward_as_managed_tool",
        "nsswitch_domain",
        "netlabel_peer_type",
        "kernel_system_state_reader",
    ] {
        writeln!(cil, "(typeattributeset {attribute} ({subject}))").expect("String formatting");
    }
    writeln!(
        cil,
        "(roletype {} {subject})",
        if production {
            "system_r"
        } else {
            "greyward_guard_owner_r"
        }
    )
    .expect("String formatting");
    Some(cil)
}

fn verify_rpm_identity(
    record: &GrantIntent,
    code: &InstalledExecutable,
    deadline: Instant,
) -> Result<(), ManagedGrantError> {
    let path = InstalledExecutablePath::try_from(code.selected_path())
        .map_err(|_| ManagedGrantError::Changed)?;
    let binding = crate::collect_installed_rpm_content(&path, deadline)
        .map_err(|_| ManagedGrantError::Changed)?;
    let observed = binding
        .observed_identity(record.grant.owner_uid)
        .map_err(|_| ManagedGrantError::Changed)?;
    if observed != record.installation || binding.generation() != &record.grant.generation {
        return Err(ManagedGrantError::Changed);
    }
    code.revalidate()?;
    Ok(())
}
