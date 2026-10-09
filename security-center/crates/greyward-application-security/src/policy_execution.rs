//! Typed enforcement continuation for the separate-account development provider.
//! Stored intent and successful compiler exit never substitute for kernel/object
//! readback. No generic command, supplied CIL, label or module name is exposed.
use crate::{
    DesiredPolicyCommit, DevelopmentDenialReadback, ExecutionHandle, InstalledExecutable,
    ManagedGrantError, PolicyStore, RegisteredDirectory, ResourceDenialProgram,
    ResourceRegistrationError, ReviewedReadGrant, StoreError,
};
use greyward_security_domain::SecurityReference;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::process::{Command, Stdio};
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyExecutionError {
    #[error("Development enforcement prerequisites, generation or deadline changed")]
    Unavailable,
    #[error("Enforcement installation failed; no effective protection was established")]
    Installation,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Registration(#[from] ResourceRegistrationError),
    #[error(transparent)]
    Grant(#[from] ManagedGrantError),
    #[error(transparent)]
    Policy(#[from] crate::ResourcePolicyError),
    #[error(transparent)]
    Kernel(#[from] crate::SelinuxReadbackError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Syscall(#[from] rustix::io::Errno),
}

/// Bounded reviewed-grant provider. Broader contexts and production storage
/// are unavailable until the corresponding provider is implemented. Mutations
/// require the nonserializable commit minted by fresh owner authorization.
pub struct DevelopmentKernelProvider {
    directory: File,
    binding: crate::enrollment::ProviderBinding,
}

impl DevelopmentKernelProvider {
    fn contexts(&self, new: &str) -> Result<String, PolicyExecutionError> {
        let path = self
            .binding
            .path()
            .join(format!("{}.cil", self.binding.module("context")));
        let previous = match OpenOptions::new()
            .read(true)
            .custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                    .map_err(|_| PolicyExecutionError::Unavailable)?,
            )
            .open(path)
        {
            Ok(mut file) => {
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != 0
                    || metadata.gid() != 0
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o777 != 0o600
                    || metadata.len() > 65536
                {
                    return Err(PolicyExecutionError::Unavailable);
                }
                let mut text = String::new();
                file.read_to_string(&mut text)?;
                text
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        retain_contexts_for(&previous, new, self.binding.production)
    }
    /// # Errors
    /// Root-private ancestry and assertion-enabled private compiler configuration
    /// are mandatory. This never changes the host compiler configuration.
    pub fn open() -> Result<Self, PolicyExecutionError> {
        Self::open_bound(crate::enrollment::ProviderBinding::development())
    }

    pub(crate) fn open_bound(
        binding: crate::enrollment::ProviderBinding,
    ) -> Result<Self, PolicyExecutionError> {
        let base = binding.path();
        if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
            return Err(PolicyExecutionError::Unavailable);
        }
        for path in base.ancestors() {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(PolicyExecutionError::Unavailable);
            }
        }
        if std::fs::metadata(base)?.mode() & 0o777 != 0o700 {
            return Err(PolicyExecutionError::Unavailable);
        }
        let config = OpenOptions::new()
            .read(true)
            .custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                    .map_err(|_| PolicyExecutionError::Unavailable)?,
            )
            .open(base.join("semanage.conf"))?;
        let metadata = config.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > 16384
        {
            return Err(PolicyExecutionError::Unavailable);
        }
        let text = std::fs::read_to_string(base.join("semanage.conf"))?;
        if text
            .lines()
            .filter(|line| line.trim() == "expand-check=1")
            .count()
            != 1
            || text.lines().any(|line| line.trim() == "expand-check=0")
        {
            return Err(PolicyExecutionError::Unavailable);
        }
        Ok(Self {
            directory: File::open(base)?,
            binding,
        })
    }

    fn actor(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        deadline: Instant,
    ) -> Result<(), PolicyExecutionError> {
        actor
            .revalidate()
            .map_err(|_| PolicyExecutionError::Unavailable)?;
        if Instant::now() >= deadline
            || crate::enrollment::ProviderBinding::for_actor(store, actor)? != self.binding
        {
            return Err(PolicyExecutionError::Unavailable);
        }
        Ok(())
    }

    fn install(
        &self,
        module: &str,
        cil: &str,
        deadline: Instant,
    ) -> Result<(), PolicyExecutionError> {
        let base = self.binding.path();
        let directory = self.directory.metadata()?;
        let current = std::fs::symlink_metadata(base)?;
        if !current.is_dir() || (current.dev(), current.ino()) != (directory.dev(), directory.ino())
        {
            return Err(PolicyExecutionError::Unavailable);
        }
        if ![
            self.binding.module("resource"),
            self.binding.module("context"),
            self.binding.module("access"),
        ]
        .iter()
        .any(|m| m == module)
            || cil.len() > 4 * 1024 * 1024
            || Instant::now() >= deadline
        {
            return Err(PolicyExecutionError::Unavailable);
        }
        let path = base.join(format!("{module}.cil"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                    .map_err(|_| PolicyExecutionError::Unavailable)?,
            )
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(PolicyExecutionError::Unavailable);
        }
        file.set_len(0)?;
        file.write_all(cil.as_bytes())?;
        file.sync_all()?;
        let base = self.binding.path();
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(PolicyExecutionError::Unavailable)?;
        let timeout = remaining.as_secs().clamp(1, 90).to_string();
        let status = Command::new("/usr/bin/timeout")
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .args([
                "--kill-after=1",
                &timeout,
                "/usr/sbin/semodule",
                "-g",
                base.join("semanage.conf")
                    .to_str()
                    .ok_or(PolicyExecutionError::Unavailable)?,
                "-i",
                path.to_str().ok_or(PolicyExecutionError::Unavailable)?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() || Instant::now() >= deadline {
            return Err(PolicyExecutionError::Installation);
        }
        Ok(())
    }

    /// Continue a consumed, freshly authorized descriptor registration. The
    /// returned receipt retains actual labeled objects; journal loading cannot
    /// produce this type after a broker restart.
    /// # Errors
    /// Installation, object, actor, revision or kernel changes refuse completion.
    pub fn register(
        &self,
        registration: crate::ResourceRegistrationLease,
        store: &mut PolicyStore,
        actor: &ExecutionHandle,
        deadline: Instant,
    ) -> Result<RegisteredDirectory, PolicyExecutionError> {
        self.actor(store, actor, deadline)?;
        let state = store.desired_policy()?;
        if state.revision != registration.revision {
            return Err(PolicyExecutionError::Unavailable);
        }
        let resources: Vec<_> = state
            .resources
            .into_iter()
            .filter(|r| r.resource().owner_uid == self.binding.uid)
            .collect();
        let program = ResourceDenialProgram::prepare_bound(
            &self.binding,
            state.revision,
            state.revision,
            &resources,
        )?;
        self.install(&self.binding.module("resource"), program.cil(), deadline)?;
        self.actor(store, actor, deadline)?;
        let kernel = DevelopmentDenialReadback::read(
            &program,
            deadline.min(Instant::now() + std::time::Duration::from_secs(30)),
        )?;
        let receipt = registration.apply_labels(store, actor, &program, &kernel)?;
        store
            .live_resources
            .insert(receipt.resource_ref().clone(), receipt.retain()?);
        Ok(receipt)
    }

    /// # Errors
    /// Expired/foreign records or code changes
    /// refuse. Context installation precedes read access and actual readback.
    pub fn activate_read_grant(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        code: &InstalledExecutable,
        deadline: Instant,
    ) -> Result<ReviewedReadGrant, PolicyExecutionError> {
        self.actor(store, actor, deadline)?;
        let state = store.desired_policy()?;
        let record = state
            .grants
            .iter()
            .find(|r| r.proposal().grant_ref == *reference)
            .ok_or(PolicyExecutionError::Unavailable)?;
        if state.grants.len() > 16 {
            return Err(PolicyExecutionError::Unavailable);
        }
        let preserved = Self::active_access(store, actor, reference, deadline)?;
        let grant = if record.proposal().generation == *code.generation() {
            ReviewedReadGrant::prepare(store, actor, reference, code, deadline)?
        } else {
            ReviewedReadGrant::prepare_rpm(store, actor, reference, code, deadline)?
        };
        // Keep revoked subject types installed. Replacing the module with only
        // a new type must not remap a still-running old subject to unlabeled_t.
        // This bounded cache carries contexts only, never any resource allow.
        self.install(
            &self.binding.module("context"),
            &self.contexts(grant.context_cil())?,
            deadline,
        )?;
        grant.revalidate(store, actor, code)?;
        let mut access = String::new();
        for old in &preserved {
            access.push_str(old.access_cil());
        }
        access.push_str(grant.access_cil());
        self.install(&self.binding.module("access"), &access, deadline)?;
        grant.verify_active(store, actor, code)?;
        for old in preserved {
            old.verify(store, actor, true)?;
        }
        Ok(grant)
    }

    fn active_access(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        excluded: &SecurityReference,
        deadline: Instant,
    ) -> Result<Vec<crate::managed_grant::RecordedReadAccess>, PolicyExecutionError> {
        let mut active = Vec::new();
        for record in store.desired_policy()?.grants {
            if record.proposal().owner_uid != actor.identity().owner_uid
                || &record.proposal().grant_ref == excluded
            {
                continue;
            }
            let access = crate::managed_grant::RecordedReadAccess::prepare(
                store,
                actor,
                &record.proposal().grant_ref,
                deadline,
            )?;
            // Desired records from a failed operation must never be activated
            // by someone else's later authorization. Preserve only live rules.
            if access.verify(store, actor, true).is_ok() {
                active.push(access);
            }
        }
        Ok(active)
    }

    /// Withdraw access while retaining the context so live denials are testable.
    /// This cannot recall already-read data or terminate an unrelated process.
    /// # Errors
    /// A successful database revoke without successful kernel denial is failure.
    pub fn revoke_read_grant(
        &self,
        commit: DesiredPolicyCommit,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        grant: &ReviewedReadGrant,
        deadline: Instant,
    ) -> Result<u32, PolicyExecutionError> {
        self.revoke_recorded_read_grant(commit, store, actor, &grant.revocation_access(), deadline)
    }

    pub(crate) fn revoke_recorded_read_grant(
        &self,
        commit: DesiredPolicyCommit,
        store: &PolicyStore,
        actor: &ExecutionHandle,
        grant: &crate::managed_grant::RecordedReadAccess,
        deadline: Instant,
    ) -> Result<u32, PolicyExecutionError> {
        self.actor(store, actor, deadline)?;
        let revision = commit.revision;
        drop(commit);
        if store.desired_policy()?.revision != revision {
            return Err(PolicyExecutionError::Unavailable);
        }
        // The revoked reference is no longer in desired state. Only preserve
        // other records whose exact contexts still have kernel read permission.
        let excluded = SecurityReference::try_from(format!("grant_{}", "0".repeat(64)))
            .map_err(|_| PolicyExecutionError::Unavailable)?;
        let preserved = Self::active_access(store, actor, &excluded, deadline)?;
        if !preserved.is_empty() {
            let access: String = preserved
                .iter()
                .map(crate::managed_grant::RecordedReadAccess::access_cil)
                .collect();
            self.install(&self.binding.module("access"), &access, deadline)?;
            for old in &preserved {
                old.verify(store, actor, true)?;
            }
            return Ok(grant.verify(store, actor, false)?);
        }
        let base = self.binding.path();
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(PolicyExecutionError::Unavailable)?;
        let timeout = remaining.as_secs().clamp(1, 90).to_string();
        let status = Command::new("/usr/bin/timeout")
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .args([
                "--kill-after=1",
                &timeout,
                "/usr/sbin/semodule",
                "-g",
                base.join("semanage.conf")
                    .to_str()
                    .ok_or(PolicyExecutionError::Unavailable)?,
                "-r",
                &self.binding.module("access"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(PolicyExecutionError::Installation);
        }
        self.actor(store, actor, deadline)?;
        Ok(grant.verify(store, actor, false)?)
    }
}

#[cfg(test)]
fn retain_contexts(previous: &str, new: &str) -> Result<String, PolicyExecutionError> {
    retain_contexts_for(previous, new, false)
}

fn retain_contexts_for(
    previous: &str,
    new: &str,
    production: bool,
) -> Result<String, PolicyExecutionError> {
    let mut digests = std::collections::BTreeSet::new();
    for text in [previous, new] {
        let mut lines = text.lines().peekable();
        while let Some(first) = lines.next() {
            let digest = first
                .strip_prefix("(type greyward_as_grant_")
                .and_then(|s| s.strip_suffix("_t)"))
                .ok_or(PolicyExecutionError::Unavailable)?;
            let mut chunk = vec![first];
            while lines.peek().is_some_and(|line| !line.starts_with("(type ")) {
                chunk.push(lines.next().expect("Peeked line"));
            }
            let canonical = crate::managed_grant::grant_context_cil(digest, production)
                .ok_or(PolicyExecutionError::Unavailable)?;
            // Accept only the exact earlier root-generated six-line schema for
            // retention. Never import supplied allows or arbitrary memberships.
            let legacy = canonical
                .lines()
                .filter(|line| {
                    !line.starts_with("(typeattributeset nsswitch_domain ")
                        && !line.starts_with("(typeattributeset netlabel_peer_type ")
                        && !line.starts_with("(typeattributeset kernel_system_state_reader ")
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let supplied = chunk.join("\n") + "\n";
            if supplied != canonical && supplied != legacy {
                return Err(PolicyExecutionError::Unavailable);
            }
            digests.insert(digest.to_owned());
        }
    }
    if digests.is_empty() || digests.len() > 32 {
        return Err(PolicyExecutionError::Unavailable);
    }
    Ok(digests
        .iter()
        .filter_map(|d| crate::managed_grant::grant_context_cil(d, production))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retired_subjects_remain_typed_without_importing_allow_rules() {
        let old = crate::managed_grant::development_grant_context(&"a".repeat(64)).unwrap();
        let new = crate::managed_grant::development_grant_context(&"b".repeat(64)).unwrap();
        let retained = retain_contexts(&old, &new).unwrap();
        assert!(retained.contains(&old));
        assert!(retained.contains(&new));
        assert!(!retained.contains("(allow "));
        assert_eq!(retain_contexts(&old, &old).unwrap(), old);
        let legacy = old
            .lines()
            .take(5)
            .chain(old.lines().last())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(retain_contexts(&legacy, &old).unwrap(), old);
        assert!(retain_contexts(&(new.clone() + "(allow forged bypass)\n"), &new).is_err());
        assert!(retain_contexts(&(legacy + "(typeattributeset forged bypass)\n"), &new).is_err());
    }
}
