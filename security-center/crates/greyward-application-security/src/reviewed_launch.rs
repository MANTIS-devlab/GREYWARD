//! Root-prepared, generation-bound launch for the fixed development provider.
//! A launched workload is not a whole-session protection receipt. Graphical
//! exposure, supplemental restrictions and public broker dispatch remain separate.
use crate::{
    ExecutionHandle, InstalledExecutable, ManagedCode, ManagedCodeStore, ManagedContentError,
    ManagedGrantError, PolicyStore, ReviewedReadGrant,
};
use greyward_security_domain::SecurityReference;
use std::fmt::Write;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;
const ENTRYPOINT: &str = "/usr/libexec/greyward-guard-entry";

fn entrypoint() -> Result<(), ReviewedLaunchError> {
    for path in ["/", "/usr", "/usr/libexec"] {
        let value = std::fs::symlink_metadata(path)?;
        if !value.is_dir() || value.uid() != 0 || value.gid() != 0 || value.mode() & 0o022 != 0 {
            return Err(ReviewedLaunchError::Invalid);
        }
    }
    let value = std::fs::symlink_metadata(ENTRYPOINT)?;
    if !value.is_file()
        || value.uid() != 0
        || value.gid() != 0
        || value.nlink() != 1
        || value.len() != 0
        || value.mode() & 0o777 != 0o555
    {
        return Err(ReviewedLaunchError::Invalid);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ReviewedLaunchError {
    #[error("Reviewed launch arguments, deadline or worker prerequisites are invalid")]
    Invalid,
    #[error(transparent)]
    Grant(#[from] ManagedGrantError),
    #[error(transparent)]
    Content(#[from] ManagedContentError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Syscall(#[from] rustix::io::Errno),
}

fn arguments(values: &[String]) -> Result<(), ReviewedLaunchError> {
    if values.len() > 32
        || values.iter().any(|v| v.contains('\0') || v.len() > 4096)
        || values.iter().map(String::len).sum::<usize>() > 8192
    {
        return Err(ReviewedLaunchError::Invalid);
    }
    Ok(())
}

/// This type cannot be deserialized from a UI request. Preparation copies the
/// held installed generation into root-only immutable storage. Neither a path
/// label nor a systemd scope authorizes a grant.
pub struct PreparedReviewedLaunch {
    source: InstalledExecutable,
    managed: ManagedCode,
    grant: ReviewedReadGrant,
    args: Vec<String>,
    deadline: Instant,
}

impl PreparedReviewedLaunch {
    /// # Errors
    /// Foreign/stale reviews, changed generations, unsafe cache and unbounded
    /// inputs refuse. The current provider supports only enrolled probe UID 1002.
    pub fn prepare(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        source: InstalledExecutable,
        cache: &ManagedCodeStore,
        args: Vec<String>,
        deadline: Instant,
    ) -> Result<Self, ReviewedLaunchError> {
        Self::prepare_bound(
            store, actor, reference, source, cache, args, deadline, false,
        )
    }

    /// # Errors
    /// The RPM installation/member generation and immutable code digest must
    /// both match the reviewed policy; neither can stand in for the other.
    pub fn prepare_rpm(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        source: InstalledExecutable,
        cache: &ManagedCodeStore,
        args: Vec<String>,
        deadline: Instant,
    ) -> Result<Self, ReviewedLaunchError> {
        Self::prepare_bound(store, actor, reference, source, cache, args, deadline, true)
    }

    #[allow(clippy::too_many_arguments)] // Two independent bindings, not a UI payload.
    fn prepare_bound(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
        source: InstalledExecutable,
        cache: &ManagedCodeStore,
        args: Vec<String>,
        deadline: Instant,
        rpm_bound: bool,
    ) -> Result<Self, ReviewedLaunchError> {
        arguments(&args)?;
        if deadline
            .checked_duration_since(Instant::now())
            .is_none_or(|d| d.is_zero() || d > Duration::from_secs(120))
        {
            return Err(ReviewedLaunchError::Invalid);
        }
        let grant = if rpm_bound {
            ReviewedReadGrant::prepare_rpm(store, actor, reference, &source, deadline)?
        } else {
            ReviewedReadGrant::prepare(store, actor, reference, &source, deadline)?
        };
        let binding = crate::enrollment::ProviderBinding::for_actor(store, actor)
            .map_err(|_| ReviewedLaunchError::Invalid)?;
        if grant.tool_profile().is_none_or(|profile| {
            !profile.accepts_code(source.selected_path(), source.generation())
                || !profile.accepts_arguments(&binding.home, &args)
        }) {
            return Err(ReviewedLaunchError::Invalid);
        }
        grant.verify_active(store, actor, &source)?;
        let mut managed = cache.import(source.content(), deadline)?;
        managed.prepare_entrypoint(deadline)?;
        if managed.generation() != source.generation() {
            return Err(ReviewedLaunchError::Invalid);
        }
        grant.verify_active(store, actor, &source)?;
        Ok(Self {
            source,
            managed,
            grant,
            args,
            deadline,
        })
    }

    /// Consume a prepared launch once. PID 1 binds the still-held immutable
    /// descriptor into a private mount before exec; an installed path is never
    /// reopened for execution. No environment, unit property, context or root
    /// command is selected by the user. Failures have no unrestricted fallback.
    /// # Errors
    /// Deadline, review/generation/kernel changes or failed service submission.
    pub fn spawn(
        self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
    ) -> Result<RunningReviewedLaunch, ReviewedLaunchError> {
        let binding = crate::enrollment::ProviderBinding::for_actor(store, actor)
            .map_err(|_| ReviewedLaunchError::Invalid)?;
        entrypoint()?;
        self.managed.revalidate()?;
        self.grant.verify_active(store, actor, &self.source)?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(ReviewedLaunchError::Invalid)?;
        if remaining < Duration::from_secs(1) {
            return Err(ReviewedLaunchError::Invalid);
        }
        let descriptor = self.managed.entry_descriptor()?;
        let source = format!("/proc/{}/fd/{}", std::process::id(), descriptor.as_raw_fd());
        let mut nonce = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let mut suffix = String::with_capacity(32);
        for byte in nonce {
            write!(suffix, "{byte:02x}").expect("String formatting");
        }
        let unit = format!("greyward-appsec-launch-{suffix}");
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .args([
                "--quiet",
                "--wait",
                "--collect",
                "--no-ask-password",
                "--expand-environment=no",
                "--service-type=exec",
            ])
            .arg(format!("--unit={unit}"));
        for value in [
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "PrivateNetwork=yes",
            "PrivateMounts=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "TasksMax=64",
            "MemoryMax=256M",
            "CPUQuota=100%",
            "TimeoutStartSec=10",
            "TimeoutStopSec=2",
            "KillMode=control-group",
        ] {
            command.args(["-p", value]);
        }
        command
            .args(["-p", &format!("User={}", binding.uid)])
            .args(["-p", &format!("Group={}", binding.gid)])
            .args([
                "-p",
                &format!(
                    "Environment=PATH=/usr/bin:/bin HOME={} LANG=C.UTF-8",
                    binding.home
                ),
            ])
            .args(["-p", &format!("RuntimeMaxSec={}", remaining.as_secs())])
            .args(["-p", &format!("SELinuxContext={}", self.grant.context())])
            .args(["-p", &format!("BindReadOnlyPaths={source}:{ENTRYPOINT}")]);
        if self.grant.tool_profile().is_some() {
            // PID 1 opens null streams itself. Passing the broker's descriptors
            // with --pipe would require an unnecessary cross-domain FD grant.
            for setting in [
                "StandardInput=null",
                "StandardOutput=null",
                "StandardError=null",
            ] {
                command.args(["-p", setting]);
            }
            // No key/comment/error/command-input channel is exported by the
            // tested inspection contract. Only its bounded exit status is
            // returned. Redirect at launch, not after reading sensitive output.
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        } else {
            command.arg("--pipe");
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        command.args(["--", ENTRYPOINT]).args(&self.args);
        // Hold both descriptors until the unit exits. Closing them after spawn
        // would let PID 1 resolve a stale/reused descriptor before mount setup.
        let child = command.spawn()?;
        Ok(RunningReviewedLaunch {
            child,
            unit,
            prepared: self,
            _descriptor: descriptor,
        })
    }
}

/// Owns only its generated root unit and held immutable code. `RuntimeMaxSec` is
/// enforced by PID 1 even if the broker disappears. No PROTECTED badge is minted.
pub struct RunningReviewedLaunch {
    child: Child,
    unit: String,
    prepared: PreparedReviewedLaunch,
    _descriptor: std::os::fd::OwnedFd,
}
impl RunningReviewedLaunch {
    /// Direct streams go only to the authenticated launching caller. The broker
    /// neither buffers nor records application output or secret contents.
    /// # Errors
    /// Missing pipes or descriptor duplication refuse stream transfer.
    pub fn streams(
        &mut self,
    ) -> Result<(std::fs::File, std::fs::File, std::fs::File), ReviewedLaunchError> {
        if self.prepared.grant.tool_profile().is_some() {
            return Ok((
                std::fs::OpenOptions::new().write(true).open("/dev/null")?,
                std::fs::File::open("/dev/null")?,
                std::fs::File::open("/dev/null")?,
            ));
        }
        let input = self
            .child
            .stdin
            .take()
            .ok_or(ReviewedLaunchError::Invalid)?;
        let output = self
            .child
            .stdout
            .take()
            .ok_or(ReviewedLaunchError::Invalid)?;
        let error = self
            .child
            .stderr
            .take()
            .ok_or(ReviewedLaunchError::Invalid)?;
        Ok((
            rustix::io::dup(&input)?.into(),
            rustix::io::dup(&output)?.into(),
            rustix::io::dup(&error)?.into(),
        ))
    }
    pub fn stdin(&mut self) -> Option<&mut std::process::ChildStdin> {
        self.child.stdin.as_mut()
    }
    pub fn stdout(&mut self) -> Option<&mut std::process::ChildStdout> {
        self.child.stdout.as_mut()
    }
    pub fn stderr(&mut self) -> Option<&mut std::process::ChildStderr> {
        self.child.stderr.as_mut()
    }
    /// # Errors
    /// Live policy or code changes refuse; a stored intent never grants access.
    pub fn revalidate(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
    ) -> Result<(), ReviewedLaunchError> {
        self.prepared.managed.revalidate()?;
        self.prepared
            .grant
            .verify_active(store, actor, &self.prepared.source)?;
        Ok(())
    }
    /// # Errors
    /// Failed manager communication/child wait. An exit code is an operation
    /// result, not proof of a protection profile or whole-session coverage.
    pub fn wait(&mut self) -> Result<std::process::ExitStatus, ReviewedLaunchError> {
        Ok(self.child.wait()?)
    }
}
impl Drop for RunningReviewedLaunch {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            // Unit identity is random and created only by this root preparation.
            // Never stop a user-supplied unit or kill an unbound numerical PID.
            let _ = Command::new("/usr/bin/timeout")
                .env_clear()
                .env("PATH", "/usr/bin:/usr/sbin")
                .args([
                    "--kill-after=1",
                    "3",
                    "/usr/bin/systemctl",
                    "--no-block",
                    "stop",
                    &self.unit,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::arguments;
    #[test]
    fn launch_argument_budget_is_bounded_without_reinterpreting_shell_text() {
        assert!(arguments(&["$(not-a-shell)".into(), "--property=User=0".into()]).is_ok());
        assert!(arguments(&["bad\0argument".into()]).is_err());
        assert!(arguments(&vec![String::new(); 33]).is_err());
        assert!(arguments(&["x".repeat(4097)]).is_err());
        assert!(arguments(&vec!["x".repeat(4000); 3]).is_err());
    }
}
