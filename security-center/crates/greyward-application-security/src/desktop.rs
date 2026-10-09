//! Fixed local-session admission through the existing root broker.
use crate::{ExecutionHandle, PolicyStore, StoreError};
use std::process::{Command, Stdio};

pub(crate) fn verified(uid: u32) -> bool {
    verified_mode(uid, false)
}
pub(crate) fn locked(uid: u32) -> bool {
    verified_mode(uid, true)
}
fn verified_mode(uid: u32, locked: bool) -> bool {
    let mut command = Command::new("/usr/bin/timeout");
    command
        .env_clear()
        .args([
            "--kill-after=1",
            "3",
            "/usr/bin/python3",
            "-I",
            "/usr/lib/greyward/application-security/desktop/verify.py",
        ])
        .arg(uid.to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if locked {
        command.arg("--locked");
    }
    let output = command.output();
    output.is_ok_and(|result| {
        result.status.success()
            && result.stdout.len() < 4096
            && serde_json::from_slice::<serde_json::Value>(&result.stdout)
                .is_ok_and(|v| v == serde_json::json!({"verified": true}))
    })
}
pub(crate) fn lock(actor: &ExecutionHandle) -> Result<(), StoreError> {
    actor
        .revalidate()
        .map_err(|_| StoreError::InvalidPolicyIntent)?;
    let store = PolicyStore::open_system()?;
    let _binding =
        crate::enrollment::ProviderBinding::production(&store, actor.identity().owner_uid)?;
    let status = Command::new("/usr/bin/timeout")
        .env_clear()
        .args([
            "--kill-after=1",
            "4",
            "/usr/bin/python3",
            "-I",
            "/usr/lib/greyward/application-security/desktop/session.py",
            "--lock",
        ])
        .arg(actor.identity().owner_uid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(StoreError::InvalidPolicyIntent);
    }
    actor
        .revalidate()
        .map_err(|_| StoreError::InvalidPolicyIntent)
}

pub(crate) fn start(actor: &ExecutionHandle) -> Result<(), StoreError> {
    actor
        .revalidate()
        .map_err(|_| StoreError::InvalidPolicyIntent)?;
    let store = PolicyStore::open_system()?;
    let _binding =
        crate::enrollment::ProviderBinding::production(&store, actor.identity().owner_uid)?;
    let id = actor.identity();
    if id.selinux_context != crate::enrollment::ProviderBinding::subject_context() {
        return Err(StoreError::InvalidPolicyIntent);
    }
    // Only kernel-bound numeric identity is forwarded. The fixed helper checks
    // the actual logind leader/seat/scope and the immutable prepared generation.
    let status = Command::new("/usr/bin/timeout")
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .args([
            "--kill-after=1",
            "20",
            "/usr/bin/systemd-run",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--no-ask-password",
            "-p",
            "NoNewPrivileges=no",
            "-p",
            "RuntimeMaxSec=18",
            "-p",
            "TimeoutStopSec=2",
            "--",
            "/usr/bin/python3",
            "-I",
            "/usr/lib/greyward/application-security/desktop/session.py",
            "--start",
        ])
        .arg(id.owner_uid.to_string())
        .arg(id.pid.to_string())
        .arg(id.start_ticks.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()?;
    actor
        .revalidate()
        .map_err(|_| StoreError::InvalidPolicyIntent)?;
    if !status.success() {
        return Err(StoreError::InvalidPolicyIntent);
    }
    Ok(())
}
