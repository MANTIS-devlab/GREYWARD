//! Protected graphical administration admission, never in the requesting subject.
use crate::{ExecutionHandle, PolicyStore, StoreError};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

pub(crate) fn request(actor: &ExecutionHandle, arguments: &[String]) -> Result<(), StoreError> {
    actor
        .revalidate()
        .map_err(|_| StoreError::InvalidPolicyIntent)?;
    if arguments.is_empty()
        || arguments.len() > 128
        || arguments.iter().map(String::len).sum::<usize>() > 16384
        || arguments.iter().any(|a| a.chars().any(char::is_control))
        || actor.identity().selinux_context != crate::enrollment::ProviderBinding::subject_context()
    {
        return Err(StoreError::InvalidPolicyIntent);
    }
    let store = PolicyStore::open_system()?;
    crate::enrollment::ProviderBinding::production(&store, actor.identity().owner_uid)?;
    if !crate::desktop::verified(actor.identity().owner_uid)
        || crate::desktop::locked(actor.identity().owner_uid)
    {
        return Err(StoreError::InvalidPolicyIntent);
    }
    let id = actor.identity();
    let path = format!(
        "/run/greyward-application-security/admin-request-{}-{}.json",
        id.owner_uid, id.pid
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let payload = serde_json::to_vec(&serde_json::json!({"arguments": arguments}))
        .map_err(|_| StoreError::InvalidPolicyIntent)?;
    file.write_all(&payload)?;
    file.sync_all()?;
    let result = Command::new("/usr/bin/timeout")
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .args([
            "--kill-after=1",
            "5",
            "/usr/bin/systemd-run",
            "--quiet",
            "--collect",
            "--no-ask-password",
            "-p",
            "Type=notify",
            "-p",
            "NotifyAccess=main",
            "-p",
            "NoNewPrivileges=no",
            "-p",
            "TimeoutStartSec=4",
            "-p",
            "TimeoutStopSec=5",
            "-p",
            "PrivateMounts=yes",
            "--unit",
        ])
        .arg(format!("greyward-admin-{}.service", id.owner_uid))
        .args(["-p", &format!("BindsTo=user@{}.service", id.owner_uid)])
        .args([
            "--",
            "/usr/bin/python3",
            "-I",
            "/usr/lib/greyward/application-security/administration/worker.py",
        ])
        .arg(id.owner_uid.to_string())
        .arg(id.pid.to_string())
        .arg(id.start_ticks.to_string())
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = std::fs::remove_file(&path);
    actor
        .revalidate()
        .map_err(|_| StoreError::InvalidPolicyIntent)?;
    if !result.is_ok_and(|status| status.success()) {
        return Err(StoreError::InvalidPolicyIntent);
    }
    Ok(())
}

pub(crate) fn devices() -> Result<String, StoreError> {
    let output = Command::new("/usr/bin/timeout")
        .env_clear()
        .args([
            "--kill-after=1",
            "4",
            "/usr/bin/python3",
            "-I",
            "/usr/share/greyward-application-security/administration/device-projection.py",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.len() > 256 * 1024 {
        return Err(StoreError::InvalidPolicyIntent);
    }
    let data: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| StoreError::InvalidPolicyIntent)?;
    if data.get("schema") != Some(&serde_json::json!("greyward.device-projection/v1"))
        || !data.get("devices").is_some_and(serde_json::Value::is_array)
    {
        return Err(StoreError::InvalidPolicyIntent);
    }
    String::from_utf8(output.stdout).map_err(|_| StoreError::InvalidPolicyIntent)
}

pub(crate) fn state(uid: u32) -> Result<String, StoreError> {
    let output = Command::new("/usr/bin/timeout")
        .env_clear()
        .args([
            "--kill-after=1",
            "4",
            "/usr/bin/python3",
            "-I",
            "/usr/lib/greyward/application-security/administration/worker.py",
            "--status",
        ])
        .arg(uid.to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(StoreError::InvalidPolicyIntent);
    }
    String::from_utf8(output.stdout).map_err(|_| StoreError::InvalidPolicyIntent)
}
