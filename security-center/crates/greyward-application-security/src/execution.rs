//! Descriptor-bound peer identity; neither titles nor client-supplied PIDs count.
use crate::registry::framed_digest;
use greyward_security_domain::{ExecutionIdentity, SecurityReference};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("Authenticated process descriptor or identity is unavailable")]
    Unavailable,
    #[error("Execution identity changed or the process exited")]
    Changed,
    #[error("Invalid or excessive kernel identity data")]
    Invalid,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
}

/// Construct only from the system bus's `GetConnectionCredentials` response.
/// There is deliberately no deserialization or frontend command for this type.
pub struct BusPeerCredentials {
    pub uid: u32,
    pub pid: u32,
    pub selinux_label: String,
    pub process_fd: OwnedFd,
}

pub struct ExecutionHandle {
    identity: ExecutionIdentity,
    process_fd: OwnedFd,
    proc_directory: File,
    executable: ObjectStamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectStamp {
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn bounded_read(mut file: File, limit: u64) -> Result<String, ExecutionError> {
    let mut bytes = Vec::new();
    file.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ExecutionError::Invalid)? > limit {
        return Err(ExecutionError::Invalid);
    }
    String::from_utf8(bytes).map_err(|_| ExecutionError::Invalid)
}

fn proc_read(directory: &File, relative: &str, limit: u64) -> Result<String, ExecutionError> {
    let descriptor = openat2(
        directory,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )?;
    bounded_read(File::from(descriptor), limit)
}

fn start_ticks(stat: &str, pid: u32) -> Result<u64, ExecutionError> {
    // comm is attacker-controlled and may contain whitespace/parentheses.
    // Never persist it, and parse fields only after its final closing bracket.
    let (prefix, _) = stat.split_once(' ').ok_or(ExecutionError::Invalid)?;
    if prefix.parse::<u32>().ok() != Some(pid) {
        return Err(ExecutionError::Changed);
    }
    let close = stat.rfind(')').ok_or(ExecutionError::Invalid)?;
    let ticks = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(ExecutionError::Invalid)?
        .parse::<u64>()
        .map_err(|_| ExecutionError::Invalid)?;
    if ticks == 0 {
        return Err(ExecutionError::Invalid);
    }
    Ok(ticks)
}

fn uid_matches(status: &str, expected: u32) -> bool {
    let Some(values) = status.lines().find_map(|line| line.strip_prefix("Uid:")) else {
        return false;
    };
    let values: Vec<_> = values.split_whitespace().collect();
    values.len() == 4
        && values
            .iter()
            .all(|value| value.parse::<u32>().ok() == Some(expected))
}

fn executable_stamp(directory: &File) -> Result<ObjectStamp, ExecutionError> {
    // The fixed procfs exe magic link is intentional; no client path is used.
    // Hold the process directory while obtaining the kernel's current object.
    let descriptor = openat2(
        directory,
        "exe",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::empty(),
    )?;
    let metadata = File::from(descriptor).metadata()?;
    if !metadata.is_file() {
        return Err(ExecutionError::Invalid);
    }
    Ok(ObjectStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

impl ExecutionHandle {
    /// Bind the bus-authenticated pidfd to live UID, start time and context.
    /// Missing `ProcessFD` must remain unavailable; never fall back to a title,
    /// guessed parent or a pidfd freshly opened from a client-supplied PID.
    /// # Errors
    /// Rejects non-pidfd descriptors, changed/exited processes and inconsistent
    /// UID/context data. This does not authorize a policy change.
    pub fn capture(credentials: BusPeerCredentials) -> Result<Self, ExecutionError> {
        if credentials.pid == 0 {
            return Err(ExecutionError::Invalid);
        }
        let info = bounded_read(
            File::open(format!(
                "/proc/self/fdinfo/{}",
                credentials.process_fd.as_raw_fd()
            ))?,
            4096,
        )?;
        let descriptor_pid = info.lines().find_map(|line| line.strip_prefix("Pid:"));
        if descriptor_pid.and_then(|value| value.trim().parse::<u32>().ok())
            != Some(credentials.pid)
        {
            return Err(ExecutionError::Unavailable);
        }
        let proc_directory = File::open(format!("/proc/{}", credentials.pid))?;
        let ticks = start_ticks(&proc_read(&proc_directory, "stat", 8192)?, credentials.pid)?;
        let context = proc_read(&proc_directory, "attr/current", 1024)?;
        let context = context.trim_end_matches(['\0', '\n']).to_owned();
        let uid = credentials.uid.to_le_bytes();
        let pid = credentials.pid.to_le_bytes();
        let start = ticks.to_le_bytes();
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        let reference = framed_digest(&[
            b"execution/v1",
            &uid,
            &pid,
            &start,
            boot.as_bytes(),
            context.as_bytes(),
        ]);
        let identity = ExecutionIdentity {
            execution_ref: SecurityReference::try_from(format!("execution_{reference}"))
                .map_err(|_| ExecutionError::Invalid)?,
            installation_ref: None, // A process is not an authenticated app installation.
            owner_uid: credentials.uid,
            boot_id: boot,
            pid: credentials.pid,
            start_ticks: ticks,
            selinux_context: context,
        };
        identity.validate().map_err(|_| ExecutionError::Invalid)?;
        if identity.selinux_context != credentials.selinux_label.trim_end_matches('\0') {
            return Err(ExecutionError::Changed);
        }
        let executable = executable_stamp(&proc_directory)?;
        let handle = Self {
            identity,
            process_fd: credentials.process_fd,
            proc_directory,
            executable,
        };
        handle.revalidate()?;
        Ok(handle)
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    /// Check again before authorization/commit; the pidfd stays held throughout.
    /// # Errors
    /// Rejects exit, UID/context/exec changes, PID reuse and inaccessible evidence.
    pub fn revalidate(&self) -> Result<(), ExecutionError> {
        let mut descriptors = [PollFd::new(&self.process_fd, PollFlags::IN)];
        if poll(
            &mut descriptors,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )? != 0
            || start_ticks(
                &proc_read(&self.proc_directory, "stat", 8192)?,
                self.identity.pid,
            )? != self.identity.start_ticks
            || !uid_matches(
                &proc_read(&self.proc_directory, "status", 16384)?,
                self.identity.owner_uid,
            )
            || proc_read(&self.proc_directory, "attr/current", 1024)?.trim_end_matches(['\0', '\n'])
                != self.identity.selinux_context
            || executable_stamp(&self.proc_directory)? != self.executable
        {
            return Err(ExecutionError::Changed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_names_cannot_shift_start_time_or_become_attribution() {
        let stat = format!("42 (a ) deceptive name) S {} 17 0", "1 ".repeat(18));
        assert_eq!(start_ticks(&stat, 42).unwrap(), 17);
        assert!(start_ticks(&stat, 43).is_err());
        assert!(start_ticks("42 missing-fields", 42).is_err());
    }

    #[test]
    fn all_uid_fields_must_match_the_authenticated_peer() {
        assert!(uid_matches("Name:\tx\nUid:\t1002 1002 1002 1002\n", 1002));
        assert!(!uid_matches("Uid:\t1002 0 1002 1002\n", 1002));
        assert!(!uid_matches("Uid:\t1002\n", 1002));
    }
}
