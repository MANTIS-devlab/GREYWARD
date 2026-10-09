//! Additive restrictions for a single prepared worker, never arbitrary exec.
//! Namespace/display construction, descriptor cleanup, code validation and
//! mandatory resource policy remain separate prerequisites of the launch owner.
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, RestrictSelfAttr, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
use rustix::fs::{OFlags, fcntl_getfl};
use rustix::io::{FdFlags, fcntl_getfd};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NativeRestrictionError {
    #[error("A prepared metadata-only descriptor is required")]
    Descriptor,
    #[error("Invalid or oversized native restriction plan")]
    Plan,
    #[error("Native restriction worker privilege/context prerequisites are absent")]
    Worker,
    #[error("Required Landlock ABI 9 restrictions were not established")]
    Landlock,
    #[error("Required seccomp restrictions were not established")]
    Seccomp,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRuleKind {
    ReadCodeTree,
    ReadCodeFile,
    /// Fixed broker-validated read-only mounts in a single-UID child namespace.
    /// Unmapped ownership establishes no publisher identity or grant authority.
    NamespaceCodeTree,
    NamespaceCodeFile,
    PrivateScratch,
    SelectedReadFile,
    NullDevice,
    PrivateDisplay,
}

/// No path is reopened. The root preparation owner chooses and validates the
/// exposed object; these structural checks alone establish no resource grant.
pub struct NativeDescriptorRule {
    file: File,
    kind: NativeRuleKind,
}

impl NativeDescriptorRule {
    /// # Errors
    /// Refuses non-O_PATH descriptors, unexpected object classes, shared/writable
    /// code trees and scratch directories not private to the worker's UID.
    pub fn capture(
        descriptor: OwnedFd,
        kind: NativeRuleKind,
    ) -> Result<Self, NativeRestrictionError> {
        let file = File::from(descriptor);
        if !fcntl_getfl(&file)?.contains(OFlags::PATH)
            || !fcntl_getfd(&file)?.contains(FdFlags::CLOEXEC)
        {
            return Err(NativeRestrictionError::Descriptor);
        }
        let metadata = file.metadata()?;
        let valid = match kind {
            NativeRuleKind::ReadCodeTree => {
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
            }
            NativeRuleKind::ReadCodeFile => {
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0
                    && metadata.mode() & 0o111 != 0
            }
            NativeRuleKind::NamespaceCodeTree | NativeRuleKind::NamespaceCodeFile => {
                let readonly = rustix::fs::fstatvfs(&file)?
                    .f_flag
                    .contains(rustix::fs::StatVfsMountFlags::RDONLY);
                metadata.uid() == 65534
                    && metadata.mode() & 0o022 == 0
                    && readonly
                    && if kind == NativeRuleKind::NamespaceCodeTree {
                        metadata.is_dir()
                    } else {
                        metadata.is_file() && metadata.mode() & 0o111 != 0
                    }
            }
            NativeRuleKind::PrivateScratch => {
                metadata.is_dir()
                    && metadata.uid() == rustix::process::getuid().as_raw()
                    && metadata.mode() & 0o777 == 0o700
            }
            NativeRuleKind::SelectedReadFile => metadata.is_file(),
            NativeRuleKind::PrivateDisplay => {
                metadata.is_dir()
                    && metadata.uid() == rustix::process::getuid().as_raw()
                    && matches!(metadata.mode() & 0o7777, 0o700 | 0o1777)
            }
            NativeRuleKind::NullDevice => {
                std::os::unix::fs::FileTypeExt::is_char_device(&metadata.file_type())
                    && metadata.rdev() == rustix::fs::makedev(1, 3)
            }
        };
        if !valid {
            return Err(NativeRestrictionError::Descriptor);
        }
        Ok(Self { file, kind })
    }
}

/// Internal worker evidence of successful synchronous restriction, not a
/// PROTECTED/ISOLATED profile or proof of namespace, display or MAC coverage.
pub struct NativeRestrictionEvidence {
    pub landlock_abi: u32,
    pub seccomp: bool,
    pub no_new_privileges: bool,
}

fn worker_prerequisites(expected_context: &str) -> Result<(), NativeRestrictionError> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0
        || uid != rustix::process::geteuid().as_raw()
        || expected_context.len() > 1024
        || expected_context
            .split(':')
            .nth(2)
            .is_none_or(|domain| !domain.starts_with("greyward_"))
    {
        return Err(NativeRestrictionError::Worker);
    }
    let context = std::fs::read_to_string("/proc/self/attr/current")?;
    if context.trim_end_matches(['\0', '\n']) != expected_context {
        return Err(NativeRestrictionError::Worker);
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let single_thread = status.lines().any(|line| line == "Threads:\t1");
    let no_capabilities = ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:"]
        .iter()
        .all(|prefix| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .is_some_and(|value| value.trim() == "0000000000000000")
        });
    let expected_uid = uid.to_string();
    let equal_uids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .is_some_and(|value| {
            let values: Vec<_> = value.split_whitespace().collect();
            values.len() == 4 && values.iter().all(|value| *value == expected_uid)
        });
    if !single_thread || !no_capabilities || !equal_uids {
        return Err(NativeRestrictionError::Worker);
    }
    Ok(())
}

fn network_disconnected_filter(
    private_display: bool,
) -> Result<ScmpFilterContext, NativeRestrictionError> {
    let mut filter =
        ScmpFilterContext::new(ScmpAction::Allow).map_err(|_| NativeRestrictionError::Seccomp)?;
    for name in [
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "unshare",
        "setns",
        "mount",
        "umount2",
        "pivot_root",
        "fsopen",
        "fsmount",
        "move_mount",
        "open_tree",
        "mount_setattr",
        "open_by_handle_at",
        "name_to_handle_at",
        "bpf",
        "perf_event_open",
        "keyctl",
        "add_key",
        "request_key",
        "userfaultfd",
        "kexec_load",
        "init_module",
        "finit_module",
        "delete_module",
        "reboot",
        "swapon",
        "swapoff",
        "io_uring_setup",
    ] {
        filter
            .add_rule(
                ScmpAction::Errno(libc::EPERM),
                ScmpSyscall::from_name(name).map_err(|_| NativeRestrictionError::Seccomp)?,
            )
            .map_err(|_| NativeRestrictionError::Seccomp)?;
    }
    for name in ["socket", "socketpair"] {
        let call = ScmpSyscall::from_name(name).map_err(|_| NativeRestrictionError::Seccomp)?;
        if private_display {
            filter
                .add_rule_conditional(
                    ScmpAction::Errno(libc::EPERM),
                    call,
                    &[ScmpArgCompare::new(
                        0,
                        ScmpCompareOp::NotEqual,
                        u64::try_from(libc::AF_UNIX)
                            .map_err(|_| NativeRestrictionError::Seccomp)?,
                    )],
                )
                .map_err(|_| NativeRestrictionError::Seccomp)?;
        } else {
            filter
                .add_rule(ScmpAction::Errno(libc::EPERM), call)
                .map_err(|_| NativeRestrictionError::Seccomp)?;
        }
    }
    if !private_display {
        filter
            .add_rule(
                ScmpAction::Errno(libc::EPERM),
                ScmpSyscall::from_name("connect").map_err(|_| NativeRestrictionError::Seccomp)?,
            )
            .map_err(|_| NativeRestrictionError::Seccomp)?;
    }
    deny_namespace_clone(&mut filter)?;
    filter
        .set_ctl_tsync(true)
        .map_err(|_| NativeRestrictionError::Seccomp)?;
    Ok(filter)
}

fn deny_namespace_clone(filter: &mut ScmpFilterContext) -> Result<(), NativeRestrictionError> {
    // clone3 passes a pointer to mutable arguments. ENOSYS allows libc to use
    // clone for ordinary threads/forks; namespace flags there are scalar values.
    filter
        .add_rule(
            ScmpAction::Errno(libc::ENOSYS),
            ScmpSyscall::from_name("clone3").map_err(|_| NativeRestrictionError::Seccomp)?,
        )
        .map_err(|_| NativeRestrictionError::Seccomp)?;
    let clone = ScmpSyscall::from_name("clone").map_err(|_| NativeRestrictionError::Seccomp)?;
    for flag in [
        libc::CLONE_NEWNS,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ] {
        let flag = u64::try_from(flag).map_err(|_| NativeRestrictionError::Seccomp)?;
        filter
            .add_rule_conditional(
                ScmpAction::Errno(libc::EPERM),
                clone,
                &[ScmpArgCompare::new(
                    0,
                    ScmpCompareOp::MaskedEqual(flag),
                    flag,
                )],
            )
            .map_err(|_| NativeRestrictionError::Seccomp)?;
    }
    Ok(())
}

/// Apply the disconnected/headless subset of managed native restrictions.
/// Call only in a disposable prepared worker with all unintended FDs closed.
/// Any error after partial establishment requires worker exit, never retrying
/// an unrestricted launch. No network-enabled/graphical profile is implied.
/// # Errors
/// Missing descriptors/context, partial ABI support or filter failure refuse
/// readiness. The owning worker must also have an independent hard deadline.
pub fn restrict_native_disconnected(
    expected_context: &str,
    rules: Vec<NativeDescriptorRule>,
) -> Result<NativeRestrictionEvidence, NativeRestrictionError> {
    restrict_native(expected_context, rules, false)
}
/// # Errors
/// The caller must first establish the private mount/PID/network namespaces and
/// expose only its nested display. `AF_UNIX` is allowed; Internet sockets are denied.
pub fn restrict_native_private_display(
    expected_context: &str,
    rules: Vec<NativeDescriptorRule>,
) -> Result<NativeRestrictionEvidence, NativeRestrictionError> {
    restrict_native(expected_context, rules, true)
}
fn restrict_native(
    expected_context: &str,
    rules: Vec<NativeDescriptorRule>,
    private_display: bool,
) -> Result<NativeRestrictionEvidence, NativeRestrictionError> {
    if rules.is_empty()
        || rules.len() > 64
        || !rules.iter().any(|rule| {
            rule.kind == NativeRuleKind::ReadCodeTree
                || (private_display && rule.kind == NativeRuleKind::NamespaceCodeTree)
        })
        || !rules
            .iter()
            .any(|rule| rule.kind == NativeRuleKind::PrivateScratch)
    {
        return Err(NativeRestrictionError::Plan);
    }
    worker_prerequisites(expected_context)?;
    // Construct the complete filter before changing process restrictions.
    let filter = network_disconnected_filter(private_display)?;
    let abi = ABI::V9;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|_| NativeRestrictionError::Landlock)?
        .create()
        .map_err(|_| NativeRestrictionError::Landlock)?;
    for rule in rules {
        let access = match rule.kind {
            NativeRuleKind::ReadCodeTree | NativeRuleKind::NamespaceCodeTree => {
                AccessFs::from_read(abi)
            }
            NativeRuleKind::ReadCodeFile | NativeRuleKind::NamespaceCodeFile => {
                AccessFs::ReadFile | AccessFs::Execute
            }
            NativeRuleKind::PrivateScratch => AccessFs::from_all(abi),
            NativeRuleKind::SelectedReadFile => AccessFs::ReadFile.into(),
            NativeRuleKind::NullDevice => AccessFs::ReadFile | AccessFs::WriteFile,
            NativeRuleKind::PrivateDisplay => AccessFs::ReadFile | AccessFs::ReadDir,
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(rule.file, access))
            .map_err(|_| NativeRestrictionError::Landlock)?;
    }
    let status = ruleset
        .all_threads(true)
        .map_err(|_| NativeRestrictionError::Landlock)?
        .no_new_privs(true)
        .restrict_self()
        .map_err(|_| NativeRestrictionError::Landlock)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(NativeRestrictionError::Landlock);
    }
    filter.load().map_err(|_| NativeRestrictionError::Seccomp)?;
    Ok(NativeRestrictionEvidence {
        landlock_abi: 9,
        seccomp: true,
        no_new_privileges: true,
    })
}
