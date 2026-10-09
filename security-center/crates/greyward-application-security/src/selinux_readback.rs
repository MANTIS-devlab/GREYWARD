//! Live development-policy queries, never object labeling or session coverage.
//! A CIL digest alone cannot prove the kernel's policy or enforcing state.
use crate::{
    ResourceDenialProgram,
    resource_policy::{DIRECTORY_DENIALS, FILE_DENIALS, SYMLINK_DENIALS},
};
use greyward_security_domain::ContentGeneration;
use rustix::fs::fstatfs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};
use thiserror::Error;

const SUBJECT: &str = "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0";
const SELINUX_FS_MAGIC: i64 = 0xf97c_ff8c;
const MAX_LEASE: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum SelinuxReadbackError {
    #[error("Root and the actual enforcing SELinux filesystem are required")]
    Kernel,
    #[error("Development policy readback is empty, expired or unbounded")]
    Deadline,
    #[error("Kernel policy query is unsupported or malformed")]
    Protocol,
    #[error("Mandatory resource denial is absent or its domain is permissive")]
    NotDenied,
    #[error("Kernel policy changed during or after readback")]
    Changed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Syscall(#[from] rustix::io::Errno),
}

struct Decision {
    allowed: u32,
    decided: u32,
    sequence: u32,
    flags: u32,
}

fn parse_decision(value: &str) -> Result<Decision, SelinuxReadbackError> {
    let words: Vec<_> = value.split_whitespace().collect();
    if value.len() > 128 || words.len() != 6 {
        return Err(SelinuxReadbackError::Protocol);
    }
    let mut values = [0; 6];
    for (index, word) in words.iter().enumerate() {
        values[index] = if index == 4 {
            word.parse()
        } else {
            u32::from_str_radix(word, 16)
        }
        .map_err(|_| SelinuxReadbackError::Protocol)?;
    }
    Ok(Decision {
        allowed: values[0],
        decided: values[1],
        sequence: values[4],
        flags: values[5],
    })
}

fn denied(decision: &Decision, mask: u32) -> Result<(), SelinuxReadbackError> {
    // Any unknown flag refuses too. A domain-level permissive bit defeats the
    // deny promise even while the host's enforcing file remains 1.
    if mask == 0
        || decision.flags != 0
        || decision.decided & mask != mask
        || decision.allowed & mask != 0
    {
        return Err(SelinuxReadbackError::NotDenied);
    }
    Ok(())
}

fn deadline_check(deadline: Instant) -> Result<(), SelinuxReadbackError> {
    if Instant::now() >= deadline {
        Err(SelinuxReadbackError::Deadline)
    } else {
        Ok(())
    }
}

fn kernel_file(path: &str, writable: bool) -> Result<File, SelinuxReadbackError> {
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file()
        || file.metadata()?.uid() != 0
        || fstatfs(&file)?.f_type != SELINUX_FS_MAGIC
    {
        return Err(SelinuxReadbackError::Kernel);
    }
    Ok(file)
}

fn bounded_text(path: &str) -> Result<String, SelinuxReadbackError> {
    let mut value = String::new();
    kernel_file(path, false)?
        .take(129)
        .read_to_string(&mut value)?;
    if value.is_empty() || value.len() > 128 {
        return Err(SelinuxReadbackError::Protocol);
    }
    Ok(value)
}

fn enforcing() -> Result<(), SelinuxReadbackError> {
    if rustix::process::getuid().as_raw() != 0
        || rustix::process::geteuid().as_raw() != 0
        || bounded_text("/sys/fs/selinux/enforce")?.trim() != "1"
    {
        return Err(SelinuxReadbackError::Kernel);
    }
    Ok(())
}

/// Read the actual root-owned `SELinux` filesystem. Missing/unsupported kernel
/// evidence remains unknown; an explicit permissive kernel is known false.
pub(crate) fn enforcing_state() -> Option<bool> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        return None;
    }
    match bounded_text("/sys/fs/selinux/enforce").ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

fn query(label: &str, class: u16) -> Result<Decision, SelinuxReadbackError> {
    query_subject(SUBJECT, label, class)
}

fn query_subject(subject: &str, label: &str, class: u16) -> Result<Decision, SelinuxReadbackError> {
    // Labels come only from the bounded canonical program; no request text or
    // contexts from a frontend are accepted by this entry point.
    let target = format!("system_u:object_r:{label}:s0");
    query_context(subject, &target, class)
}

fn query_context(
    subject: &str,
    target: &str,
    class: u16,
) -> Result<Decision, SelinuxReadbackError> {
    let mut transaction = kernel_file("/sys/fs/selinux/access", true)?;
    transaction.write_all(format!("{subject} {target} {class}").as_bytes())?;
    let mut response = String::new();
    transaction.take(129).read_to_string(&mut response)?;
    parse_decision(&response)
}

/// Necessary process-isolation prerequisite, never a whole-session receipt.
/// Ordinary subjects must not inspect a separate authentication subject. Self
/// inspection is deliberately retained. This verifies type-policy decisions,
/// not the authentication UI, its executable, input path or agent registration.
pub(crate) fn enrollment_boundary_readback() -> Result<(), SelinuxReadbackError> {
    enforcing()?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut sequence = None;
    let authentication = "system_u:system_r:greyward_as_auth_t:s0";
    for subject in ordinary_subjects()? {
        for (class, rights) in [
            ("file", &["read", "write", "append"][..]),
            (
                "process",
                &[
                    "ptrace",
                    "signal",
                    "sigkill",
                    "sigstop",
                    "transition",
                    "dyntransition",
                ][..],
            ),
            ("fd", &["use"][..]),
            ("fifo_file", &["open", "read", "write", "append"][..]),
            ("unix_stream_socket", &["connectto"][..]),
        ] {
            deadline_check(deadline)?;
            let (index, mask) = class_mask(class, rights)?;
            let decision = query_context(&subject, authentication, index)?;
            denied(&decision, mask)?;
            if sequence.is_some_and(|old| old != decision.sequence) {
                return Err(SelinuxReadbackError::Changed);
            }
            sequence = Some(decision.sequence);
        }
    }
    for subject in [SUBJECT, authentication] {
        let (index, mask) = class_mask("file", &["read"])?;
        let decision = query_context(subject, subject, index)?;
        if decision.flags != 0 || decision.decided & mask != mask || decision.allowed & mask != mask
        {
            return Err(SelinuxReadbackError::NotDenied);
        }
        if sequence != Some(decision.sequence) {
            return Err(SelinuxReadbackError::Changed);
        }
    }
    enforcing()?;
    deadline_check(deadline)
}

fn ordinary_subjects() -> Result<Vec<String>, SelinuxReadbackError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/lib/greyward/application-security/desktop/ordinary.json")?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
        || meta.len() > 65536
    {
        return Err(SelinuxReadbackError::Protocol);
    }
    let value: serde_json::Value =
        serde_json::from_reader(file).map_err(|_| SelinuxReadbackError::Protocol)?;
    let types = value["ordinary"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or(SelinuxReadbackError::Protocol)?;
    let mut subjects = Vec::new();
    for value in types {
        let name = value
            .as_str()
            .filter(|s| {
                s.ends_with("_t")
                    && s.len() <= 128
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .ok_or(SelinuxReadbackError::Protocol)?;
        subjects.push(format!("greyward_guard_u:greyward_guard_r:{name}:s0"));
    }
    Ok(subjects)
}
pub(crate) fn ordinary_context_available() -> bool {
    enforcing().is_ok()
        && class_mask("file", &["read"]).is_ok_and(|(class, mask)| {
            query_context(SUBJECT, SUBJECT, class).is_ok_and(|decision| {
                decision.flags == 0
                    && decision.decided & mask == mask
                    && decision.allowed & mask == mask
            })
        })
}

pub(crate) fn reviewed_read_decision(
    subject: &str,
    label: &str,
    active: bool,
) -> Result<u32, SelinuxReadbackError> {
    enforcing()?;
    let (class, read) = class_mask("file", &["open", "read"])?;
    let (_, write) = class_mask(
        "file",
        &[
            "write",
            "append",
            "setattr",
            "relabelto",
            "relabelfrom",
            "unlink",
            "link",
            "execute",
        ],
    )?;
    let decision = query_subject(subject, label, class)?;
    denied(&decision, write)?;
    if active {
        if decision.decided & read != read || decision.allowed & read != read {
            return Err(SelinuxReadbackError::NotDenied);
        }
    } else {
        denied(&decision, read)?;
    }
    Ok(decision.sequence)
}

fn class_mask(class: &str, rights: &[&str]) -> Result<(u16, u32), SelinuxReadbackError> {
    let class_id: u16 = bounded_text(&format!("/sys/fs/selinux/class/{class}/index"))?
        .trim()
        .parse()
        .map_err(|_| SelinuxReadbackError::Protocol)?;
    if class_id == 0 {
        return Err(SelinuxReadbackError::Protocol);
    }
    let mut mask = 0;
    for right in rights {
        let position: u32 = bounded_text(&format!("/sys/fs/selinux/class/{class}/perms/{right}"))?
            .trim()
            .parse()
            .map_err(|_| SelinuxReadbackError::Protocol)?;
        if !(1..=32).contains(&position) {
            return Err(SelinuxReadbackError::Protocol);
        }
        mask |= 1 << (position - 1);
    }
    Ok((class_id, mask))
}

/// Process-private evidence of named type-policy decisions at one kernel
/// sequence. It proves no object label, workload, identity, grant or coverage.
/// Persisting/serializing this receipt cannot make it authoritative after restart.
pub struct DevelopmentDenialReadback {
    program: ContentGeneration,
    policy_revision: u64,
    sequence: u32,
    anchor_label: String,
    anchor_class: u16,
    anchor_mask: u32,
    labels: usize,
    deadline: Instant,
}

impl DevelopmentDenialReadback {
    /// Requires a hard-bounded root worker: between-call deadlines do not cancel
    /// stalled syscalls. Never invoked by the experimental public read broker.
    /// # Errors
    /// Missing policy, permissive state, unexpected grants, changed kernel
    /// sequence, unsupported interfaces or an expired/unbounded lease refuse.
    pub fn read(
        program: &ResourceDenialProgram,
        deadline: Instant,
    ) -> Result<Self, SelinuxReadbackError> {
        if deadline
            .checked_duration_since(Instant::now())
            .is_none_or(|remaining| remaining.is_zero() || remaining > MAX_LEASE)
        {
            return Err(SelinuxReadbackError::Deadline);
        }
        enforcing()?;
        let classes = [
            ("file", FILE_DENIALS),
            ("dir", DIRECTORY_DENIALS),
            ("lnk_file", SYMLINK_DENIALS),
        ]
        .into_iter()
        .map(|(class, rights)| class_mask(class, rights))
        .collect::<Result<Vec<_>, _>>()?;
        let anchor_label = program
            .labels()
            .next()
            .ok_or(SelinuxReadbackError::Deadline)?
            .to_owned();
        let mut sequence = None;
        let mut labels = 0;
        let subjects = if program.cil().contains("greyward_as_ordinary") {
            ordinary_subjects()?
        } else {
            vec![SUBJECT.to_owned()]
        };
        for label in program.labels() {
            for subject in &subjects {
                for (class, mask) in &classes {
                    deadline_check(deadline)?;
                    let decision = query_subject(subject, label, *class)?;
                    denied(&decision, *mask)?;
                    if sequence.is_some_and(|old| old != decision.sequence) {
                        return Err(SelinuxReadbackError::Changed);
                    }
                    sequence = Some(decision.sequence);
                }
            }
            labels += 1;
        }
        let receipt = Self {
            program: program.generation().clone(),
            policy_revision: program.revision(),
            sequence: sequence.ok_or(SelinuxReadbackError::Protocol)?,
            anchor_label,
            anchor_class: classes[0].0,
            anchor_mask: classes[0].1,
            labels,
            deadline,
        };
        receipt.revalidate(program)?;
        Ok(receipt)
    }

    /// # Errors
    /// Expired receipts, changed program/revision or a changed/permissive kernel.
    pub fn revalidate(&self, program: &ResourceDenialProgram) -> Result<(), SelinuxReadbackError> {
        deadline_check(self.deadline)?;
        if program.generation() != &self.program || program.revision() != self.policy_revision {
            return Err(SelinuxReadbackError::Changed);
        }
        enforcing()?;
        let decision = query(&self.anchor_label, self.anchor_class)?;
        denied(&decision, self.anchor_mask)?;
        if decision.sequence != self.sequence {
            return Err(SelinuxReadbackError::Changed);
        }
        deadline_check(self.deadline)
    }

    pub fn labels_checked(&self) -> usize {
        self.labels
    }
    pub fn kernel_sequence(&self) -> u32 {
        self.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_decision_parser_refuses_partial_oversized_or_unknown_protocol() {
        for value in [
            "",
            "0 ffffffff",
            "0 ffffffff 0 0 a 0",
            "0 ffffffff 0 0 1 0 extra",
            "g ffffffff 0 0 1 0",
        ] {
            assert!(parse_decision(value).is_err());
        }
        assert!(parse_decision(&"0".repeat(129)).is_err());
        let decision = parse_decision("a ffffffff 0 ffffffff 42 0").unwrap();
        assert_eq!(decision.sequence, 42);
        assert_eq!(decision.allowed, 10);
    }

    #[test]
    fn an_allow_partial_decision_or_domain_permissive_flag_is_not_denial() {
        for value in [
            "2 ffffffff 0 0 42 0",
            "0 1 0 0 42 0",
            "0 ffffffff 0 0 42 1",
            "0 ffffffff 0 0 42 2",
        ] {
            assert!(denied(&parse_decision(value).unwrap(), 2).is_err());
        }
        let decision = parse_decision("1 ffffffff 0 0 42 0").unwrap();
        assert!(denied(&decision, 2).is_ok());
        assert!(denied(&decision, 0).is_err());
    }

    #[test]
    fn a_cached_receipt_cannot_follow_another_revision_or_outlive_its_lease() {
        let program = ResourceDenialProgram::prepare_development_baseline(2, 2, 1002, &[]).unwrap();
        let mut receipt = DevelopmentDenialReadback {
            program: program.generation().clone(),
            policy_revision: 2,
            sequence: 1,
            anchor_label: "unused".into(),
            anchor_class: 1,
            anchor_mask: 1,
            labels: 0,
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let next = ResourceDenialProgram::prepare_development_baseline(3, 3, 1002, &[]).unwrap();
        assert!(matches!(
            receipt.revalidate(&next),
            Err(SelinuxReadbackError::Changed)
        ));
        receipt.deadline = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            receipt.revalidate(&program),
            Err(SelinuxReadbackError::Deadline)
        ));
    }
}
