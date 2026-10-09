//! Bounded root audit projection, not a policy or second history database.
//! Only bounded executable basenames and historical PIDs cross this boundary;
//! no path, argv, environment or process-title fields are retained.
use crate::{ResourceDenialProgram, framed_digest};
use greyward_security_domain::SecurityReference;
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const CHUNK: u64 = 256 * 1024;
const RETAIN: usize = 256;
#[derive(Clone, Serialize)]
pub(crate) struct AccessEvent {
    sequence: u64,
    event_id: String,
    resource_ref: SecurityReference,
    action: String,
    decision: &'static str,
    attribution: &'static str,
    process: Option<ObservedProcess>,
    occurred_at_ms: Option<u64>,
    policy_revision: u64,
}
#[derive(Clone, Serialize)]
struct ObservedProcess {
    pid: u32,
    executable_name: String,
    source: &'static str,
}
#[derive(Default)]
struct Record {
    denied: Option<(String, String)>,
    failed_uid: Option<u32>,
    process: Option<ObservedProcess>,
    emitted: bool,
}
#[derive(Default)]
pub(crate) struct AccessEvents {
    file: Option<File>,
    partial: String,
    records: BTreeMap<String, Record>,
    events: VecDeque<AccessEvent>,
    sequence: u64,
    truncated: bool,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_ascii_whitespace()
        .find_map(|token| token.strip_prefix(key))
}
fn audit_id(line: &str) -> Option<&str> {
    let id = field(line, "msg=audit(")?.strip_suffix("):")?;
    (id.len() <= 64 && id.bytes().all(|c| c.is_ascii_digit() || b".:".contains(&c))).then_some(id)
}
fn audit_time(id: &str) -> Option<u64> {
    let (seconds, fraction) = id.split_once(':')?.0.split_once('.')?;
    if fraction.is_empty() || fraction.len() > 9 {
        return None;
    }
    let millis = format!("{fraction:0<3}");
    seconds
        .parse::<u64>()
        .ok()?
        .checked_mul(1000)?
        .checked_add(millis[..3].parse().ok()?)
}
fn observed_process(line: &str) -> Option<ObservedProcess> {
    let pid = field(line, "pid=")?
        .parse::<u32>()
        .ok()
        .filter(|p| *p > 0)?;
    let raw = field(line, "exe=")?;
    let executable = if let Some(quoted) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        quoted.to_owned()
    } else {
        if raw.len() > 8192 || raw.len() % 2 != 0 {
            return None;
        }
        let bytes: Option<Vec<u8>> = raw
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digits = std::str::from_utf8(pair).ok()?;
                u8::from_str_radix(digits, 16).ok()
            })
            .collect();
        String::from_utf8(bytes?).ok()?
    };
    if !executable.starts_with('/') || executable.len() > 4096 {
        return None;
    }
    let name = executable.rsplit('/').next()?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
    {
        return None;
    }
    Some(ObservedProcess {
        pid,
        executable_name: name.to_owned(),
        source: "KERNEL_AUDIT",
    })
}
fn denial(line: &str) -> Option<(String, String)> {
    if !line.starts_with("type=AVC ") || field(line, "permissive=") != Some("0") {
        return None;
    }
    let subject = field(line, "scontext=")?.split(':').nth(2)?;
    if subject != "greyward_guard_t" && !subject.starts_with("greyward_as_subject_") {
        return None;
    }
    let rights = line.split_once("avc:  denied  { ")?.1.split_once(" }")?.0;
    let action = if rights.split_ascii_whitespace().any(|r| r == "read") {
        "READ"
    } else if rights
        .split_ascii_whitespace()
        .any(|r| matches!(r, "write" | "append"))
    {
        "WRITE"
    } else if rights.split_ascii_whitespace().any(|r| r == "open") {
        "OPEN"
    } else {
        return None;
    };
    let target = field(line, "tcontext=")?.split(':').nth(2)?;
    Some((target.to_owned(), action.to_owned()))
}

impl AccessEvents {
    /// Start at the current end: no unbounded replay or secret-bearing logs.
    pub(crate) fn open() -> Self {
        let mut result = Self {
            file: Self::audit_file().ok(),
            ..Self::default()
        };
        if let Some(file) = &mut result.file {
            if file.seek(SeekFrom::End(0)).is_err() {
                result.file = None;
            }
        }
        result
    }
    fn audit_file() -> std::io::Result<File> {
        for directory in ["/var", "/var/log", "/var/log/audit"] {
            let m = std::fs::symlink_metadata(directory)?;
            if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/var/log/audit/audit.log")?;
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(file)
    }
    fn collect(&mut self, policy: &ResourceDenialProgram) -> std::io::Result<()> {
        let current = Self::audit_file()?;
        let same = self.file.as_ref().is_some_and(|file| {
            file.metadata().is_ok_and(|m| {
                current
                    .metadata()
                    .is_ok_and(|c| c.ino() == m.ino() && c.dev() == m.dev())
            })
        });
        if !same {
            self.file = Some(current);
            self.partial.clear();
            self.records.clear();
            self.truncated = true;
        }
        let file = self.file.as_mut().ok_or(std::io::ErrorKind::NotFound)?;
        if file.stream_position()? > file.metadata()?.len() {
            file.seek(SeekFrom::Start(0))?;
            self.partial.clear();
            self.records.clear();
            self.truncated = true;
        }
        let mut bytes = Vec::new();
        file.take(CHUNK).read_to_end(&mut bytes)?;
        let text = String::from_utf8(bytes).map_err(|_| std::io::ErrorKind::InvalidData)?;
        self.partial.push_str(&text);
        let Some(end) = self.partial.rfind('\n') else {
            if self.partial.len() > 16384 {
                self.partial.clear();
                self.truncated = true;
            }
            return Ok(());
        };
        let lines = self.partial[..=end].to_owned();
        self.partial.drain(..=end);
        for line in lines.lines().filter(|line| line.len() <= 16384) {
            self.ingest(line, policy);
        }
        if self.records.len() > RETAIN {
            self.records.clear();
            self.truncated = true;
        }
        Ok(())
    }
    fn ingest(&mut self, line: &str, policy: &ResourceDenialProgram) {
        let Some(id) = audit_id(line) else {
            return;
        };
        if !line.starts_with("type=AVC ") && !line.starts_with("type=SYSCALL ") {
            return;
        }
        let record = self.records.entry(id.to_owned()).or_default();
        if let Some(denied) = denial(line) {
            record.denied = Some(denied);
        }
        if line.starts_with("type=SYSCALL ")
            && field(line, "success=") == Some("no")
            && matches!(field(line, "exit="), Some("-13" | "-1"))
        {
            record.failed_uid = field(line, "uid=").and_then(|uid| uid.parse().ok());
            record.process = observed_process(line);
        }
        let (Some((target, action)), Some(uid)) = (&record.denied, record.failed_uid) else {
            return;
        };
        if uid != policy.owner_uid() || record.emitted {
            return;
        }
        let Some(reference) = policy.reference_for_label(target) else {
            return;
        };
        record.emitted = true;
        self.sequence += 1;
        let boot = std::fs::read("/proc/sys/kernel/random/boot_id").unwrap_or_default();
        self.events.push_back(AccessEvent {
            sequence: self.sequence,
            event_id: format!(
                "appsec-denial-{}",
                framed_digest(&[&boot, id.as_bytes(), target.as_bytes(), action.as_bytes()])
            ),
            resource_ref: reference.clone(),
            action: action.clone(),
            decision: "DENIED",
            attribution: "UNKNOWN",
            process: record.process.clone(),
            occurred_at_ms: audit_time(id),
            policy_revision: policy.revision(),
        });
        if self.events.len() > RETAIN {
            self.events.pop_front();
        }
    }
    pub(crate) fn read(
        &mut self,
        cursor: u64,
        limit: usize,
        policy: &ResourceDenialProgram,
    ) -> serde_json::Value {
        let available = std::fs::read("/sys/fs/selinux/enforce").is_ok_and(|v| v == b"1")
            && self.collect(policy).is_ok();
        let events: Vec<_> = if available {
            self.events
                .iter()
                .filter(|e| e.sequence > cursor)
                .take(limit)
                .cloned()
                .collect()
        } else {
            vec![]
        };
        let next = events
            .last()
            .map_or(self.sequence.min(cursor), |e| e.sequence);
        serde_json::json!({"schema": "greyward.application-security/v1",
            "source_state": if available {"AVAILABLE"} else {"UNAVAILABLE"},
            "cursor": next, "truncated": self.truncated || cursor > self.sequence
                || self.events.front().is_some_and(|e| cursor < e.sequence.saturating_sub(1)),
            "events": events})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_process_metadata_keeps_no_private_path_or_title() {
        let process =
            observed_process("pid=42 exe=\"/home/test/private/bin/python3\" comm=forged").unwrap();
        assert_eq!(process.pid, 42);
        assert_eq!(process.executable_name, "python3");
        assert_eq!(
            observed_process("pid=8 exe=2F7573722F62696E2F636174")
                .unwrap()
                .executable_name,
            "cat"
        );
        for line in [
            "pid=0 exe=\"/usr/bin/cat\"",
            "pid=42 exe=\"/usr/bin/<script>\"",
            "pid=42 comm=brave",
            "pid=42 exe=ZZ",
            "pid=42 exe=\"relative\"",
        ] {
            assert!(observed_process(line).is_none());
        }
        assert_eq!(audit_time("123.4:7"), Some(123_400));
        assert_eq!(audit_time("123.456789:7"), Some(123_456));
        assert!(audit_time("18446744073709551615.123:7").is_none());
    }
    #[test]
    fn only_enforcing_resource_denials_without_process_claims() {
        let line = "type=AVC msg=audit(123.456:7): avc:  denied  { read } for pid=42 name=secret scontext=u:r:greyward_guard_t:s0 tcontext=u:object_r:resource_t:s0 tclass=file permissive=0";
        assert_eq!(audit_id(line), Some("123.456:7"));
        assert_eq!(denial(line), Some(("resource_t".into(), "READ".into())));
        assert!(denial(&line.replace("permissive=0", "permissive=1")).is_none());
        assert!(denial(&line.replace("greyward_guard_t", "unconfined_t")).is_none());
        assert!(denial(&line.replace("{ read }", "{ ioctl }")).is_none());
    }
}
