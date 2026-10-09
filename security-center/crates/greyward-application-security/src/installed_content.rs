//! Held installed-file evidence. Only the broker's filesystem namespace is used.
//! This proves path/content coherence, not provenance, immutability or a launch.
use crate::{CandidateContent, ContentError};
use greyward_security_domain::{ContentGeneration, InstalledExecutablePath};
use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InstalledContentError {
    #[error("Only a bounded canonical installed /usr executable is supported")]
    InvalidPath,
    #[error("Installed ancestry must be root-owned, non-writable directories")]
    UnsafeAncestor,
    #[error("Installed executable membership changed during verification")]
    Changed,
    #[error("Installed executable verification expired")]
    Deadline,
    #[error(transparent)]
    Content(#[from] ContentError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
}

#[derive(Debug, PartialEq, Eq)]
struct DirectoryStamp {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    changed: (i64, i64),
}

impl From<Metadata> for DirectoryStamp {
    fn from(value: Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            owner: value.uid(),
            group: value.gid(),
            mode: value.mode(),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

struct Ancestor {
    file: File,
    stamp: DirectoryStamp,
}

fn deadline_check(deadline: Instant) -> Result<(), InstalledContentError> {
    if Instant::now() >= deadline {
        Err(InstalledContentError::Deadline)
    } else {
        Ok(())
    }
}

fn components(path: &str) -> Result<Vec<&str>, InstalledContentError> {
    InstalledExecutablePath::try_from(path).map_err(|_| InstalledContentError::InvalidPath)?;
    Ok(path[1..].split('/').collect())
}

fn directory(file: File) -> Result<Ancestor, InstalledContentError> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() == 0
        || metadata.mode() & 0o7022 != 0
    {
        return Err(InstalledContentError::UnsafeAncestor);
    }
    Ok(Ancestor {
        file,
        stamp: DirectoryStamp::from(metadata),
    })
}

const RESOLUTION: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

/// Nonserializable proof with no caller-supplied root descriptor or exported FD.
/// The system broker must call this from its own trusted mount/user namespace.
/// A path supplied by the webview never becomes an identity/grant automatically.
pub struct InstalledExecutable {
    path: String,
    ancestors: Vec<Ancestor>,
    content: CandidateContent,
    deadline: Instant,
}

impl InstalledExecutable {
    /// Open each ancestor without symlinks, magic links or mount crossings,
    /// retain it, then hash the held read-only regular executable. Unsupported
    /// separate /usr mounts and symlink launch paths remain explicit failures.
    /// A blocked filesystem syscall needs an independent worker hard deadline.
    /// # Errors
    /// Mutable/unowned ancestors, alias mounts, invalid paths and expiry fail.
    pub fn capture(path: &str, deadline: Instant) -> Result<Self, InstalledContentError> {
        deadline_check(deadline)?;
        components(path)?;
        let root = File::from(open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        Self::capture_from_root(root, path, deadline)
    }

    fn capture_from_root(
        root: File,
        path: &str,
        deadline: Instant,
    ) -> Result<Self, InstalledContentError> {
        deadline_check(deadline)?;
        let parts = components(path)?;
        let mut ancestors = vec![directory(root)?];
        for part in &parts[..parts.len() - 1] {
            deadline_check(deadline)?;
            let parent = &ancestors
                .last()
                .ok_or(InstalledContentError::InvalidPath)?
                .file;
            let child = File::from(openat2(
                parent,
                *part,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLUTION,
            )?);
            ancestors.push(directory(child)?);
        }
        let parent = &ancestors
            .last()
            .ok_or(InstalledContentError::InvalidPath)?
            .file;
        let descriptor = openat2(
            parent,
            *parts.last().ok_or(InstalledContentError::InvalidPath)?,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLUTION,
        )?;
        let content = CandidateContent::capture(descriptor, deadline)?;
        if content.root_package_mode().is_none() {
            return Err(InstalledContentError::Content(
                ContentError::InvalidDescriptor,
            ));
        }
        let selected = Self {
            path: path.to_owned(),
            ancestors,
            content,
            deadline,
        };
        selected.revalidate()?;
        Ok(selected)
    }

    pub fn generation(&self) -> &ContentGeneration {
        self.content.generation()
    }

    pub(crate) fn content(&self) -> &CandidateContent {
        &self.content
    }

    pub(crate) fn selected_path(&self) -> &str {
        &self.path
    }

    /// Check held ancestry and verify each link still names the held child.
    /// Reopened metadata descriptors are never returned or used for execution.
    /// This cannot seal code, cancel stalled syscalls or prevent later writes.
    /// # Errors
    /// Rename, replacement, metadata change, alias insertion or expiry invalidates.
    pub fn revalidate(&self) -> Result<(), InstalledContentError> {
        deadline_check(self.deadline)?;
        let parts = components(&self.path)?;
        for ancestor in &self.ancestors {
            if DirectoryStamp::from(ancestor.file.metadata()?) != ancestor.stamp {
                return Err(InstalledContentError::Changed);
            }
        }
        for (index, name) in parts.iter().enumerate() {
            deadline_check(self.deadline)?;
            let expected = if index + 1 < self.ancestors.len() {
                let metadata = self.ancestors[index + 1].file.metadata()?;
                (metadata.dev(), metadata.ino())
            } else {
                self.content.held_inode()
            };
            let linked = File::from(openat2(
                &self.ancestors[index].file,
                *name,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLUTION,
            )?);
            let observed = linked.metadata()?;
            if (observed.dev(), observed.ino()) != expected {
                return Err(InstalledContentError::Changed);
            }
        }
        self.content.revalidate_object()?;
        deadline_check(self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, chown, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn traversal_and_unbounded_installed_paths_are_rejected() {
        for path in [
            "",
            "/usr",
            "/usr/",
            "/usr//bin/cat",
            "/usr/./cat",
            "/usr/../cat",
            "/usr/bin/x\n",
            "/usr/bin/x\0",
            "/proc/self/exe",
            "usr/bin/cat",
        ] {
            assert!(components(path).is_err());
        }
        assert!(components(&format!("/usr/{}", "a/".repeat(33))).is_err());
        assert!(components(&format!("/usr/{}", "a".repeat(4096))).is_err());
        assert_eq!(components("/usr/bin/cat").unwrap(), ["usr", "bin", "cat"]);
    }

    #[test]
    fn expired_capture_never_opens_an_installed_object() {
        assert!(matches!(
            InstalledExecutable::capture("/usr/bin/cat", Instant::now()),
            Err(InstalledContentError::Deadline)
        ));
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            assert_eq!(rustix::process::getuid().as_raw(), 0);
            let parent = Path::new("/var/lib/greyward-development/application-security");
            let metadata = fs::symlink_metadata(parent).unwrap();
            assert!(metadata.is_dir());
            assert_eq!((metadata.uid(), metadata.mode() & 0o777), (0, 0o700));
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = parent.join(format!("installed-{}-{nonce}", std::process::id()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir_all(path.join("usr/bin")).unwrap();
            for relative in ["usr", "usr/bin"] {
                fs::set_permissions(path.join(relative), fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            Self(path)
        }

        fn executable(&self, name: &str, bytes: &[u8]) {
            let path = self.0.join("usr/bin").join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn capture(&self, path: &str) -> Result<InstalledExecutable, InstalledContentError> {
            InstalledExecutable::capture_from_root(
                File::from(
                    open(
                        &self.0,
                        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .unwrap(),
                ),
                path,
                deadline(),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    #[ignore = "Explicit root-owned synthetic fixture in a hard-bounded development unit"]
    fn root_installed_membership_invalidates_on_replacement_or_ancestor_change() {
        let fixture = Fixture::new();
        fixture.executable("sample", b"\x7fELFsynthetic-original");
        let selected = fixture.capture("/usr/bin/sample").unwrap();
        selected.revalidate().unwrap();
        fixture.executable("replacement", b"\x7fELFsynthetic-replacement");
        fs::rename(
            fixture.0.join("usr/bin/replacement"),
            fixture.0.join("usr/bin/sample"),
        )
        .unwrap();
        assert!(selected.revalidate().is_err());
        let replaced = fixture.capture("/usr/bin/sample").unwrap();
        assert_ne!(selected.generation(), replaced.generation());
        fs::set_permissions(fixture.0.join("usr"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(replaced.revalidate().is_err());
        assert!(matches!(
            fixture.capture("/usr/bin/sample"),
            Err(InstalledContentError::UnsafeAncestor)
        ));
    }

    #[test]
    #[ignore = "Explicit root-owned synthetic fixture in a hard-bounded development unit"]
    fn root_installed_aliases_and_ordinary_owned_exact_copies_are_refused() {
        let fixture = Fixture::new();
        fixture.executable("sample", b"\x7fELFsynthetic-same-bytes");
        fixture.executable("copy", b"\x7fELFsynthetic-same-bytes");
        let selected = fixture.capture("/usr/bin/sample").unwrap();
        chown(fixture.0.join("usr/bin/copy"), Some(1002), Some(1002)).unwrap();
        assert!(fixture.capture("/usr/bin/copy").is_err());
        symlink("sample", fixture.0.join("usr/bin/link")).unwrap();
        assert!(fixture.capture("/usr/bin/link").is_err());
        symlink("bin", fixture.0.join("usr/alias")).unwrap();
        assert!(fixture.capture("/usr/alias/sample").is_err());
        fs::remove_file(fixture.0.join("usr/alias")).unwrap();
        fs::remove_file(fixture.0.join("usr/bin/link")).unwrap();
        // A harmless root-owned new sibling also invalidates the review lease.
        assert!(selected.revalidate().is_err());
        let selected = fixture.capture("/usr/bin/sample").unwrap();
        fs::rename(fixture.0.join("usr/bin"), fixture.0.join("usr/previous")).unwrap();
        fs::create_dir(fixture.0.join("usr/bin")).unwrap();
        fs::set_permissions(fixture.0.join("usr/bin"), fs::Permissions::from_mode(0o755)).unwrap();
        fixture.executable("sample", b"\x7fELFsynthetic-same-bytes");
        assert!(selected.revalidate().is_err());
    }

    #[test]
    #[ignore = "Fixed private bind mount supplied by the reviewed development tool"]
    fn root_bind_alias_cannot_gain_installed_membership() {
        assert_eq!(rustix::process::getuid().as_raw(), 0);
        let root = "/var/lib/greyward-development/application-security/installed-object-probe";
        let open_root = || {
            File::from(
                open(
                    root,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .unwrap(),
            )
        };
        InstalledExecutable::capture_from_root(open_root(), "/usr/bin/sample", deadline()).unwrap();
        assert!(matches!(
            InstalledExecutable::capture_from_root(open_root(), "/usr/alias/sample", deadline()),
            Err(InstalledContentError::Kernel(rustix::io::Errno::XDEV))
        ));
    }
}
