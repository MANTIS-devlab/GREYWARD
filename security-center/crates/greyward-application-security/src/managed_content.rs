//! Root-controlled code copies, not publisher verification or sandbox evidence.
//! Import must run in a confined worker with an independent hard deadline.
use crate::{CandidateContent, ContentError};
use greyward_security_domain::ContentGeneration;
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use std::fs::{self, File, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const SYSTEM_CONTENT: &str = "/var/lib/greyward/application-security/content";
const MAX_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CACHE_FILES: usize = 2000;

#[derive(Debug, Error)]
pub enum ManagedContentError {
    #[error("Managed code requires private root-owned storage")]
    UnsafeStorage,
    #[error("Managed content budget is exhausted")]
    Capacity,
    #[error("Managed code digest contradicts its generation")]
    Changed,
    #[error(transparent)]
    Candidate(#[from] ContentError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
}

pub struct ManagedCode {
    content: CandidateContent,
}

impl ManagedCode {
    pub(crate) fn prepare_document(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ManagedContentError> {
        if self.content.kind() != crate::PayloadKind::Document {
            return Err(ManagedContentError::Changed);
        }
        let fd = self.content.duplicate_descriptor()?;
        rustix::fs::fsetxattr(
            &fd,
            "security.selinux",
            b"unconfined_u:object_r:user_home_t:s0",
            rustix::fs::XattrFlags::empty(),
        )?;
        self.content = self.content.recapture(fd, deadline)?;
        Ok(())
    }
    pub fn generation(&self) -> &ContentGeneration {
        self.content.generation()
    }

    /// This proves the cached object's stamp, not its publisher, `SELinux` launch
    /// context, syscall restrictions or any effective protection profile.
    /// # Errors
    /// Changed cache objects cannot remain a prepared generation.
    pub fn revalidate(&self) -> Result<(), ManagedContentError> {
        Ok(self.content.revalidate_object()?)
    }

    // Only a root-created immutable copy can become an entrypoint. No caller
    // supplies a label or path, and the refreshed stamp retains the same hash.
    pub(crate) fn prepare_entrypoint(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ManagedContentError> {
        self.revalidate()?;
        let descriptor = self.content.duplicate_descriptor()?;
        let context = b"system_u:object_r:bin_t:s0";
        let mut observed = [0u8; 128];
        let count = rustix::fs::fgetxattr(&descriptor, "security.selinux", &mut observed[..])?;
        let current = observed[..count]
            .strip_suffix(&[0])
            .unwrap_or(&observed[..count]);
        if current != context {
            rustix::fs::fsetxattr(
                &descriptor,
                "security.selinux",
                context,
                rustix::fs::XattrFlags::REPLACE,
            )?;
        }
        let original = self.content.generation().clone();
        let updated = self.content.recapture(descriptor, deadline)?;
        if updated.generation() != &original {
            return Err(ManagedContentError::Changed);
        }
        self.content = updated;
        Ok(())
    }

    pub(crate) fn entry_descriptor(&self) -> Result<OwnedFd, ManagedContentError> {
        Ok(self.content.duplicate_descriptor()?)
    }
}

pub struct ManagedCodeStore {
    directory: PathBuf,
    directory_fd: File,
    _lock: File,
}

fn private_directory(path: &Path) -> Result<(), ManagedContentError> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        return Err(ManagedContentError::UnsafeStorage);
    }
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(ManagedContentError::UnsafeStorage);
        }
    }
    if fs::metadata(path)?.mode() & 0o777 != 0o700 {
        return Err(ManagedContentError::UnsafeStorage);
    }
    Ok(())
}

fn cache_file(file: &File, mode: u32) -> Result<(), ManagedContentError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o777 != mode
        || metadata.nlink() != 1
    {
        return Err(ManagedContentError::UnsafeStorage);
    }
    Ok(())
}

fn no_follow() -> Result<i32, ManagedContentError> {
    i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
        .map_err(|_| ManagedContentError::UnsafeStorage)
}

struct Pending(PathBuf);
impl Drop for Pending {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl ManagedCodeStore {
    /// The installation creates this directory; there is no user path override.
    /// # Errors
    /// Missing, unowned, writable, symlinked or concurrently locked storage
    /// stays unavailable. No caller-supplied executable path is accepted.
    pub fn open_system() -> Result<Self, ManagedContentError> {
        Self::open_private(Path::new(SYSTEM_CONTENT))
    }

    /// Fixed separate-account development storage; never aliases production.
    /// # Errors
    /// Root ownership, restrictive ancestry and single-writer checks apply.
    #[doc(hidden)]
    pub fn open_development_launch_probe() -> Result<Self, ManagedContentError> {
        Self::open_private(Path::new(
            "/var/lib/greyward-development/application-security/registration-critical/content",
        ))
    }

    pub(crate) fn open_bound(
        binding: &crate::enrollment::ProviderBinding,
    ) -> Result<Self, ManagedContentError> {
        Self::open_private(&binding.path().join("content"))
    }

    fn open_private(path: &Path) -> Result<Self, ManagedContentError> {
        private_directory(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(no_follow()?)
            .open(path.join(".lock"))?;
        cache_file(&lock, 0o600)?;
        // Retain this lock through quota checking, copy and atomic publication.
        // Competing workers fail immediately rather than blocking the broker.
        flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self {
            directory: path.to_owned(),
            directory_fd: File::open(path)?,
            _lock: lock,
        })
    }

    fn capacity(&self, additional: u64) -> Result<(), ManagedContentError> {
        let mut bytes = additional;
        let mut count = 0;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if entry.file_name() == ".lock" {
                continue;
            }
            count += 1;
            if count >= MAX_CACHE_FILES {
                return Err(ManagedContentError::Capacity);
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o222 != 0
            {
                return Err(ManagedContentError::UnsafeStorage);
            }
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or(ManagedContentError::Capacity)?;
            if bytes > MAX_CACHE_BYTES {
                return Err(ManagedContentError::Capacity);
            }
        }
        if bytes > MAX_CACHE_BYTES {
            return Err(ManagedContentError::Capacity);
        }
        Ok(())
    }

    fn load(
        &self,
        candidate: &CandidateContent,
        deadline: Instant,
    ) -> Result<ManagedCode, ManagedContentError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(no_follow()?)
            .open(self.directory.join(candidate.generation().as_str()))?;
        cache_file(&file, 0o555)?;
        let content = candidate.recapture(file.into(), deadline)?;
        if content.generation() != candidate.generation() {
            return Err(ManagedContentError::Changed);
        }
        Ok(ManagedCode { content })
    }

    /// Copy exact candidate bytes into a newly root-created inode, close the
    /// writable descriptor, then validate and publish without replacing code.
    /// A source owner retaining a writable descriptor cannot modify the copy.
    /// # Errors
    /// Expiry, changed bytes, unsafe storage, quota or publication errors refuse
    /// the generation. There is no original-path or unrestricted fallback.
    pub fn import(
        &self,
        candidate: &CandidateContent,
        deadline: Instant,
    ) -> Result<ManagedCode, ManagedContentError> {
        private_directory(&self.directory)?;
        candidate.revalidate_object()?;
        let target = self.directory.join(candidate.generation().as_str());
        match fs::symlink_metadata(&target) {
            Ok(_) => return self.load(candidate, deadline),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        self.capacity(candidate.byte_length())?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagedContentError::UnsafeStorage)?
            .as_nanos();
        let pending = Pending(
            self.directory
                .join(format!(".pending-{}-{nonce}", std::process::id())),
        );
        {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&pending.0)?;
            cache_file(&output, 0o600)?;
            candidate.materialize(&mut output, deadline)?;
            output.set_permissions(fs::Permissions::from_mode(0o555))?;
            output.sync_all()?;
            // Closing this handle is part of the immutable-copy boundary.
        }
        renameat_with(
            &self.directory_fd,
            pending
                .0
                .file_name()
                .ok_or(ManagedContentError::UnsafeStorage)?,
            &self.directory_fd,
            candidate.generation().as_str(),
            RenameFlags::NOREPLACE,
        )?;
        self.directory_fd.sync_all()?;
        self.load(candidate, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, FileExt, symlink};
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[test]
    fn a_session_process_cannot_open_managed_code_storage() {
        if rustix::process::getuid().as_raw() != 0 {
            assert!(matches!(
                ManagedCodeStore::open_private(Path::new("/tmp")),
                Err(ManagedContentError::UnsafeStorage)
            ));
        }
    }

    fn assert_ordinary_denied(path: &Path) {
        let ordinary = std::process::Command::new("/usr/sbin/runuser").args(["-u", "greyward-guard-probe", "--",
            "/usr/bin/python3", "-I", "-c", "import os,sys; assert os.getuid()==1002; p=sys.argv[1]; denied=0\nfor mode in ('rb','wb'):\n try: open(p,mode).close()\n except PermissionError: denied+=1\nsys.exit(0 if denied==2 else 1)"])
            .arg(path).status().unwrap();
        assert!(
            ordinary.success(),
            "ordinary UID must not read/write private managed code"
        );
    }

    fn assert_import_failure_leaves_no_pending_copy(store: &ManagedCodeStore, source: &Path) {
        let candidate =
            CandidateContent::capture(File::open(source).unwrap().into(), deadline()).unwrap();
        assert!(store.import(&candidate, Instant::now()).is_err());
        assert!(!fs::read_dir(&store.directory).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pending-")
        }));
        let sparse = store.directory.join("quota-probe");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o555)
            .open(&sparse)
            .unwrap();
        file.set_len(MAX_CACHE_BYTES + 1).unwrap();
        drop(file);
        assert!(matches!(
            store.import(&candidate, deadline()),
            Err(ManagedContentError::Capacity)
        ));
        fs::remove_file(sparse).unwrap();
    }

    #[test]
    #[ignore = "exact root fixture in private development storage; never opens the production cache"]
    fn root_copy_survives_source_writers_and_rejects_corrupt_aliases() {
        assert_eq!(rustix::process::getuid().as_raw(), 0);
        let base = Path::new("/var/lib/greyward-development/application-security");
        private_directory(base).unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = base.join(format!("code-probe-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = directory.join("content");
        fs::DirBuilder::new().mode(0o700).create(&cache).unwrap();
        let source = directory.join("mutable-code");
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&source)
            .unwrap();
        writer
            .write_all(b"\x7fELFsynthetic old generation")
            .unwrap();
        rustix::fs::chown(
            &source,
            Some(rustix::process::Uid::from_raw(1002)),
            Some(rustix::process::Gid::from_raw(1002)),
        )
        .unwrap();
        let candidate =
            CandidateContent::capture(File::open(&source).unwrap().into(), deadline()).unwrap();
        let store = ManagedCodeStore::open_private(&cache).unwrap();
        assert!(
            ManagedCodeStore::open_private(&cache).is_err(),
            "second writer must not race quota/publication"
        );
        let managed = store.import(&candidate, deadline()).unwrap();
        assert_eq!(managed.generation(), candidate.generation());
        let cached = cache.join(managed.generation().as_str());
        assert_eq!(fs::metadata(&cached).unwrap().mode() & 0o777, 0o555);
        assert_eq!(fs::metadata(&cached).unwrap().uid(), 0);
        assert_ne!(
            fs::metadata(&source).unwrap().ino(),
            fs::metadata(&cached).unwrap().ino()
        );
        assert_ordinary_denied(&cached);
        writer
            .write_all_at(b"\x7fELFchanged source contents", 0)
            .unwrap();
        assert!(candidate.revalidate_object().is_err());
        managed.revalidate().unwrap();
        assert_eq!(
            fs::read(&cached).unwrap(),
            b"\x7fELFsynthetic old generation"
        );
        assert!(store.import(&candidate, deadline()).is_err());
        assert_import_failure_leaves_no_pending_copy(&store, &source);
        drop(managed);
        let original = fs::read(&cached).unwrap();
        fs::remove_file(&cached).unwrap();
        symlink(&source, &cached).unwrap();
        assert!(store.load(&candidate, deadline()).is_err());
        fs::remove_file(&cached).unwrap();
        fs::hard_link(&source, &cached).unwrap();
        assert!(store.load(&candidate, deadline()).is_err());
        fs::remove_file(&cached).unwrap();
        fs::write(&cached, &original).unwrap();
        fs::set_permissions(&cached, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(store.load(&candidate, Instant::now()).is_err());
        fs::write(&cached, b"\x7fELFwrong generation").unwrap();
        assert!(matches!(
            store.load(&candidate, deadline()),
            Err(ManagedContentError::Changed)
        ));
        drop(store);
        fs::remove_dir_all(&directory).unwrap();
    }
}
