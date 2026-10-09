//! Descriptor-bound candidate content; no installation trust or launch authority.
//! A mutable input must become a validated immutable managed copy before launch.
use greyward_security_domain::ContentGeneration;
use rustix::fs::{OFlags, fcntl_getfl};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::Instant;
use thiserror::Error;

const MAX_CANDIDATE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ContentError {
    #[error("A read-only regular executable descriptor is required")]
    InvalidDescriptor,
    #[error("Unsupported candidate format or size")]
    Unsupported,
    #[error("Candidate identity or content changed during verification")]
    Changed,
    #[error("Candidate verification deadline expired")]
    Deadline,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for Stamp {
    fn from(value: Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            owner: value.uid(),
            group: value.gid(),
            mode: value.mode(),
            length: value.len(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

pub struct CandidateContent {
    file: File,
    stamp: Stamp,
    generation: ContentGeneration,
    kind: crate::PayloadKind,
}

fn deadline_check(deadline: Instant) -> Result<(), ContentError> {
    if Instant::now() >= deadline {
        Err(ContentError::Deadline)
    } else {
        Ok(())
    }
}

impl CandidateContent {
    /// Hash the held inode, never reopen the requested pathname. Positional
    /// reads ignore a sender's shared descriptor offset. Only ELF candidates
    /// are recognized here; this is not full ELF/AppImage/signature validation.
    /// Run in a confined verifier with an independently enforced worker deadline:
    /// checks between reads do not cancel a filesystem that stalls inside read.
    /// # Errors
    /// Invalid/changed descriptors, unsupported inputs and expiry fail closed.
    pub fn capture(descriptor: OwnedFd, deadline: Instant) -> Result<Self, ContentError> {
        let value = Self::capture_payload(descriptor, deadline, false)?;
        if value.kind != crate::PayloadKind::Elf {
            return Err(ContentError::Unsupported);
        }
        Ok(value)
    }
    /// # Errors
    /// Shared content binding for isolated payloads or an ordinary selected
    /// document. This never creates a reviewed installed executable identity.
    pub(crate) fn capture_payload(
        descriptor: OwnedFd,
        deadline: Instant,
        document: bool,
    ) -> Result<Self, ContentError> {
        deadline_check(deadline)?;
        let file = File::from(descriptor);
        let flags = fcntl_getfl(&file)?;
        let before = file.metadata()?;
        if flags.contains(OFlags::PATH)
            || flags.intersects(OFlags::WRONLY | OFlags::RDWR)
            || !before.is_file()
        {
            return Err(ContentError::InvalidDescriptor);
        }
        if before.len() == 0
            || before.len()
                > if document {
                    32 * 1024 * 1024
                } else {
                    MAX_CANDIDATE_BYTES
                }
        {
            return Err(ContentError::Unsupported);
        }
        let kind = if document {
            crate::PayloadKind::Document
        } else {
            crate::payload::classify(&file)?
        };
        if matches!(
            kind,
            crate::PayloadKind::Elf | crate::PayloadKind::AppImage { .. }
        ) && before.mode() & 0o111 == 0
        {
            return Err(ContentError::InvalidDescriptor);
        }
        let stamp = Stamp::from(before);
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut offset = 0;
        while offset < stamp.length {
            deadline_check(deadline)?;
            let remaining = usize::try_from((stamp.length - offset).min(buffer.len() as u64))
                .map_err(|_| ContentError::Unsupported)?;
            let count = file.read_at(&mut buffer[..remaining], offset)?;
            if count == 0 {
                return Err(ContentError::Changed);
            }
            digest.update(&buffer[..count]);
            offset += u64::try_from(count).map_err(|_| ContentError::Unsupported)?;
        }
        deadline_check(deadline)?;
        if Stamp::from(file.metadata()?) != stamp {
            return Err(ContentError::Changed);
        }
        let generation = ContentGeneration::try_from(format!("{:x}", digest.finalize()))
            .map_err(|_| ContentError::Unsupported)?;
        Ok(Self {
            file,
            stamp,
            generation,
            kind,
        })
    }

    pub fn kind(&self) -> crate::PayloadKind {
        self.kind
    }
    pub(crate) fn recapture(
        &self,
        descriptor: OwnedFd,
        deadline: Instant,
    ) -> Result<Self, ContentError> {
        let value = Self::capture_payload(
            descriptor,
            deadline,
            self.kind == crate::PayloadKind::Document,
        )?;
        if value.kind != self.kind {
            return Err(ContentError::Changed);
        }
        Ok(value)
    }

    pub fn generation(&self) -> &ContentGeneration {
        &self.generation
    }

    pub(crate) fn duplicate_descriptor(&self) -> Result<OwnedFd, ContentError> {
        self.revalidate_object()?;
        Ok(self.file.try_clone()?.into())
    }

    pub(crate) fn byte_length(&self) -> u64 {
        self.stamp.length
    }

    pub(crate) fn root_package_mode(&self) -> Option<u32> {
        // This is an ownership/mode check, not a writable-ancestor check or a
        // claim that RPM metadata proves publisher authenticity.
        (self.stamp.owner == 0 && self.stamp.group == 0 && self.stamp.mode & 0o7022 == 0)
            .then_some(self.stamp.mode)
    }

    pub(crate) fn held_inode(&self) -> (u64, u64) {
        (self.stamp.device, self.stamp.inode)
    }

    // Only the root cache imports candidates. Never expose the selected inode
    // itself as immutable code. The worker supplies the independent deadline.
    pub(crate) fn materialize(
        &self,
        target: &mut File,
        deadline: Instant,
    ) -> Result<(), ContentError> {
        self.revalidate_object()?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut offset = 0;
        while offset < self.stamp.length {
            deadline_check(deadline)?;
            let remaining = usize::try_from((self.stamp.length - offset).min(buffer.len() as u64))
                .map_err(|_| ContentError::Unsupported)?;
            let count = self.file.read_at(&mut buffer[..remaining], offset)?;
            if count == 0 {
                return Err(ContentError::Changed);
            }
            digest.update(&buffer[..count]);
            target.write_all(&buffer[..count])?;
            offset += u64::try_from(count).map_err(|_| ContentError::Unsupported)?;
        }
        deadline_check(deadline)?;
        self.revalidate_object()?;
        if format!("{:x}", digest.finalize()) != self.generation.as_str() {
            return Err(ContentError::Changed);
        }
        Ok(())
    }

    /// Detect invalidating metadata changes. This does not seal a mutable inode
    /// or close a later write/exec race, and must never authorize execution alone.
    /// # Errors
    /// Changed objects remain unusable as the reviewed candidate generation.
    pub fn revalidate_object(&self) -> Result<(), ContentError> {
        if Stamp::from(self.file.metadata()?) != self.stamp {
            return Err(ContentError::Changed);
        }
        Ok(())
    }
}
