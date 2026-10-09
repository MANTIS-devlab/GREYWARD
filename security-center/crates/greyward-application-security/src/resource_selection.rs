//! Metadata-only directory selection. This establishes neither labels nor policy.
//! The held object is reviewed; a pathname is never reopened to apply a change.
use crate::registry::framed_digest;
use greyward_security_domain::SecurityReference;
use rustix::fs::{Mode, OFlags, ResolveFlags, fcntl_getfl, fstatfs, openat2};
use std::fs::{File, Metadata};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;
use thiserror::Error;

/// Retained metadata is a reconciliation hint, not replacement-safe protection.
/// Device/inode numbers must never independently authorize access after restart.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryObjectReceipt {
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

#[derive(Debug, Error)]
pub enum ResourceSelectionError {
    #[error("A metadata-only directory descriptor is required")]
    InvalidDescriptor,
    #[error("Individual files require a replacement-safe provider; select their directory")]
    UnsupportedObject,
    #[error("The selected directory is not owned by the authenticated user")]
    Owner,
    #[error("Filesystem protection has not been established for this mount")]
    UnsupportedFilesystem,
    #[error("The selected directory changed; a new review is required")]
    Changed,
    #[error("Resource selection expired")]
    Expired,
    #[error("Only a bounded relative directory selection is supported")]
    InvalidPath,
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
    links: u64,
    changed: (i64, i64),
    modified: (i64, i64),
}

impl From<Metadata> for DirectoryStamp {
    fn from(value: Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            owner: value.uid(),
            group: value.gid(),
            mode: value.mode(),
            links: value.nlink(),
            changed: (value.ctime(), value.ctime_nsec()),
            modified: (value.mtime(), value.mtime_nsec()),
        }
    }
}

/// Non-serializable held lease; its reference is not a persistent resource ID.
/// Persistence, replacement-safe labels and authorization are separate gates.
pub struct DirectorySelection {
    file: File,
    stamp: DirectoryStamp,
    deadline: Instant,
    selection_ref: SecurityReference,
}

fn check_deadline(deadline: Instant) -> Result<(), ResourceSelectionError> {
    if Instant::now() >= deadline {
        Err(ResourceSelectionError::Expired)
    } else {
        Ok(())
    }
}

impl DirectorySelection {
    /// Secure relative resolution refuses traversal, symlinks and mount aliases.
    /// The trusted caller supplies an authenticated user's base descriptor/UID,
    /// never values copied from a UI request. Resolved symlinks need a separate
    /// explicit review; silently following them is not supported here.
    /// # Errors
    /// Unsupported resolution/objects/mounts and expired selections fail closed.
    pub fn beneath(
        base: impl AsFd,
        relative: &str,
        authenticated_uid: u32,
        deadline: Instant,
    ) -> Result<Self, ResourceSelectionError> {
        check_deadline(deadline)?;
        if relative.is_empty()
            || relative.len() > 4096
            || relative.split('/').count() > 32
            || relative.split('/').any(|part| {
                part.is_empty() || part == "." || part == ".." || part.chars().any(char::is_control)
            })
        {
            return Err(ResourceSelectionError::InvalidPath);
        }
        let descriptor = openat2(
            base,
            relative,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?;
        Self::capture(descriptor, authenticated_uid, deadline)
    }

    /// Holds the selected inode without reading directory entries or contents.
    /// Filesystem recognition is eligibility only, never verified coverage.
    /// Independently enforce a worker deadline: syscall stalls cannot be canceled
    /// by checks between calls. No public registration API uses this yet.
    /// # Errors
    /// Invalid descriptors, owner mismatch, unsupported objects/mounts or expiry.
    pub fn capture(
        descriptor: OwnedFd,
        authenticated_uid: u32,
        deadline: Instant,
    ) -> Result<Self, ResourceSelectionError> {
        check_deadline(deadline)?;
        let file = File::from(descriptor);
        if !fcntl_getfl(&file)?.contains(OFlags::PATH) {
            return Err(ResourceSelectionError::InvalidDescriptor);
        }
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.nlink() == 0 {
            return Err(ResourceSelectionError::UnsupportedObject);
        }
        if metadata.uid() != authenticated_uid {
            return Err(ResourceSelectionError::Owner);
        }
        // Btrfs, ext-family and XFS only. This is not a label inheritance or
        // mount-option proof. FUSE, overlay, network and unknown mounts fail.
        if ![0x9123_683e, 0x0000_ef53, 0x5846_5342].contains(&fstatfs(&file)?.f_type) {
            return Err(ResourceSelectionError::UnsupportedFilesystem);
        }
        let stamp = DirectoryStamp::from(metadata);
        let digest = framed_digest(&[
            b"directory-selection/v1",
            &stamp.device.to_le_bytes(),
            &stamp.inode.to_le_bytes(),
            &stamp.owner.to_le_bytes(),
            &stamp.changed.0.to_le_bytes(),
            &stamp.changed.1.to_le_bytes(),
        ]);
        let selection_ref = SecurityReference::try_from(format!("resource_{digest}"))
            .map_err(|_| ResourceSelectionError::InvalidDescriptor)?;
        check_deadline(deadline)?;
        Ok(Self {
            file,
            stamp,
            deadline,
            selection_ref,
        })
    }

    pub fn selection_ref(&self) -> &SecurityReference {
        &self.selection_ref
    }

    /// Private proxy for metadata-only xattr syscalls on the still-held inode.
    /// Never returned to a UI, reopened as a user pathname or used to read data.
    pub(crate) fn held_metadata_path(&self) -> Result<String, ResourceSelectionError> {
        self.revalidate()?;
        Ok(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    pub(crate) fn duplicate_object(&self) -> Result<File, ResourceSelectionError> {
        self.revalidate()?;
        Ok(self.file.try_clone()?)
    }

    pub(crate) fn object_receipt(&self) -> Result<DirectoryObjectReceipt, ResourceSelectionError> {
        self.revalidate()?;
        Ok(DirectoryObjectReceipt {
            device: self.stamp.device,
            inode: self.stamp.inode,
            owner_uid: self.stamp.owner,
            changed_seconds: self.stamp.changed.0,
            changed_nanoseconds: self.stamp.changed.1,
        })
    }

    /// Revalidates the held inode, including rename/child changes, never a path.
    /// This detects review invalidation; it is not a locking/relabeling mechanism
    /// and does not eliminate a subsequent race. No descriptor is exposed.
    /// # Errors
    /// Any change or expiry requires a new selection and review.
    pub fn revalidate(&self) -> Result<(), ResourceSelectionError> {
        check_deadline(self.deadline)?;
        if DirectoryStamp::from(self.file.metadata()?) != self.stamp {
            return Err(ResourceSelectionError::Changed);
        }
        check_deadline(self.deadline)
    }
}
