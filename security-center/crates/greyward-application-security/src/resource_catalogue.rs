//! Fixed metadata-only discovery, never a resource registration/protection claim.
use crate::{DirectorySelection, ResourceSelectionError};
use greyward_security_domain::{ProtectedCategory, ResourceCoverage};
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use std::os::fd::AsFd;
use std::time::Instant;

pub const PROTECTED_CATALOGUE_VERSION: u32 = 1;

struct Location {
    id: &'static str,
    relative: &'static str,
    category: ProtectedCategory,
}

const LOCATIONS: &[Location] = &[
    Location {
        id: "ssh",
        relative: ".ssh",
        category: ProtectedCategory::Credentials,
    },
    Location {
        id: "gpg",
        relative: ".gnupg",
        category: ProtectedCategory::Credentials,
    },
    Location {
        id: "git-credentials",
        relative: ".git-credentials",
        category: ProtectedCategory::Credentials,
    },
    Location {
        id: "git-config-credentials",
        relative: ".config/git/credentials",
        category: ProtectedCategory::Credentials,
    },
    Location {
        id: "aws",
        relative: ".aws",
        category: ProtectedCategory::Cloud,
    },
    Location {
        id: "azure",
        relative: ".azure",
        category: ProtectedCategory::Cloud,
    },
    Location {
        id: "gcloud",
        relative: ".config/gcloud",
        category: ProtectedCategory::Cloud,
    },
    Location {
        id: "kubernetes",
        relative: ".kube",
        category: ProtectedCategory::Cloud,
    },
    Location {
        id: "vault-token",
        relative: ".vault-token",
        category: ProtectedCategory::Cloud,
    },
    Location {
        id: "firefox",
        relative: ".mozilla/firefox",
        category: ProtectedCategory::BrowserSession,
    },
    Location {
        id: "brave",
        relative: ".config/BraveSoftware/Brave-Browser",
        category: ProtectedCategory::BrowserSession,
    },
    Location {
        id: "chrome",
        relative: ".config/google-chrome",
        category: ProtectedCategory::BrowserSession,
    },
    Location {
        id: "chromium",
        relative: ".config/chromium",
        category: ProtectedCategory::BrowserSession,
    },
];

/// Reasons contain no actual resource path or secret contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogueLimitation {
    UnsupportedObject,
    UnsupportedFilesystem,
    WrongOwner,
    SelectionRefused,
}

enum Presence {
    Directory(DirectorySelection),
    NotPresent,
    Unavailable(CatalogueLimitation),
}

/// Holds transient review leases rather than root policy or persistent IDs.
pub struct CatalogueItem {
    location: &'static Location,
    presence: Presence,
}

impl CatalogueItem {
    pub fn catalogue_id(&self) -> &'static str {
        self.location.id
    }

    pub fn category(&self) -> ProtectedCategory {
        self.location.category
    }

    pub fn coverage(&self) -> ResourceCoverage {
        match self.presence {
            Presence::Directory(_) => ResourceCoverage::Unknown,
            Presence::NotPresent => ResourceCoverage::NotPresent,
            Presence::Unavailable(_) => ResourceCoverage::Unavailable,
        }
    }

    pub fn limitation(&self) -> Option<CatalogueLimitation> {
        if let Presence::Unavailable(reason) = self.presence {
            Some(reason)
        } else {
            None
        }
    }
}

pub struct CatalogueDiscovery {
    home: DirectorySelection,
    items: Vec<CatalogueItem>,
}

impl CatalogueDiscovery {
    /// The trusted collector supplies the actual authenticated user's home FD
    /// and UID. This scans only fixed locations, without listing directories,
    /// reading files, following aliases or making labels/policy changes.
    /// Independently bound the worker: a check between syscalls is not a hard
    /// deadline for a stalled filesystem. No session API accepts arbitrary FDs.
    /// # Errors
    /// Invalid/unowned home, unsupported home filesystem, expiry or a changed
    /// review object fail closed. Per-location refusal stays explicitly unavailable.
    pub fn discover(
        home: impl AsFd,
        authenticated_uid: u32,
        deadline: Instant,
    ) -> Result<Self, ResourceSelectionError> {
        let home_lease = DirectorySelection::capture(
            home.as_fd().try_clone_to_owned()?,
            authenticated_uid,
            deadline,
        )?;
        let mut items = Vec::with_capacity(LOCATIONS.len());
        for location in LOCATIONS {
            home_lease.revalidate()?;
            let descriptor = openat2(
                home.as_fd(),
                location.relative,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            );
            let presence = match descriptor {
                Ok(selected) => {
                    match DirectorySelection::capture(selected, authenticated_uid, deadline) {
                        Ok(directory) => Presence::Directory(directory),
                        Err(ResourceSelectionError::UnsupportedObject) => {
                            Presence::Unavailable(CatalogueLimitation::UnsupportedObject)
                        }
                        Err(ResourceSelectionError::UnsupportedFilesystem) => {
                            Presence::Unavailable(CatalogueLimitation::UnsupportedFilesystem)
                        }
                        Err(ResourceSelectionError::Owner) => {
                            Presence::Unavailable(CatalogueLimitation::WrongOwner)
                        }
                        Err(ResourceSelectionError::Expired) => {
                            return Err(ResourceSelectionError::Expired);
                        }
                        Err(_) => Presence::Unavailable(CatalogueLimitation::SelectionRefused),
                    }
                }
                Err(rustix::io::Errno::NOENT) => Presence::NotPresent,
                Err(_) => Presence::Unavailable(CatalogueLimitation::SelectionRefused),
            };
            items.push(CatalogueItem { location, presence });
        }
        let discovery = Self {
            home: home_lease,
            items,
        };
        discovery.revalidate()?;
        Ok(discovery)
    }

    pub fn items(&self) -> &[CatalogueItem] {
        &self.items
    }

    /// A review must be reacquired after object changes or expiry. This is not
    /// replacement-safe registration or an enforcement readback mechanism.
    /// # Errors
    /// Any retained home/directory lease invalidation refuses the review.
    pub fn revalidate(&self) -> Result<(), ResourceSelectionError> {
        self.home.revalidate()?;
        for item in &self.items {
            if let Presence::Directory(directory) = &item.presence {
                directory.revalidate()?;
            }
        }
        Ok(())
    }
}
