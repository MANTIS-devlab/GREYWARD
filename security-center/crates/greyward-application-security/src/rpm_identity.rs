//! Installed RPM content evidence, separate from signature/source approval.
//! Inputs must come from a bounded fixed-format collector against the system
//! RPM database. Never accept these receipts through a session mutation API.
use crate::{
    IdentitySeed, InstalledContentError, InstalledExecutable, InventoryChange, PolicyStore,
    RegistryError, StoreError, framed_digest,
};
use greyward_security_backends::{RpmMetadataError, read_installed_rpm_metadata};
use greyward_security_domain::{
    ApplicationIdentity, ApplicationProvider, ContentGeneration, InstalledExecutablePath,
};
use std::time::Instant;
use thiserror::Error;

pub use greyward_security_backends::RPM_EXECUTABLE_QUERY;
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_FILE_ROWS: usize = 8192;

#[derive(Debug, Error)]
pub enum RpmIdentityError {
    #[error("Installed RPM evidence is incomplete, ambiguous or unsupported")]
    InvalidReceipt,
    #[error("The selected executable is not eligible root-owned package code")]
    UnsafeObject,
    #[error("Package generation or executable content changed")]
    Changed,
    #[error(transparent)]
    InstalledContent(#[from] InstalledContentError),
    #[error(transparent)]
    Metadata(#[from] RpmMetadataError),
}

/// Opaque nonserializable evidence; it cannot serve as a grant or provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmFileReceipt {
    name: String,
    epoch: u32,
    version: String,
    release: String,
    architecture: String,
    header: ContentGeneration,
    selected_path: String,
    digest: ContentGeneration,
    mode: u32,
}

fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+~^-".contains(&byte))
        && !value.starts_with(['-', '.'])
}

fn canonical_number(value: &str) -> Option<u32> {
    let number = value.parse::<u32>().ok()?;
    (number.to_string() == value).then_some(number)
}

fn installed_path(value: &str) -> bool {
    // Initially support canonical /usr ELF paths only. Symlink resolution,
    // other prefixes, scripts and execution search are separate provider work.
    InstalledExecutablePath::try_from(value).is_ok()
}

/// Collect before/after RPM receipts and hash the held root-owned executable
/// using one shared deadline. This is one executable, not complete native
/// inventory, publisher approval or launch authority. Filesystem verification
/// still needs an independent worker deadline for stalled kernel operations.
/// # Errors
/// Ambiguous/changed metadata, unsafe membership and provider failures refuse.
pub fn collect_installed_rpm_content(
    path: &InstalledExecutablePath,
    deadline: Instant,
) -> Result<RpmContentBinding, RpmIdentityError> {
    let before =
        RpmFileReceipt::parse(&read_installed_rpm_metadata(path, deadline)?, path.as_str())?;
    let selected = InstalledExecutable::capture(path.as_str(), deadline)?;
    let after =
        RpmFileReceipt::parse(&read_installed_rpm_metadata(path, deadline)?, path.as_str())?;
    before.bind_content(&selected, &after)
}

impl RpmFileReceipt {
    /// Decode exactly one successful RPM query, including an exact selected
    /// file row. Header SHA-256 binds metadata; it is not a verified signature.
    /// # Errors
    /// Reject truncation, duplicate owners/rows, weak hashes, mutable/config/
    /// ghost files, privilege-bearing modes and unrecognized serialization.
    pub fn parse(bytes: &[u8], selected_path: &str) -> Result<Self, RpmIdentityError> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES || !installed_path(selected_path) {
            return Err(RpmIdentityError::InvalidReceipt);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| RpmIdentityError::InvalidReceipt)?;
        if !text.ends_with('\n') || text.contains('\0') || text.contains('\r') {
            return Err(RpmIdentityError::InvalidReceipt);
        }
        let mut lines = text.lines();
        let fields: Vec<_> = lines
            .next()
            .ok_or(RpmIdentityError::InvalidReceipt)?
            .split('\t')
            .collect();
        if fields.len() != 7
            || ![fields[0], fields[2], fields[3], fields[4]]
                .into_iter()
                .all(segment)
            || fields[6] != "8"
        {
            return Err(RpmIdentityError::InvalidReceipt);
        }
        let epoch = canonical_number(fields[1]).ok_or(RpmIdentityError::InvalidReceipt)?;
        let header = ContentGeneration::try_from(fields[5].to_owned())
            .map_err(|_| RpmIdentityError::InvalidReceipt)?;
        let mut selected = None;
        let mut count = 0;
        for line in lines {
            count += 1;
            let row: Vec<_> = line.split('\t').collect();
            if count > MAX_FILE_ROWS || row.len() != 4 || !row[0].starts_with('/') {
                return Err(RpmIdentityError::InvalidReceipt);
            }
            if row[0] != selected_path {
                continue;
            }
            if selected.is_some() || row[3] != "0" {
                return Err(RpmIdentityError::InvalidReceipt);
            }
            let mode = canonical_number(row[2]).ok_or(RpmIdentityError::InvalidReceipt)?;
            if mode & 0o170_000 != 0o100_000 || mode & 0o111 == 0 || mode & 0o7022 != 0 {
                return Err(RpmIdentityError::InvalidReceipt);
            }
            let digest = ContentGeneration::try_from(row[1].to_owned())
                .map_err(|_| RpmIdentityError::InvalidReceipt)?;
            selected = Some((digest, mode));
        }
        let (digest, mode) = selected.ok_or(RpmIdentityError::InvalidReceipt)?;
        Ok(Self {
            name: fields[0].to_owned(),
            epoch,
            version: fields[2].to_owned(),
            release: fields[3].to_owned(),
            architecture: fields[4].to_owned(),
            header,
            selected_path: selected_path.to_owned(),
            digest,
            mode,
        })
    }

    pub fn package_name(&self) -> &str {
        &self.name
    }

    /// Compare receipts before/after descriptor hashing, with matching file
    /// bytes and root ownership/mode. No launch FD or grant identity is returned.
    /// The held executable establishes matching root-owned path membership.
    /// Approved source receipts, trusted collector namespaces, update
    /// authorization and an immutable managed launch remain independent gates.
    /// # Errors
    /// Stale/replaced metadata, wrong content or ordinary-owned objects fail.
    pub fn bind_content(
        &self,
        installed: &InstalledExecutable,
        after: &Self,
    ) -> Result<RpmContentBinding, RpmIdentityError> {
        if installed.selected_path() != self.selected_path {
            return Err(RpmIdentityError::UnsafeObject);
        }
        installed.revalidate()?;
        let candidate = installed.content();
        if self != after || candidate.generation() != &self.digest {
            return Err(RpmIdentityError::Changed);
        }
        if candidate.root_package_mode() != Some(self.mode) {
            return Err(RpmIdentityError::UnsafeObject);
        }
        installed.revalidate()?;
        let epoch = self.epoch.to_le_bytes();
        let generation = ContentGeneration::try_from(framed_digest(&[
            b"rpm-executable-evidence/v1",
            self.name.as_bytes(),
            &epoch,
            self.version.as_bytes(),
            self.release.as_bytes(),
            self.architecture.as_bytes(),
            self.header.as_str().as_bytes(),
            self.selected_path.as_bytes(),
            self.digest.as_str().as_bytes(),
        ]))
        .map_err(|_| RpmIdentityError::InvalidReceipt)?;
        Ok(RpmContentBinding {
            generation,
            package_name: self.name.clone(),
            installed_path: InstalledExecutablePath::try_from(self.selected_path.as_str())
                .map_err(|_| RpmIdentityError::InvalidReceipt)?,
            architecture: self.architecture.clone(),
        })
    }
}

/// Content/metadata coherence only. The internal factory may derive an observed
/// registry identity; no signed source receipt, prepared execution authority or
/// protection snapshot is established by this binding.
pub struct RpmContentBinding {
    generation: ContentGeneration,
    package_name: String,
    installed_path: InstalledExecutablePath,
    architecture: String,
}

impl RpmContentBinding {
    pub fn generation(&self) -> &ContentGeneration {
        &self.generation
    }

    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    /// Internal observed registry identity for the authenticated owner. Different
    /// executable members do not overwrite each other's content generations.
    /// RPM database membership does not identify a reviewed repository/signer:
    /// source/provenance stays explicitly unverified, with no grant/update trust.
    /// Only a partial provider refresh may ingest this one-executable observation.
    /// # Errors
    /// Refuses invalid provider metadata before any registry transaction.
    pub fn observed_identity(
        &self,
        authenticated_uid: u32,
    ) -> Result<ApplicationIdentity, RegistryError> {
        let logical = framed_digest(&[
            b"rpm-member/v1",
            self.package_name.as_bytes(),
            self.installed_path.as_str().as_bytes(),
        ]);
        IdentitySeed {
            provider: ApplicationProvider::Rpm,
            logical_id: logical,
            installation_id: self.architecture.clone(),
            source_id: "system-rpm-unverified".into(),
            owner_uid: authenticated_uid,
        }
        .identity(self.generation.clone())
    }

    /// Add this validated member without inferring package/provider uninstall.
    /// # Errors
    /// Invalid/stale/corrupt transactions do not change the inventory.
    pub fn reconcile_observation(
        &self,
        store: &mut PolicyStore,
        authenticated_uid: u32,
        expected_revision: u64,
        now: u64,
    ) -> Result<Vec<InventoryChange>, StoreError> {
        store.reconcile_provider(
            authenticated_uid,
            ApplicationProvider::Rpm,
            vec![self.observed_identity(authenticated_uid)?],
            false,
            expected_revision,
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greyward_security_domain::ProvenanceState;

    fn observed(path: &str, architecture: &str, code: &[u8]) -> RpmContentBinding {
        // Factory tests only: production bindings can only be acquired after
        // descriptor/hash/installed-ancestry validation above.
        RpmContentBinding {
            generation: crate::content_generation(code),
            package_name: "sample".into(),
            installed_path: InstalledExecutablePath::try_from(path).unwrap(),
            architecture: architecture.into(),
        }
    }

    #[test]
    fn native_members_and_owners_are_distinct_and_updates_never_gain_provenance() {
        let before = observed("/usr/bin/sample", "x86_64", b"old")
            .observed_identity(1000)
            .unwrap();
        let after = observed("/usr/bin/sample", "x86_64", b"new")
            .observed_identity(1000)
            .unwrap();
        assert_eq!(before.installation_ref, after.installation_ref);
        assert_ne!(before.generation, after.generation);
        for other in [
            observed("/usr/bin/helper", "x86_64", b"old")
                .observed_identity(1000)
                .unwrap(),
            observed("/usr/bin/sample", "aarch64", b"old")
                .observed_identity(1000)
                .unwrap(),
            observed("/usr/bin/sample", "x86_64", b"old")
                .observed_identity(1001)
                .unwrap(),
        ] {
            assert_ne!(before.installation_ref, other.installation_ref);
        }
        assert_eq!(before.provenance.state, ProvenanceState::Unknown);
        assert_eq!(after.provenance.state, ProvenanceState::Unknown);
        assert!(after.provenance.source_receipt.is_none());
    }

    #[test]
    fn a_single_native_observation_never_removes_another_member_or_provider() {
        let mut store = crate::PolicyStore::isolated_memory().unwrap();
        let first = observed("/usr/bin/sample", "x86_64", b"old")
            .observed_identity(1000)
            .unwrap();
        let helper = observed("/usr/bin/helper", "x86_64", b"helper")
            .observed_identity(1000)
            .unwrap();
        store
            .reconcile_provider(
                1000,
                ApplicationProvider::Rpm,
                vec![first.clone(), helper.clone()],
                false,
                0,
                10,
            )
            .unwrap();
        let other = IdentitySeed {
            provider: ApplicationProvider::Flatpak,
            logical_id: "org.example.App".into(),
            installation_id: "user".into(),
            source_id: "unknown".into(),
            owner_uid: 1000,
        }
        .identity(crate::content_generation(b"flatpak"))
        .unwrap();
        store
            .reconcile_provider(
                1000,
                ApplicationProvider::Flatpak,
                vec![other.clone()],
                false,
                1,
                10,
            )
            .unwrap();
        let next = observed("/usr/bin/sample", "x86_64", b"new");
        let changes = next.reconcile_observation(&mut store, 1000, 2, 20).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].obsolete_generation.as_ref(),
            Some(&first.generation)
        );
        assert_eq!(
            store
                .get_application(1000, &helper.installation_ref)
                .unwrap()
                .unwrap()
                .identity,
            helper
        );
        assert_eq!(
            store
                .get_application(1000, &other.installation_ref)
                .unwrap()
                .unwrap()
                .identity,
            other
        );
        assert_eq!(store.list_applications(1000, None, 100).unwrap().len(), 3);
    }
}
