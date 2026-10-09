use greyward_security_domain::{
    ApplicationIdentity, ApplicationProvider, ApplicationSecurityError, ContentGeneration,
    ProvenanceSnapshot, SecurityReference,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const MAX_APPLICATIONS: usize = 2_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("Provider identity metadata is invalid")]
    InvalidMetadata,
    #[error("Application inventory limit reached")]
    Capacity,
    #[error("Conflicting installation records")]
    DuplicateInstallation,
    #[error("Inventory revision exhausted")]
    RevisionExhausted,
    #[error(transparent)]
    Identity(#[from] ApplicationSecurityError),
}

/// Only provider collectors supply these fields. A path/name is not authenticity.
#[derive(Debug, Clone)]
pub struct IdentitySeed {
    pub provider: ApplicationProvider,
    pub logical_id: String,
    pub installation_id: String,
    pub source_id: String,
    pub owner_uid: u32,
}

fn metadata_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-:".contains(&byte))
}

pub(crate) fn framed_digest(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(
            u64::try_from(part.len())
                .expect("Bounded identity fields fit in u64")
                .to_le_bytes(),
        );
        hash.update(part);
    }
    format!("{:x}", hash.finalize())
}

impl IdentitySeed {
    /// # Errors
    /// Rejects unbounded metadata and path/URL/command-shaped identifiers.
    pub fn identity(
        &self,
        generation: ContentGeneration,
    ) -> Result<ApplicationIdentity, RegistryError> {
        if ![&self.logical_id, &self.installation_id, &self.source_id]
            .into_iter()
            .all(|value| metadata_valid(value))
        {
            return Err(RegistryError::InvalidMetadata);
        }
        let provider = match self.provider {
            ApplicationProvider::Rpm => "rpm",
            ApplicationProvider::Flatpak => "flatpak",
            ApplicationProvider::AppImage => "appimage",
            ApplicationProvider::Manual => "manual",
            ApplicationProvider::Script => "script",
            ApplicationProvider::Unknown => "unknown",
        };
        let uid = self.owner_uid.to_le_bytes();
        let application = framed_digest(&[
            b"application/v1",
            provider.as_bytes(),
            self.logical_id.as_bytes(),
            &uid,
        ]);
        let installation = framed_digest(&[
            b"installation/v1",
            application.as_bytes(),
            self.installation_id.as_bytes(),
            self.source_id.as_bytes(),
        ]);
        Ok(ApplicationIdentity {
            display_name: (self.logical_id.len() != 64).then(|| self.logical_id.clone()),
            application_ref: SecurityReference::try_from(format!("application_{application}"))?,
            installation_ref: SecurityReference::try_from(format!("installation_{installation}"))?,
            generation,
            provider: self.provider,
            owner_uid: self.owner_uid,
            provenance: ProvenanceSnapshot::default(),
        })
    }
}

/// Digest already acquired/verified provider content, never a pathname alone.
/// # Panics
/// Only if the SHA-256 implementation returns a noncanonical digest.
pub fn content_generation(content: &[u8]) -> ContentGeneration {
    // SHA-256 always produces the lowercase 64-byte form required by the type.
    ContentGeneration::try_from(format!("{:x}", Sha256::digest(content)))
        .expect("SHA-256 content generation must be canonical")
}

pub type RegistryEntry = greyward_security_domain::ApplicationInventoryRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryChange {
    pub installation_ref: SecurityReference,
    pub obsolete_generation: Option<ContentGeneration>,
}

/// A single broker owns mutation; callers receive bounded per-owner projections.
#[derive(Debug, Clone, Default)]
pub struct ApplicationRegistry {
    entries: BTreeMap<SecurityReference, RegistryEntry>,
    revision: u64,
}

impl ApplicationRegistry {
    pub(crate) fn restore(
        entries: Vec<RegistryEntry>,
        revision: u64,
    ) -> Result<Self, RegistryError> {
        if entries.len() > MAX_APPLICATIONS {
            return Err(RegistryError::Capacity);
        }
        let mut indexed = BTreeMap::new();
        for entry in entries {
            entry.identity.validate()?;
            if entry.last_seen < entry.first_seen {
                return Err(RegistryError::InvalidMetadata);
            }
            if indexed
                .insert(entry.identity.installation_ref.clone(), entry)
                .is_some()
            {
                return Err(RegistryError::DuplicateInstallation);
            }
        }
        Ok(Self {
            entries: indexed,
            revision,
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Atomically reconcile one owner's inventory. Validate everything first.
    /// # Errors
    /// Rejects invalid/duplicate identities or capacity overflow without mutation.
    pub fn reconcile(
        &mut self,
        owner_uid: u32,
        identities: Vec<ApplicationIdentity>,
        now: u64,
    ) -> Result<Vec<InventoryChange>, RegistryError> {
        self.reconcile_scope(owner_uid, None, identities, true, now)
    }

    /// Reconcile one provider without erasing another provider's inventory.
    /// Partial reads can update observed records, but cannot infer uninstall.
    /// # Errors
    /// Rejects foreign providers/owners, collisions and invalid batches atomically.
    pub fn reconcile_provider(
        &mut self,
        owner_uid: u32,
        provider: ApplicationProvider,
        identities: Vec<ApplicationIdentity>,
        complete: bool,
        now: u64,
    ) -> Result<Vec<InventoryChange>, RegistryError> {
        self.reconcile_scope(owner_uid, Some(provider), identities, complete, now)
    }

    pub(crate) fn reconcile_scope(
        &mut self,
        owner_uid: u32,
        provider: Option<ApplicationProvider>,
        identities: Vec<ApplicationIdentity>,
        complete: bool,
        now: u64,
    ) -> Result<Vec<InventoryChange>, RegistryError> {
        if identities.len() > MAX_APPLICATIONS {
            return Err(RegistryError::Capacity);
        }
        let mut prepared = BTreeMap::new();
        for identity in identities {
            identity.validate()?;
            if identity.owner_uid != owner_uid
                || provider.is_some_and(|expected| identity.provider != expected)
                || self
                    .entries
                    .get(&identity.installation_ref)
                    .is_some_and(|old| {
                        old.identity.owner_uid != owner_uid
                            || old.identity.provider != identity.provider
                    })
            {
                return Err(RegistryError::InvalidMetadata);
            }
            if prepared
                .insert(identity.installation_ref.clone(), identity)
                .is_some()
            {
                return Err(RegistryError::DuplicateInstallation);
            }
        }
        let selected = |entry: &RegistryEntry| {
            entry.identity.owner_uid == owner_uid
                && provider.is_none_or(|value| entry.identity.provider == value)
        };
        let retained = self
            .entries
            .values()
            .filter(|entry| {
                !selected(entry)
                    || (!complete && !prepared.contains_key(&entry.identity.installation_ref))
            })
            .count();
        if retained + prepared.len() > MAX_APPLICATIONS {
            return Err(RegistryError::Capacity);
        }
        let mut next = self.entries.clone();
        next.retain(|_, entry| !selected(entry) || !complete);
        let mut changes = Vec::new();
        for (reference, entry) in &self.entries {
            if complete && selected(entry) && !prepared.contains_key(reference) {
                changes.push(InventoryChange {
                    installation_ref: reference.clone(),
                    obsolete_generation: Some(entry.identity.generation.clone()),
                });
            }
        }
        for (reference, identity) in prepared {
            let previous = self.entries.get(&reference);
            let obsolete_generation = previous
                .filter(|entry| entry.identity.generation != identity.generation)
                .map(|entry| entry.identity.generation.clone());
            if previous.is_none() || obsolete_generation.is_some() {
                changes.push(InventoryChange {
                    installation_ref: reference.clone(),
                    obsolete_generation,
                });
            }
            next.insert(
                reference,
                RegistryEntry {
                    identity,
                    first_seen: previous.map_or(now, |entry| entry.first_seen),
                    last_seen: previous.map_or(now, |entry| entry.last_seen.max(now)),
                },
            );
        }
        if next != self.entries {
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or(RegistryError::RevisionExhausted)?;
            self.entries = next;
        }
        Ok(changes)
    }

    pub fn list(
        &self,
        owner_uid: u32,
        after: Option<&SecurityReference>,
        limit: usize,
    ) -> Vec<&RegistryEntry> {
        self.entries
            .iter()
            .filter(|(reference, entry)| {
                entry.identity.owner_uid == owner_uid
                    && after.is_none_or(|cursor| *reference > cursor)
            })
            .take(limit.min(100))
            .map(|(_, entry)| entry)
            .collect()
    }

    pub fn generation_matches(
        &self,
        owner_uid: u32,
        reference: &SecurityReference,
        generation: &ContentGeneration,
    ) -> bool {
        self.entries.get(reference).is_some_and(|entry| {
            entry.identity.owner_uid == owner_uid && &entry.identity.generation == generation
        })
    }

    pub fn get(&self, owner_uid: u32, reference: &SecurityReference) -> Option<&RegistryEntry> {
        self.entries
            .get(reference)
            .filter(|entry| entry.identity.owner_uid == owner_uid)
    }
}
