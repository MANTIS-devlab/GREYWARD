//! Internal provider-to-registry intake. This is not a session mutation API.
//! Provider metadata supplies observed identity, never publisher approval or a
//! grant. Incomplete observations cannot establish uninstall or enforcement.
use crate::{
    IdentitySeed, InventoryChange, MAX_APPLICATIONS, PolicyStore, RegistryError, StoreError,
    framed_digest,
};
use greyward_security_backends::{FlatpakAvailability, FlatpakFacts};
use greyward_security_domain::{ApplicationIdentity, ApplicationProvider};
use std::collections::BTreeSet;

pub struct FlatpakInventoryObservation {
    owner_uid: u32,
    identities: Vec<ApplicationIdentity>,
    complete: bool,
}

fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with(['-', '.'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

impl FlatpakInventoryObservation {
    /// The trusted collector supplies the authenticated owner's default system
    /// and user installations. User-controlled deployment/repository metadata
    /// remains unverified. Named installations need their separate provider.
    /// # Errors
    /// Invalid or duplicate descriptors reject the batch before storage changes.
    pub fn from_provider(
        facts: &FlatpakFacts,
        authenticated_uid: u32,
    ) -> Result<Self, RegistryError> {
        if facts.apps.len() > MAX_APPLICATIONS {
            return Err(RegistryError::Capacity);
        }
        let mut observation = Self {
            owner_uid: authenticated_uid,
            identities: Vec::new(),
            complete: facts.availability == FlatpakAvailability::Available,
        };
        if !matches!(
            facts.availability,
            FlatpakAvailability::Available | FlatpakAvailability::Partial
        ) {
            observation.complete = false;
            return Ok(observation);
        }
        let mut references = BTreeSet::new();
        for app in &facts.apps {
            let (Some(arch), Some(branch)) = (&app.arch, &app.branch) else {
                observation.complete = false;
                continue;
            };
            if app.app_id.len() > 255
                || app.app_id.split('.').count() < 3
                || !app.app_id.split('.').all(segment)
                || !segment(arch)
                || !segment(branch)
                || !matches!(app.scope.as_str(), "system" | "user")
                || app.origin.as_ref().is_some_and(|origin| {
                    origin.is_empty() || origin.len() > 256 || origin.chars().any(char::is_control)
                })
            {
                return Err(RegistryError::InvalidMetadata);
            }
            if !references.insert((&app.app_id, &app.scope, arch, branch)) {
                return Err(RegistryError::DuplicateInstallation);
            }
            let Some(generation) = app
                .deployment_commit
                .as_ref()
                .filter(|_| app.identity_state == FlatpakAvailability::Available)
            else {
                observation.complete = false;
                continue;
            };
            // Frame fields so different repository/install/channel tuples never
            // collide through concatenation. Missing origin is not an origin
            // literally named "unknown". Neither state proves authenticity.
            let installation = framed_digest(&[
                b"flatpak-installation/v1",
                app.scope.as_bytes(),
                arch.as_bytes(),
                branch.as_bytes(),
            ]);
            let source = framed_digest(&[
                b"flatpak-repository/v1",
                &[u8::from(app.origin.is_some())],
                app.origin.as_deref().unwrap_or("").as_bytes(),
            ]);
            observation.identities.push(
                IdentitySeed {
                    provider: ApplicationProvider::Flatpak,
                    logical_id: app.app_id.clone(),
                    installation_id: installation,
                    source_id: source,
                    owner_uid: authenticated_uid,
                }
                .identity(generation.clone())?,
            );
        }
        Ok(observation)
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Commit once against the expected policy-store inventory revision. No
    /// grant transfer, permission reset or protection claim accompanies intake.
    /// # Errors
    /// Stale revisions and invalid/corrupt storage leave the transaction intact.
    pub fn reconcile(
        self,
        store: &mut PolicyStore,
        expected_revision: u64,
        now: u64,
    ) -> Result<Vec<InventoryChange>, StoreError> {
        store.reconcile_provider(
            self.owner_uid,
            ApplicationProvider::Flatpak,
            self.identities,
            self.complete,
            expected_revision,
            now,
        )
    }
}
