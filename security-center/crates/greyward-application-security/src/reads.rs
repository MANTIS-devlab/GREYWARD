//! Read projections scoped to a kernel-bound caller. No policy mutation API.
//! Inventory records alone cannot establish enforcement or collection coverage.
use crate::{ExecutionError, ExecutionHandle, PolicyStore, RegistryEntry, StoreError};
use greyward_security_domain::{
    APPLICATION_SECURITY_SCHEMA, EnforcementEvidence, EnforcementHealth, ProtectionProfile,
    ProtectionSnapshot, SecurityReference,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReadError {
    #[error("Invalid bounded application query")]
    InvalidQuery,
    #[error("Application inventory revision changed")]
    RevisionChanged,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
}

pub type ApplicationDetails = greyward_security_domain::ApplicationReadDetails;
pub type ApplicationPage = greyward_security_domain::ApplicationInventoryPage;

pub struct ApplicationReads<'a> {
    store: &'a PolicyStore,
}

fn detail(record: RegistryEntry, evidence: &EnforcementEvidence) -> ApplicationDetails {
    let requested = match record.identity.provider {
        greyward_security_domain::ApplicationProvider::AppImage
        | greyward_security_domain::ApplicationProvider::Script
        | greyward_security_domain::ApplicationProvider::Manual => ProtectionProfile::Isolated,
        _ => ProtectionProfile::Protected,
    };
    // No live enforcement provider is installed in this foundation. Preserve
    // uncertainty instead of deriving protection from a signed package/record.
    let protection = ProtectionSnapshot::from_evidence(requested, evidence);
    ApplicationDetails { record, protection }
}

impl<'a> ApplicationReads<'a> {
    pub fn new(store: &'a PolicyStore) -> Self {
        Self { store }
    }

    /// # Errors
    /// Exited/foreign peers, stale pages and invalid queries refuse. A journal
    /// never supplies coverage; without retained live proof metadata stays UNKNOWN.
    pub fn resources(
        &self,
        actor: &ExecutionHandle,
        after: Option<&SecurityReference>,
        expected_revision: Option<u64>,
        limit: usize,
    ) -> Result<greyward_security_domain::ProtectedResourcePage, ReadError> {
        actor.revalidate()?;
        if !(1..=100).contains(&limit) || (after.is_some() && expected_revision.is_none()) {
            return Err(ReadError::InvalidQuery);
        }
        let state = self.store.desired_policy()?;
        if expected_revision.is_some_and(|r| r != state.revision) {
            return Err(ReadError::RevisionChanged);
        }
        let owner = actor.identity().owner_uid;
        let protection = self.store.protection_prerequisites(actor)?;
        let mut scoped_resources: Vec<_> = state
            .resources
            .into_iter()
            .filter(|r| r.resource().owner_uid == owner)
            .map(|r| {
                let mut resource = r.resource().clone();
                if protection.coverage.complete() {
                    resource.coverage = greyward_security_domain::ResourceCoverage::Protected;
                }
                resource
            })
            .collect();
        scoped_resources.sort_by(|a, b| a.resource_ref.cmp(&b.resource_ref));
        if after.is_some_and(|cursor| {
            cursor.namespace() != "resource"
                || !scoped_resources.iter().any(|r| &r.resource_ref == cursor)
        }) {
            return Err(ReadError::InvalidQuery);
        }
        let resources: Vec<_> = scoped_resources
            .into_iter()
            .filter(|r| after.is_none_or(|cursor| &r.resource_ref > cursor))
            .take(limit)
            .collect();
        actor.revalidate()?;
        if self.store.desired_policy()?.revision != state.revision {
            return Err(ReadError::RevisionChanged);
        }
        let next_cursor = if resources.len() == limit {
            resources.last().map(|r| r.resource_ref.clone())
        } else {
            None
        };
        Ok(greyward_security_domain::ProtectedResourcePage {
            schema: APPLICATION_SECURITY_SCHEMA.into(),
            policy_revision: state.revision,
            inventory_health: EnforcementHealth::Unknown,
            resources,
            next_cursor,
        })
    }

    /// # Errors
    /// Foreign and absent resources have identical absence; no object IDs or
    /// private paths are disclosed. Policy/caller changes refuse the projection.
    pub fn resource(
        &self,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
    ) -> Result<greyward_security_domain::ProtectedResourceLookup, ReadError> {
        actor.revalidate()?;
        if reference.namespace() != "resource" {
            return Err(ReadError::InvalidQuery);
        }
        let state = self.store.desired_policy()?;
        let protection = self.store.protection_prerequisites(actor)?;
        let resource = state
            .resources
            .iter()
            .find(|r| {
                &r.resource().resource_ref == reference
                    && r.resource().owner_uid == actor.identity().owner_uid
            })
            .map(|r| {
                let mut resource = r.resource().clone();
                if protection.coverage.complete() {
                    resource.coverage = greyward_security_domain::ResourceCoverage::Protected;
                }
                resource
            });
        actor.revalidate()?;
        if self.store.desired_policy()?.revision != state.revision {
            return Err(ReadError::RevisionChanged);
        }
        Ok(greyward_security_domain::ProtectedResourceLookup {
            schema: APPLICATION_SECURITY_SCHEMA.into(),
            policy_revision: state.revision,
            resource,
        })
    }

    /// # Errors
    /// Rejects exited/replaced peers, stale pagination, unowned cursors and
    /// malformed queries. The UID comes only from the authenticated handle.
    pub fn list(
        &self,
        actor: &ExecutionHandle,
        after: Option<&SecurityReference>,
        expected_revision: Option<u64>,
        limit: usize,
    ) -> Result<ApplicationPage, ReadError> {
        actor.revalidate()?;
        if !(1..=100).contains(&limit) || (after.is_some() && expected_revision.is_none()) {
            return Err(ReadError::InvalidQuery);
        }
        let owner = actor.identity().owner_uid;
        let before = self.store.inventory_revision()?;
        let evidence = if self.store.production {
            self.store.protection_prerequisites(actor)?
        } else {
            EnforcementEvidence::default()
        };
        if expected_revision.is_some_and(|expected| before != expected) {
            return Err(ReadError::RevisionChanged);
        }
        if let Some(cursor) = after {
            if cursor.namespace() != "installation"
                || self.store.get_application(owner, cursor)?.is_none()
            {
                return Err(ReadError::InvalidQuery);
            }
        }
        let applications: Vec<_> = self
            .store
            .list_applications(owner, after, limit)?
            .into_iter()
            .map(|record| detail(record, &evidence))
            .collect();
        actor.revalidate()?;
        if self.store.inventory_revision()? != before {
            return Err(ReadError::RevisionChanged);
        }
        // A full page may require one final empty read. This never silently drops
        // records after the first page or guesses that collection is complete.
        let next_cursor = if applications.len() == limit {
            applications
                .last()
                .map(|value| value.record.identity.installation_ref.clone())
        } else {
            None
        };
        Ok(ApplicationPage {
            schema: APPLICATION_SECURITY_SCHEMA.into(),
            inventory_revision: before,
            inventory_health: EnforcementHealth::Unknown,
            applications,
            next_cursor,
        })
    }

    /// # Errors
    /// Unknown/foreign IDs return the same absence. Storage or caller-identity
    /// failures stay errors, never an empty safe application snapshot.
    pub fn get(
        &self,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
    ) -> Result<Option<ApplicationDetails>, ReadError> {
        actor.revalidate()?;
        if reference.namespace() != "installation" {
            return Err(ReadError::InvalidQuery);
        }
        let before = self.store.inventory_revision()?;
        let record = self
            .store
            .get_application(actor.identity().owner_uid, reference)?;
        actor.revalidate()?;
        if self.store.inventory_revision()? != before {
            return Err(ReadError::RevisionChanged);
        }
        let evidence = if self.store.production {
            self.store.protection_prerequisites(actor)?
        } else {
            EnforcementEvidence::default()
        };
        Ok(record.map(|record| detail(record, &evidence)))
    }
}
