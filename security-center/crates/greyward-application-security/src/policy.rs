//! Pure policy preparation, not authorization or evidence of enforced access.
//! Only root-owned reconciled records may supply these inputs in the broker.
use greyward_security_domain::{
    AccessGrant, ApplicationIdentity, ApplicationSecurityError, ContentGeneration,
    ExecutionIdentity, GrantLifetime, ProtectedResource, ResourceAccess, SecurityReference,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const MAX_POLICY_RESOURCES: usize = 2_000;
pub const MAX_POLICY_GRANTS: usize = 2_000;
const MAX_INSTALLATION_GRANTS: usize = 32;
const MAX_RUN_MEMBERSHIPS: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("Policy input exceeds its bounded representation")]
    Capacity,
    #[error("Policy revision is invalid or changed")]
    Revision,
    #[error("Policy contains conflicting records")]
    Duplicate,
    #[error("Grant refers to missing or foreign policy objects")]
    ForeignObject,
    #[error("Requested resource is not registered to this owner")]
    UnknownResource,
    #[error(transparent)]
    Contract(#[from] ApplicationSecurityError),
}

/// Desired rule only. Even a candidate still requires prepared kernel policy,
/// validated code, fresh authorization on creation and authoritative readback.
#[derive(Debug, PartialEq, Eq)]
pub enum ResourceRule<'a> {
    DenyUnlessReviewed,
    ReviewedCandidate(&'a SecurityReference),
}

/// Root controller's prepared run record, not a caller-supplied ancestry claim.
/// Code generation is independent of a later installation update.
pub struct RunPolicyMembership {
    pub execution: ExecutionIdentity,
    pub generation: ContentGeneration,
}

/// Rebuild on root policy/inventory revision changes. No serialization, file
/// paths, code execution, frontend commands or mutable authorization flags.
pub struct PolicyIndex {
    revision: u64,
    installations: BTreeMap<SecurityReference, ApplicationIdentity>,
    resources: BTreeMap<SecurityReference, ProtectedResource>,
    grants: BTreeMap<SecurityReference, Vec<AccessGrant>>,
    stale_grants: BTreeSet<SecurityReference>,
    run_memberships: BTreeMap<SecurityReference, RunPolicyMembership>,
}

impl PolicyIndex {
    /// Build a bounded immutable representation outside the ordinary launch
    /// path. Changed code keeps its old grant visible for review, but inactive.
    /// # Errors
    /// Rejects corrupt, duplicate, foreign, future or unbounded policy records.
    pub fn prepare(
        revision: u64,
        installations: Vec<ApplicationIdentity>,
        resources: Vec<ProtectedResource>,
        grants: Vec<AccessGrant>,
        run_memberships: Vec<RunPolicyMembership>,
    ) -> Result<Self, PolicyError> {
        if revision == 0 {
            return Err(PolicyError::Revision);
        }
        if installations.len() > crate::MAX_APPLICATIONS
            || resources.len() > MAX_POLICY_RESOURCES
            || grants.len() > MAX_POLICY_GRANTS
            || run_memberships.len() > MAX_RUN_MEMBERSHIPS
        {
            return Err(PolicyError::Capacity);
        }
        let mut index = Self {
            revision,
            installations: BTreeMap::new(),
            resources: BTreeMap::new(),
            grants: BTreeMap::new(),
            stale_grants: BTreeSet::new(),
            run_memberships: BTreeMap::new(),
        };
        for installation in installations {
            installation.validate()?;
            if index
                .installations
                .insert(installation.installation_ref.clone(), installation)
                .is_some()
            {
                return Err(PolicyError::Duplicate);
            }
        }
        for resource in resources {
            resource.validate()?;
            if resource.policy_revision == 0 || resource.policy_revision > revision {
                return Err(PolicyError::Revision);
            }
            if index
                .resources
                .insert(resource.resource_ref.clone(), resource)
                .is_some()
            {
                return Err(PolicyError::Duplicate);
            }
        }
        for membership in run_memberships {
            let execution = &membership.execution;
            execution.validate()?;
            if execution
                .installation_ref
                .as_ref()
                .and_then(|reference| index.installations.get(reference))
                .is_none_or(|identity| identity.owner_uid != execution.owner_uid)
            {
                return Err(PolicyError::ForeignObject);
            }
            if index
                .run_memberships
                .insert(execution.execution_ref.clone(), membership)
                .is_some()
            {
                return Err(PolicyError::Duplicate);
            }
        }
        let mut references = BTreeSet::new();
        for grant in grants {
            grant.validate()?;
            if grant.policy_revision > revision {
                return Err(PolicyError::Revision);
            }
            if !references.insert(grant.grant_ref.clone()) {
                return Err(PolicyError::Duplicate);
            }
            let installation = index
                .installations
                .get(&grant.installation_ref)
                .filter(|identity| identity.owner_uid == grant.owner_uid)
                .ok_or(PolicyError::ForeignObject)?;
            for resource in &grant.resources {
                if index
                    .resources
                    .get(resource)
                    .is_none_or(|record| record.owner_uid != grant.owner_uid)
                {
                    return Err(PolicyError::ForeignObject);
                }
            }
            if installation.generation != grant.generation {
                index.stale_grants.insert(grant.grant_ref.clone());
            }
            let entries = index
                .grants
                .entry(grant.installation_ref.clone())
                .or_default();
            if entries.len() >= MAX_INSTALLATION_GRANTS {
                return Err(PolicyError::Capacity);
            }
            entries.push(grant);
        }
        // Stable ordering makes overlapping reviews deterministic.
        for entries in index.grants.values_mut() {
            entries.sort_by(|left, right| left.grant_ref.cmp(&right.grant_ref));
        }
        Ok(index)
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn stale_grants(&self) -> impl Iterator<Item = &SecurityReference> {
        self.stale_grants.iter()
    }

    /// Pure desired-policy evaluation. The broker must supply a validated
    /// installation and root-controlled workload identity, never a claimed
    /// application/execution reference from the caller. This method attaches
    /// no restrictions and produces no Allowed/Protected presentation state.
    /// # Errors
    /// Rejects stale policy, foreign resources and malformed identities.
    pub fn resource_rule(
        &self,
        expected_revision: u64,
        installation: &ApplicationIdentity,
        execution: Option<&ExecutionIdentity>,
        resource: &SecurityReference,
        access: ResourceAccess,
    ) -> Result<ResourceRule<'_>, PolicyError> {
        if self.revision != expected_revision {
            return Err(PolicyError::Revision);
        }
        installation.validate()?;
        if self
            .resources
            .get(resource)
            .is_none_or(|record| record.owner_uid != installation.owner_uid)
        {
            return Err(PolicyError::UnknownResource);
        }
        // A forged source/provenance or replaced generation is not the cached
        // installation. Unknown direct execution gets no candidate implicitly.
        if self.installations.get(&installation.installation_ref) != Some(installation) {
            return Ok(ResourceRule::DenyUnlessReviewed);
        }
        if let Some(execution) = execution {
            execution.validate()?;
            if execution.owner_uid != installation.owner_uid
                || execution.installation_ref.as_ref() != Some(&installation.installation_ref)
                || self
                    .run_memberships
                    .get(&execution.execution_ref)
                    .is_none_or(|member| {
                        &member.execution != execution
                            || member.generation != installation.generation
                    })
            {
                return Ok(ResourceRule::DenyUnlessReviewed);
            }
        }
        let Some(grants) = self.grants.get(&installation.installation_ref) else {
            return Ok(ResourceRule::DenyUnlessReviewed);
        };
        for grant in grants {
            if self.stale_grants.contains(&grant.grant_ref)
                || !grant.resources.contains(resource)
                || !grant.access.contains(&access)
            {
                continue;
            }
            let eligible = match &grant.lifetime {
                GrantLifetime::Persistent => true,
                GrantLifetime::ThisRun { execution_ref } => execution.is_some_and(|identity| {
                    identity.owner_uid == grant.owner_uid
                        && identity.installation_ref.as_ref() == Some(&grant.installation_ref)
                        && &identity.execution_ref == execution_ref
                        && self
                            .run_memberships
                            .get(execution_ref)
                            .is_some_and(|member| {
                                &member.execution == identity
                                    && member.generation == grant.generation
                            })
                }),
            };
            if eligible {
                return Ok(ResourceRule::ReviewedCandidate(&grant.grant_ref));
            }
        }
        Ok(ResourceRule::DenyUnlessReviewed)
    }
}
