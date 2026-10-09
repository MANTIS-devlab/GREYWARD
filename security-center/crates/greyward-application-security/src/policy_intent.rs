//! Durable reviewed intentions, never effective grants or protected labels.
//! Only a fresh kernel-bound owner authorization can commit a review. No bus
//! mutation is exposed until the matching enforcement/readback provider exists.
use crate::resource_selection::DirectoryObjectReceipt;
use crate::{
    AuthorizationError, AuthorizationIntent, AuthorizationPurpose, DirectorySelection,
    ExecutionError, ExecutionHandle, PolicyStore, ResourceRegistrationLease,
    ResourceSelectionError, StoreError, SystemAuthorizer, registry::framed_digest,
};
use dbus::strings::BusName;
use greyward_security_domain::{
    AccessGrant, ApplicationIdentity, ExecutionIdentity, GrantLifetime, ProtectedCategory,
    ProtectedResource, ResourceCoverage, SecurityReference,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyIntentError {
    #[error("Policy review is invalid or no longer owned by this execution")]
    InvalidReview,
    #[error("Policy review expired")]
    Deadline,
    #[error("Application generation or resource review changed")]
    Changed,
    #[error("Timed access requires verified workload lifetime and is not available")]
    TimedGrantUnavailable,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Selection(#[from] ResourceSelectionError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
}

/// Private root policy metadata. No path, contents or effective label is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceIntent {
    pub(crate) resource: ProtectedResource,
    pub(crate) object: DirectoryObjectReceipt,
    pub(crate) reviewed_by: ExecutionIdentity,
    pub(crate) operation_ref: SecurityReference,
}

impl ResourceIntent {
    pub fn resource(&self) -> &ProtectedResource {
        &self.resource
    }

    pub(crate) fn validate(&self, revision: u64) -> bool {
        self.resource.validate().is_ok()
            && self.reviewed_by.validate().is_ok()
            && self.operation_ref.namespace() == "operation"
            && self.resource.coverage == ResourceCoverage::Unknown
            && self.resource.owner_uid == self.reviewed_by.owner_uid
            && self.object.owner_uid == self.resource.owner_uid
            && self.object.inode != 0
            && (0..1_000_000_000).contains(&self.object.changed_nanoseconds)
            && (1..=revision).contains(&self.resource.policy_revision)
    }
}

/// Reviewed persistent proposal. It grants no access and cannot be converted
/// into an effective readback simply by loading it from SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantIntent {
    pub(crate) grant: AccessGrant,
    pub(crate) installation: ApplicationIdentity,
    pub(crate) reviewed_by: ExecutionIdentity,
    pub(crate) operation_ref: SecurityReference,
    // Legacy development records remain readable for withdrawal. Absence never
    // acquires a tested profile or automatic launch permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tool_profile: Option<crate::ReviewedToolProfile>,
}

impl GrantIntent {
    pub fn proposal(&self) -> &AccessGrant {
        &self.grant
    }

    pub(crate) fn validate(&self, revision: u64) -> bool {
        self.grant.validate().is_ok()
            && self.installation.validate().is_ok()
            && self.reviewed_by.validate().is_ok()
            && self.operation_ref.namespace() == "operation"
            && self.grant.lifetime == GrantLifetime::Persistent
            && self.grant.owner_uid == self.reviewed_by.owner_uid
            && self.grant.owner_uid == self.installation.owner_uid
            && self.grant.installation_ref == self.installation.installation_ref
            && self.grant.generation == self.installation.generation
            && (1..=revision).contains(&self.grant.policy_revision)
    }
}

/// Internal bounded snapshot, separate from live coverage and event history.
pub struct DesiredPolicyState {
    pub revision: u64,
    pub resources: Vec<ResourceIntent>,
    pub grants: Vec<GrantIntent>,
}

pub(crate) enum IntentChange {
    Register(ResourceIntent),
    ProposeGrant(GrantIntent),
    RevokeGrant(SecurityReference),
    RemoveCustomResource(SecurityReference),
}

pub struct PolicyReviewLease {
    pub operation_ref: SecurityReference,
    pub expected_revision: u64,
    pub deadline: Instant,
}

pub struct DirectoryResourceReview {
    pub selection: DirectorySelection,
    pub category: ProtectedCategory,
    pub label: String,
}

/// Immutable, non-deserializable reviewed payload retained by the broker.
/// A UI may return an operation reference; it cannot replace this payload.
pub struct PolicyIntentReview {
    actor: ExecutionIdentity,
    lease: PolicyReviewLease,
    change: IntentChange,
    selection: Option<DirectorySelection>,
}

/// A storage acknowledgment only, never `OperationResult::Completed` or evidence
/// that resources have been labelled, workloads restarted or access revoked.
pub struct DesiredPolicyCommit {
    pub revision: u64,
    registration: Option<ResourceRegistrationLease>,
}

impl DesiredPolicyCommit {
    /// Transfer the held selection once, after successful fresh authorization
    /// and persistence. This is still pending, not a completed registration.
    pub fn take_registration(&mut self) -> Option<ResourceRegistrationLease> {
        self.registration.take()
    }
}

impl PolicyIntentReview {
    /// A presentation summary contains no descriptor, path or authorization.
    /// # Errors
    /// Only a live, immutable directory review supplies this summary.
    pub fn registration_preview(
        &self,
    ) -> Result<greyward_security_domain::ResourceRegistrationPreview, PolicyIntentError> {
        let IntentChange::Register(record) = &self.change else {
            return Err(PolicyIntentError::InvalidReview);
        };
        let remaining = self
            .lease
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(PolicyIntentError::Deadline)?;
        let preview = greyward_security_domain::ResourceRegistrationPreview {
            operation_ref: self.lease.operation_ref.clone(),
            resource: record.resource.clone(),
            expected_revision: self.lease.expected_revision,
            expires_after_ms: u32::try_from(remaining.as_millis())
                .map_err(|_| PolicyIntentError::InvalidReview)?,
        };
        preview
            .validate()
            .map_err(|_| PolicyIntentError::InvalidReview)?;
        Ok(preview)
    }
    fn prepare(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        lease: PolicyReviewLease,
        change: IntentChange,
        selection: Option<DirectorySelection>,
    ) -> Result<Self, PolicyIntentError> {
        actor.revalidate()?;
        if lease.operation_ref.namespace() != "operation"
            || lease.expected_revision == 0
            || lease
                .deadline
                .checked_duration_since(Instant::now())
                .is_none_or(|remaining| remaining.is_zero() || remaining > Duration::from_secs(120))
        {
            return Err(PolicyIntentError::InvalidReview);
        }
        let review = Self {
            actor: actor.identity().clone(),
            lease,
            change,
            selection,
        };
        review.revalidate(store, actor)?;
        Ok(review)
    }

    /// Review the held directory, without relabeling or reporting it protected.
    /// # Errors
    /// Changed/foreign descriptors, malformed copy, stale policy or expiry refuse.
    pub fn register_directory(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        input: DirectoryResourceReview,
        lease: PolicyReviewLease,
    ) -> Result<Self, PolicyIntentError> {
        let object = input.selection.object_receipt()?;
        let resource_ref = SecurityReference::try_from(format!(
            "resource_{}",
            framed_digest(&[
                b"resource-intent/v1",
                actor.identity().boot_id.as_bytes(),
                input.selection.selection_ref().as_str().as_bytes(),
            ])
        ))
        .map_err(|_| PolicyIntentError::InvalidReview)?;
        let revision = lease
            .expected_revision
            .checked_add(1)
            .ok_or(PolicyIntentError::InvalidReview)?;
        let record = ResourceIntent {
            resource: ProtectedResource {
                resource_ref,
                owner_uid: object.owner_uid,
                category: input.category,
                label: input.label,
                coverage: ResourceCoverage::Unknown,
                policy_revision: revision,
            },
            object,
            reviewed_by: actor.identity().clone(),
            operation_ref: lease.operation_ref.clone(),
        };
        Self::prepare(
            store,
            actor,
            lease,
            IntentChange::Register(record),
            Some(input.selection),
        )
    }

    /// Persistent raw-access review. In-process extensions share any eventual
    /// grant; mandatory compilation/readback must precede effective activation.
    /// # Errors
    /// Missing/foreign resources, changed code, stale revisions or timed grants.
    pub fn propose_persistent_grant(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        grant: AccessGrant,
        lease: PolicyReviewLease,
    ) -> Result<Self, PolicyIntentError> {
        Self::propose_profiled_grant(store, actor, grant, lease, None)
    }

    pub(crate) fn propose_profiled_grant(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        mut grant: AccessGrant,
        lease: PolicyReviewLease,
        tool_profile: Option<crate::ReviewedToolProfile>,
    ) -> Result<Self, PolicyIntentError> {
        if grant.lifetime != GrantLifetime::Persistent {
            return Err(PolicyIntentError::TimedGrantUnavailable);
        }
        let installation = store
            .get_application(actor.identity().owner_uid, &grant.installation_ref)?
            .ok_or(PolicyIntentError::Changed)?
            .identity;
        grant.policy_revision = lease
            .expected_revision
            .checked_add(1)
            .ok_or(PolicyIntentError::InvalidReview)?;
        let record = GrantIntent {
            grant,
            installation,
            reviewed_by: actor.identity().clone(),
            operation_ref: lease.operation_ref.clone(),
            tool_profile,
        };
        Self::prepare(
            store,
            actor,
            lease,
            IntentChange::ProposeGrant(record),
            None,
        )
    }

    /// Revoke an intention. Existing effective workloads still need separate
    /// termination and verified kernel readback; this cannot promise revocation.
    /// # Errors
    /// Unknown/foreign grant, stale revision or expired review.
    pub fn revoke_grant(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: SecurityReference,
        lease: PolicyReviewLease,
    ) -> Result<Self, PolicyIntentError> {
        Self::prepare(
            store,
            actor,
            lease,
            IntentChange::RevokeGrant(reference),
            None,
        )
    }

    /// Only custom resources can be removed through this per-user operation.
    /// # Errors
    /// Foreign/fixed/dependent resources or stale/expired review are refused.
    pub fn remove_custom_resource(
        store: &PolicyStore,
        actor: &ExecutionHandle,
        reference: SecurityReference,
        lease: PolicyReviewLease,
    ) -> Result<Self, PolicyIntentError> {
        Self::prepare(
            store,
            actor,
            lease,
            IntentChange::RemoveCustomResource(reference),
            None,
        )
    }

    fn revalidate(
        &self,
        store: &PolicyStore,
        actor: &ExecutionHandle,
    ) -> Result<(), PolicyIntentError> {
        if Instant::now() >= self.lease.deadline {
            return Err(PolicyIntentError::Deadline);
        }
        actor.revalidate()?;
        if actor.identity() != &self.actor {
            return Err(PolicyIntentError::Changed);
        }
        if let Some(selection) = &self.selection {
            selection.revalidate()?;
        }
        store.validate_intent_change(
            self.actor.owner_uid,
            self.lease.expected_revision,
            &self.change,
        )?;
        Ok(())
    }

    /// Fresh owner authentication, exact peer/payload revalidation and a CAS
    /// transaction. No cached authorization, mutable UI payload or kernel fallback.
    /// # Errors
    /// Any authorization, identity, descriptor, revision or storage failure.
    pub fn commit(
        self,
        store: &mut PolicyStore,
        actor: &ExecutionHandle,
        sender: &BusName<'_>,
        authorizer: &SystemAuthorizer,
        interactive: bool,
    ) -> Result<DesiredPolicyCommit, PolicyIntentError> {
        self.revalidate(store, actor)?;
        let intent = AuthorizationIntent {
            purpose: AuthorizationPurpose::OwnerGrant,
            operation_ref: self.lease.operation_ref.clone(),
            expected_revision: self.lease.expected_revision,
            deadline: self
                .lease
                .deadline
                .min(Instant::now() + Duration::from_secs(30)),
            interactive,
        };
        let ticket = authorizer.authorize(&intent, sender, actor)?;
        self.revalidate(store, actor)?;
        authorizer.consume_ticket(ticket, &intent, sender, actor)?;
        self.revalidate(store, actor)?;
        let revision = store.commit_intent_change(
            self.actor.owner_uid,
            self.lease.expected_revision,
            &self.change,
        )?;
        let registration = match (self.change, self.selection) {
            (IntentChange::Register(record), Some(selection)) => {
                Some(ResourceRegistrationLease::committed(
                    record,
                    selection,
                    self.actor,
                    revision,
                    self.lease.deadline,
                ))
            }
            _ => None,
        };
        Ok(DesiredPolicyCommit {
            revision,
            registration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BusPeerCredentials;
    use rustix::fs::{CWD, Mode, OFlags, openat};
    use rustix::process::{Pid, PidfdFlags, pidfd_open};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = PathBuf::from(format!(
                "/var/tmp/greyward-policy-review-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn selection(&self) -> DirectorySelection {
            let descriptor = openat(
                CWD,
                &self.0,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            DirectorySelection::capture(
                descriptor,
                rustix::process::getuid().as_raw(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn actor() -> ExecutionHandle {
        let pid = std::process::id();
        ExecutionHandle::capture(BusPeerCredentials {
            uid: rustix::process::getuid().as_raw(),
            pid,
            selinux_label: fs::read_to_string("/proc/self/attr/current")
                .unwrap()
                .trim_end_matches(['\0', '\n'])
                .into(),
            process_fd: pidfd_open(
                Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
                PidfdFlags::NONBLOCK,
            )
            .unwrap(),
        })
        .unwrap()
    }

    fn lease(revision: u64) -> PolicyReviewLease {
        PolicyReviewLease {
            operation_ref: SecurityReference::try_from(format!("operation_{}", "a".repeat(64)))
                .unwrap(),
            expected_revision: revision,
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    fn input(fixture: &Fixture) -> DirectoryResourceReview {
        DirectoryResourceReview {
            selection: fixture.selection(),
            category: ProtectedCategory::Custom,
            label: "Synthetic directory".into(),
        }
    }

    #[test]
    fn preparing_a_descriptor_review_does_not_write_or_claim_protection() {
        let fixture = Fixture::new();
        let actor = actor();
        let store = PolicyStore::isolated_memory().unwrap();
        let review =
            PolicyIntentReview::register_directory(&store, &actor, input(&fixture), lease(1))
                .unwrap();
        review.revalidate(&store, &actor).unwrap();
        let IntentChange::Register(record) = &review.change else {
            panic!("Wrong reviewed payload")
        };
        assert_eq!(record.resource.coverage, ResourceCoverage::Unknown);
        assert_eq!(record.object.owner_uid, actor.identity().owner_uid);
        let encoded = serde_json::to_string(record).unwrap();
        assert!(!encoded.contains(fixture.0.to_str().unwrap()));
        assert!(store.desired_policy().unwrap().resources.is_empty());
        assert_eq!(store.desired_policy().unwrap().revision, 1);
    }

    #[test]
    fn directory_or_execution_changes_invalidate_review_before_authorization() {
        let fixture = Fixture::new();
        let actor = actor();
        let store = PolicyStore::isolated_memory().unwrap();
        let review =
            PolicyIntentReview::register_directory(&store, &actor, input(&fixture), lease(1))
                .unwrap();
        fs::write(fixture.0.join("new-object"), b"synthetic").unwrap();
        assert!(matches!(
            review.revalidate(&store, &actor),
            Err(PolicyIntentError::Selection(
                ResourceSelectionError::Changed
            ))
        ));
        let mut review =
            PolicyIntentReview::register_directory(&store, &actor, input(&fixture), lease(1))
                .unwrap();
        review.actor.start_ticks += 1;
        assert!(matches!(
            review.revalidate(&store, &actor),
            Err(PolicyIntentError::Changed)
        ));
        assert_eq!(store.desired_policy().unwrap().revision, 1);
    }

    #[test]
    fn stale_expired_unbounded_or_wrong_namespace_leases_are_refused() {
        let fixture = Fixture::new();
        let actor = actor();
        let store = PolicyStore::isolated_memory().unwrap();
        assert!(matches!(
            PolicyIntentReview::register_directory(&store, &actor, input(&fixture), lease(2)),
            Err(PolicyIntentError::Store(StoreError::StaleRevision))
        ));
        for deadline in [
            Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            Instant::now() + Duration::from_secs(121),
        ] {
            let mut invalid = lease(1);
            invalid.deadline = deadline;
            assert!(
                PolicyIntentReview::register_directory(&store, &actor, input(&fixture), invalid)
                    .is_err()
            );
        }
        let mut invalid = lease(1);
        invalid.operation_ref =
            SecurityReference::try_from(format!("grant_{}", "a".repeat(64))).unwrap();
        assert!(
            PolicyIntentReview::register_directory(&store, &actor, input(&fixture), invalid)
                .is_err()
        );
        assert!(store.desired_policy().unwrap().resources.is_empty());
    }
}
