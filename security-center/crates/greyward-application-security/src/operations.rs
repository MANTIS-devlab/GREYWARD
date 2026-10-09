//! Bounded operation lifecycle. It does not authorize changes or run workers.
//! Running cancellation/expiry requires worker termination acknowledgement.
use greyward_security_domain::{
    ApplicationSecurityError, ExecutionIdentity, OperationFailure, OperationOutcome,
    OperationResult, PolicyChangePreview, SecurityReference,
};
use std::collections::BTreeMap;
use std::time::Instant;
use thiserror::Error;

pub const MAX_OPERATIONS: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OperationError {
    #[error("Operation queue is full")]
    Capacity,
    #[error("Operation is unavailable to this execution")]
    NotOwned,
    #[error("Invalid operation state transition")]
    InvalidTransition,
    #[error("Preview revision or identity changed")]
    StalePreview,
    #[error("Operation deadline expired")]
    Deadline,
    #[error(transparent)]
    Contract(#[from] ApplicationSecurityError),
}

struct TrackedOperation {
    owner: ExecutionIdentity,
    revision: u64,
    generation: Option<greyward_security_domain::ContentGeneration>,
    deadline: Instant,
    result: OperationResult,
    expiry_requested: bool,
}

#[derive(Default)]
pub struct OperationTable {
    entries: BTreeMap<SecurityReference, TrackedOperation>,
}

impl OperationTable {
    /// Call only after peer identity and policy preparation are validated.
    /// # Errors
    /// Rejects malformed, duplicate or excess operation records.
    pub fn prepare(
        &mut self,
        owner: ExecutionIdentity,
        preview: PolicyChangePreview,
        now: Instant,
    ) -> Result<(), OperationError> {
        owner.validate()?;
        preview.validate()?;
        self.prepare_binding(
            owner,
            preview.operation_ref,
            preview.expected_revision,
            Some(preview.generation),
            preview.expires_after_ms,
            now,
        )
    }

    /// # Errors
    /// Resource registration cannot borrow an application generation or claim
    /// enforcement. Its reviewed descriptor remains owned by the workflow.
    pub fn prepare_registration(
        &mut self,
        owner: ExecutionIdentity,
        preview: greyward_security_domain::ResourceRegistrationPreview,
        now: Instant,
    ) -> Result<(), OperationError> {
        owner.validate()?;
        preview.validate()?;
        if preview.resource.owner_uid != owner.owner_uid {
            return Err(OperationError::NotOwned);
        }
        self.prepare_binding(
            owner,
            preview.operation_ref,
            preview.expected_revision,
            None,
            preview.expires_after_ms,
            now,
        )
    }

    fn prepare_binding(
        &mut self,
        owner: ExecutionIdentity,
        reference: SecurityReference,
        revision: u64,
        generation: Option<greyward_security_domain::ContentGeneration>,
        expires: u32,
        now: Instant,
    ) -> Result<(), OperationError> {
        if self.entries.contains_key(&reference) {
            return Err(OperationError::InvalidTransition);
        }
        if self.entries.len() >= MAX_OPERATIONS {
            return Err(OperationError::Capacity);
        }
        let deadline = now
            .checked_add(std::time::Duration::from_millis(u64::from(expires)))
            .ok_or(OperationError::Deadline)?;
        let result = OperationResult {
            operation_ref: reference.clone(),
            outcome: OperationOutcome::Pending,
            committed_revision: None,
            verified_readback: false,
            failure: None,
        };
        self.entries.insert(
            reference,
            TrackedOperation {
                owner,
                revision,
                generation,
                deadline,
                result,
                expiry_requested: false,
            },
        );
        Ok(())
    }

    fn owned(
        &mut self,
        reference: &SecurityReference,
        owner: &ExecutionIdentity,
    ) -> Result<&mut TrackedOperation, OperationError> {
        let entry = self
            .entries
            .get_mut(reference)
            .ok_or(OperationError::NotOwned)?;
        // UID alone is insufficient: boot/PID/start/context bind the preview to
        // the authenticated execution. PID reuse cannot acquire its operation.
        if &entry.owner != owner {
            return Err(OperationError::NotOwned);
        }
        Ok(entry)
    }

    /// Authorization is checked by the broker before this state transition.
    /// # Errors
    /// Rejects stale, expired, replayed or foreign previews.
    pub fn begin(
        &mut self,
        reference: &SecurityReference,
        owner: &ExecutionIdentity,
        current_revision: u64,
        generation: &greyward_security_domain::ContentGeneration,
        now: Instant,
    ) -> Result<(), OperationError> {
        let entry = self.owned(reference, owner)?;
        if now >= entry.deadline {
            return Err(OperationError::Deadline);
        }
        if current_revision != entry.revision || entry.generation.as_ref() != Some(generation) {
            return Err(OperationError::StalePreview);
        }
        if entry.result.outcome != OperationOutcome::Pending {
            return Err(OperationError::InvalidTransition);
        }
        entry.result.outcome = OperationOutcome::Running;
        Ok(())
    }

    /// # Errors
    /// Descriptor reviews use their own binding and cannot execute a grant.
    pub fn begin_registration(
        &mut self,
        reference: &SecurityReference,
        owner: &ExecutionIdentity,
        current_revision: u64,
        now: Instant,
    ) -> Result<(), OperationError> {
        let entry = self.owned(reference, owner)?;
        if now >= entry.deadline {
            return Err(OperationError::Deadline);
        }
        if entry.revision != current_revision || entry.generation.is_some() {
            return Err(OperationError::StalePreview);
        }
        if entry.result.outcome != OperationOutcome::Pending {
            return Err(OperationError::InvalidTransition);
        }
        entry.result.outcome = OperationOutcome::Running;
        Ok(())
    }

    /// Worker failure preserves any acknowledged commit and never becomes
    /// success or cancellation. Called only by the owning root workflow.
    /// # Errors
    /// Refuses rewriting a terminal result or a foreign operation.
    pub fn failed(
        &mut self,
        reference: &SecurityReference,
        owner: &ExecutionIdentity,
        reason: OperationFailure,
    ) -> Result<(), OperationError> {
        let entry = self.owned(reference, owner)?;
        if !matches!(
            entry.result.outcome,
            OperationOutcome::Running | OperationOutcome::Verifying
        ) {
            return Err(OperationError::InvalidTransition);
        }
        entry.result.outcome = OperationOutcome::Failed;
        entry.result.failure = Some(reason);
        Ok(())
    }

    /// # Errors
    /// Unknown/foreign operations cannot be observed or cancelled.
    pub fn get(
        &self,
        reference: &SecurityReference,
        owner: &ExecutionIdentity,
    ) -> Result<OperationResult, OperationError> {
        let entry = self
            .entries
            .get(reference)
            .filter(|entry| &entry.owner == owner)
            .ok_or(OperationError::NotOwned)?;
        Ok(entry.result.clone())
    }

    /// # Errors
    /// Rejects cancellation of a committing, terminal or foreign operation.
    pub fn cancel(
        &mut self,
        reference: &SecurityReference,
        owner: &ExecutionIdentity,
    ) -> Result<(), OperationError> {
        let entry = self.owned(reference, owner)?;
        entry.result.outcome = match entry.result.outcome {
            OperationOutcome::Pending => OperationOutcome::Cancelled,
            OperationOutcome::Running => OperationOutcome::CancelRequested,
            _ => return Err(OperationError::InvalidTransition),
        };
        Ok(())
    }

    /// Broker-owned timer: running work remains cancellation requested until
    /// the worker has actually stopped. A UI timeout does not call this method.
    pub fn expire(&mut self, now: Instant) -> Vec<SecurityReference> {
        let mut terminate = Vec::new();
        for (reference, entry) in &mut self.entries {
            if now < entry.deadline {
                continue;
            }
            match entry.result.outcome {
                OperationOutcome::Pending => {
                    entry.result.outcome = OperationOutcome::Expired;
                    entry.result.failure = Some(OperationFailure::DeadlineExceeded);
                }
                OperationOutcome::Running | OperationOutcome::CancelRequested => {
                    entry.expiry_requested = true;
                    entry.result.outcome = OperationOutcome::CancelRequested;
                    terminate.push(reference.clone());
                }
                OperationOutcome::Verifying => {
                    // A committed change cannot truthfully become cancelled.
                    // Its effective state remains uncertain until fresh readback.
                    entry.result.outcome = OperationOutcome::Failed;
                    entry.result.failure = Some(OperationFailure::ReadbackFailed);
                    terminate.push(reference.clone());
                }
                _ => (),
            }
        }
        terminate
    }

    /// Worker acknowledgement, never a UI operation.
    /// # Errors
    /// Rejects a false stopped acknowledgement outside cancellation state.
    pub fn stopped(&mut self, reference: &SecurityReference) -> Result<(), OperationError> {
        let entry = self
            .entries
            .get_mut(reference)
            .ok_or(OperationError::InvalidTransition)?;
        if entry.result.outcome != OperationOutcome::CancelRequested {
            return Err(OperationError::InvalidTransition);
        }
        entry.result.outcome = if entry.expiry_requested {
            OperationOutcome::Expired
        } else {
            OperationOutcome::Cancelled
        };
        entry.result.failure = entry
            .expiry_requested
            .then_some(OperationFailure::DeadlineExceeded);
        Ok(())
    }

    /// Commit acknowledgement is not success; authoritative verification must
    /// follow. Expired/cancelled workers are forbidden from committing here.
    /// # Errors
    /// Rejects late or inconsistent worker commits.
    pub fn committed(
        &mut self,
        reference: &SecurityReference,
        revision: u64,
        now: Instant,
    ) -> Result<(), OperationError> {
        let entry = self
            .entries
            .get_mut(reference)
            .ok_or(OperationError::InvalidTransition)?;
        if entry.result.outcome != OperationOutcome::Running || revision <= entry.revision {
            return Err(OperationError::InvalidTransition);
        }
        entry.result.committed_revision = Some(revision);
        if now >= entry.deadline {
            // Preserve a real commit even when it completed late. Never call
            // that policy change cancelled or claim a verified successful apply.
            entry.result.outcome = OperationOutcome::Failed;
            entry.result.failure = Some(OperationFailure::DeadlineExceeded);
            return Err(OperationError::Deadline);
        }
        entry.result.outcome = OperationOutcome::Verifying;
        Ok(())
    }

    /// Readback outcome comes from the broker's authoritative provider, not UI.
    /// # Errors
    /// Rejects late/mismatched verification and transitions without a commit.
    pub fn verified(
        &mut self,
        reference: &SecurityReference,
        readback_revision: u64,
        matched: bool,
        now: Instant,
    ) -> Result<(), OperationError> {
        let entry = self
            .entries
            .get_mut(reference)
            .ok_or(OperationError::InvalidTransition)?;
        if entry.result.outcome != OperationOutcome::Verifying {
            return Err(OperationError::InvalidTransition);
        }
        let verified = now < entry.deadline
            && matched
            && entry.result.committed_revision == Some(readback_revision);
        entry.result.outcome = if verified {
            OperationOutcome::Completed
        } else {
            OperationOutcome::Failed
        };
        entry.result.verified_readback = verified;
        entry.result.failure = (!verified).then_some(OperationFailure::ReadbackFailed);
        Ok(())
    }

    /// Retention is bounded; only terminal records may be removed.
    /// # Errors
    /// Live/committing work cannot be discarded to make room in the queue.
    pub fn forget(&mut self, reference: &SecurityReference) -> Result<(), OperationError> {
        let entry = self
            .entries
            .get(reference)
            .ok_or(OperationError::InvalidTransition)?;
        if !matches!(
            entry.result.outcome,
            OperationOutcome::Completed
                | OperationOutcome::Failed
                | OperationOutcome::Cancelled
                | OperationOutcome::Expired
        ) {
            return Err(OperationError::InvalidTransition);
        }
        self.entries.remove(reference);
        Ok(())
    }
}
