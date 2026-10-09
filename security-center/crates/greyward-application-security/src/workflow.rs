//! Typed policy/launch workflow for the enrolled development account. Every
//! completion follows authoritative readback; a persisted intention is not
//! protection. The explicit installed workflow service uses this same provider;
//! the default read-only service does not activate it.
use crate::{
    BrokerError, DevelopmentKernelProvider, DirectoryResourceReview, DirectorySelection,
    ExecutionHandle, IdentitySeed, InstalledContentError, InstalledExecutable, IsolatedLaunchError,
    ManagedCodeStore, ManagedContentError, ManagedGrantError, OperationError, OperationTable,
    PolicyExecutionError, PolicyIntentError, PolicyIntentReview, PolicyReviewLease, PolicyStore,
    PreparedIsolatedLaunch, PreparedReviewedLaunch, ReadRequest, RegistryError,
    ResourceSelectionError, ReviewedLaunchError, RpmIdentityError, RunningIsolatedLaunch,
    RunningReviewedLaunch, StoreError, SystemAuthorizer, collect_installed_rpm_content,
    project_read,
};
use dbus::strings::BusName;
use greyward_security_domain::{
    AccessGrant, ApplicationIdentity, ApplicationProvider, ContentGeneration, ExecutionIdentity,
    GrantLifetime, InstalledExecutablePath, OperationFailure, OperationOutcome, OperationResult,
    PolicyChangePreview, PolicyRisk, ProtectedCategory, ResourceAccess, SecurityReference,
};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

const REVIEW_TIME: Duration = Duration::from_secs(100);
const MAX_PENDING: usize = 32;
const TEST_TOOL: &str = "/usr/local/libexec/greyward-application-security-reviewed-tool";

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("Workflow is unavailable to this execution or provider")]
    Unavailable,
    #[error("Workflow capacity reached")]
    Capacity,
    #[error("Development request deadline expired")]
    Deadline,
    #[error(transparent)]
    Intent(#[from] PolicyIntentError),
    #[error(transparent)]
    Operation(#[from] OperationError),
    #[error(transparent)]
    Enforcement(#[from] PolicyExecutionError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Selection(#[from] ResourceSelectionError),
    #[error(transparent)]
    Content(#[from] InstalledContentError),
    #[error(transparent)]
    ManagedContent(#[from] ManagedContentError),
    #[error(transparent)]
    Rpm(#[from] RpmIdentityError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Isolation(#[from] IsolatedLaunchError),
    #[error(transparent)]
    Grant(#[from] ManagedGrantError),
    #[error(transparent)]
    Launch(#[from] ReviewedLaunchError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

enum Change {
    Registration,
    Grant {
        reference: SecurityReference,
        code: InstalledExecutable,
    },
    Revocation {
        grant: Box<crate::managed_grant::RecordedReadAccess>,
    },
}
struct PendingReview {
    actor: ExecutionIdentity,
    review: PolicyIntentReview,
    generation: Option<ContentGeneration>,
    change: Change,
    deadline: Instant,
}
struct PendingLaunch {
    actor: ExecutionIdentity,
    prepared: PreparedWorkload,
    deadline: Instant,
}
enum PreparedWorkload {
    Reviewed(Box<PreparedReviewedLaunch>),
    Isolated(Box<PreparedIsolatedLaunch>),
}
pub enum RunningWorkload {
    Reviewed(Box<RunningReviewedLaunch>),
    Isolated(Box<RunningIsolatedLaunch>),
}
impl RunningWorkload {
    /// # Errors
    /// Only standard streams from an established, owned prepared workload.
    pub fn streams(
        &mut self,
    ) -> Result<(std::fs::File, std::fs::File, std::fs::File), ReviewedLaunchError> {
        match self {
            Self::Reviewed(r) => r.streams(),
            Self::Isolated(r) => r.streams(),
        }
    }
    /// # Errors
    /// Waiting is bounded independently by PID 1 and is not protection evidence.
    pub fn wait(&mut self) -> Result<std::process::ExitStatus, ReviewedLaunchError> {
        match self {
            Self::Reviewed(r) => r.wait(),
            Self::Isolated(r) => r.wait(),
        }
    }
}

pub use greyward_security_domain::WorkflowPreview;

/// Root owns all nonserializable reviews, descriptors and launch handles.
/// A separate bounded worker owns this object; operation reads use the shared
/// table while authentication/compiler work proceeds, without cancelling it.
pub struct DevelopmentWorkflow {
    access_events: crate::access_events::AccessEvents,
    store: PolicyStore,
    binding: crate::enrollment::ProviderBinding,
    provider: Option<DevelopmentKernelProvider>,
    authority: SystemAuthorizer,
    operations: Arc<Mutex<OperationTable>>,
    pending: BTreeMap<SecurityReference, PendingReview>,
    launches: BTreeMap<SecurityReference, PendingLaunch>,
}

fn reference(namespace: &str) -> Result<SecurityReference, WorkflowError> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    SecurityReference::try_from(format!("{namespace}_{}", crate::framed_digest(&[&bytes])))
        .map_err(|_| WorkflowError::Unavailable)
}

impl DevelopmentWorkflow {
    fn actor_check(&self, actor: &ExecutionHandle) -> Result<(), WorkflowError> {
        if self.binding.isolation_only {
            return Err(WorkflowError::Unavailable);
        }
        if crate::enrollment::ProviderBinding::for_actor(&self.store, actor)? != self.binding {
            return Err(WorkflowError::Unavailable);
        }
        Ok(())
    }
    pub(crate) fn open_production(
        uid: u32,
        operations: Arc<Mutex<OperationTable>>,
    ) -> Result<Self, WorkflowError> {
        let store = PolicyStore::open_system()?;
        let binding = crate::enrollment::ProviderBinding::production(&store, uid)?;
        Self::open_bound(store, binding, operations)
    }
    pub(crate) fn open_isolation(
        uid: u32,
        operations: Arc<Mutex<OperationTable>>,
    ) -> Result<Self, WorkflowError> {
        Self::open_bound(
            PolicyStore::open_system()?,
            crate::enrollment::ProviderBinding::isolation(uid)?,
            operations,
        )
    }
    /// # Errors
    /// Bounded, peer-scoped root audit evidence; missing audit is unavailable.
    pub fn security_events(
        &mut self,
        actor: &ExecutionHandle,
        cursor: u64,
        limit: u32,
    ) -> Result<String, WorkflowError> {
        self.actor_check(actor)?;
        if !(1..=100).contains(&limit) {
            return Err(WorkflowError::Unavailable);
        }
        let state = self.store.desired_policy()?;
        let policy = crate::ResourceDenialProgram::prepare_bound(
            &self.binding,
            state.revision,
            state.revision,
            &state
                .resources
                .into_iter()
                .filter(|r| r.resource().owner_uid == self.binding.uid)
                .collect::<Vec<_>>(),
        )
        .map_err(|_| WorkflowError::Unavailable)?;
        serde_json::to_string(&self.access_events.read(cursor, limit as usize, &policy))
            .map_err(|_| WorkflowError::Unavailable)
    }
    /// # Errors
    /// Durable reviewed intentions only: this list does not assert live access.
    pub fn grants(&self, actor: &ExecutionHandle) -> Result<String, WorkflowError> {
        if !self.binding.permits_isolation_actor(actor) {
            return Err(WorkflowError::Unavailable);
        }
        let state = self.store.desired_policy()?;
        let grants: Vec<_> = state
            .grants
            .iter()
            .filter(|record| record.proposal().owner_uid == actor.identity().owner_uid)
            .map(crate::GrantIntent::proposal)
            .collect();
        serde_json::to_string(&serde_json::json!({
            "schema": greyward_security_domain::APPLICATION_SECURITY_SCHEMA,
            "policy_revision": state.revision, "enforcement_health": "UNKNOWN",
            "grants": grants,
            "capabilities": {
                "isolation": crate::isolated_launch::available(&self.binding, actor),
                "policy_changes": !self.binding.isolation_only && self.actor_check(actor).is_ok()
            }
        }))
        .map_err(|_| WorkflowError::Unavailable)
    }
    /// # Errors
    /// Same typed owner/revision/deadline contracts as the installed read broker.
    pub fn read(
        &self,
        actor: &ExecutionHandle,
        request: ReadRequest,
        deadline: Instant,
    ) -> Result<String, BrokerError> {
        project_read(&self.store, actor, request, deadline)
    }
    /// # Errors
    /// Fixed separate-account storage/provider only; no production fallback.
    pub fn open(operations: Arc<Mutex<OperationTable>>) -> Result<Self, WorkflowError> {
        Self::open_bound(
            PolicyStore::open_development_registration_probe()?,
            crate::enrollment::ProviderBinding::development(),
            operations,
        )
    }
    fn open_bound(
        store: PolicyStore,
        binding: crate::enrollment::ProviderBinding,
        operations: Arc<Mutex<OperationTable>>,
    ) -> Result<Self, WorkflowError> {
        Ok(Self {
            access_events: crate::access_events::AccessEvents::open(),
            provider: if binding.isolation_only {
                None
            } else {
                Some(DevelopmentKernelProvider::open_bound(binding.clone())?)
            },
            store,
            binding,
            authority: SystemAuthorizer::connect().map_err(|_| WorkflowError::Unavailable)?,
            operations,
            pending: BTreeMap::new(),
            launches: BTreeMap::new(),
        })
    }

    fn table(&self) -> Result<std::sync::MutexGuard<'_, OperationTable>, WorkflowError> {
        self.operations
            .lock()
            .map_err(|_| WorkflowError::Unavailable)
    }
    fn lease(&self, revision: u64) -> Result<PolicyReviewLease, WorkflowError> {
        if self.pending.len() >= MAX_PENDING {
            return Err(WorkflowError::Capacity);
        }
        if self.store.desired_policy()?.revision != revision {
            return Err(StoreError::StaleRevision.into());
        }
        Ok(PolicyReviewLease {
            operation_ref: reference("operation")?,
            expected_revision: revision,
            deadline: Instant::now() + REVIEW_TIME,
        })
    }

    /// # Errors
    /// Only an actual `O_PATH` directory FD owned by the authenticated actor is
    /// retained. Registration never accepts a pathname to reopen after review.
    pub fn preview_registration(
        &mut self,
        actor: &ExecutionHandle,
        descriptor: OwnedFd,
        category: ProtectedCategory,
        label: String,
        revision: u64,
    ) -> Result<WorkflowPreview, WorkflowError> {
        self.actor_check(actor)?;
        self.expire();
        let lease = self.lease(revision)?;
        let deadline = lease.deadline;
        let selection =
            DirectorySelection::capture(descriptor, actor.identity().owner_uid, deadline)?;
        let review = PolicyIntentReview::register_directory(
            &self.store,
            actor,
            DirectoryResourceReview {
                selection,
                category,
                label,
            },
            lease,
        )?;
        let summary = review.registration_preview()?;
        self.table()?.prepare_registration(
            actor.identity().clone(),
            summary.clone(),
            Instant::now(),
        )?;
        self.pending.insert(
            summary.operation_ref.clone(),
            PendingReview {
                actor: actor.identity().clone(),
                review,
                generation: None,
                change: Change::Registration,
                deadline,
            },
        );
        Ok(WorkflowPreview::Registration(summary))
    }

    fn installed(
        &self,
        path: &str,
        actor: &ExecutionHandle,
        deadline: Instant,
    ) -> Result<(InstalledExecutable, ApplicationIdentity), WorkflowError> {
        let code = InstalledExecutable::capture(path, deadline)?;
        let identity = if path == TEST_TOOL && !self.binding.production {
            IdentitySeed {
                provider: ApplicationProvider::Manual,
                logical_id: "critical-reviewed-tool".into(),
                installation_id: "root-owned-development".into(),
                source_id: "explicit-review".into(),
                owner_uid: self.binding.uid,
            }
            .identity(code.generation().clone())
            .map_err(|_| WorkflowError::Unavailable)?
        } else {
            let path =
                InstalledExecutablePath::try_from(path).map_err(|_| WorkflowError::Unavailable)?;
            collect_installed_rpm_content(&path, deadline)?
                .observed_identity(actor.identity().owner_uid)?
        };
        code.revalidate()?;
        Ok((code, identity))
    }

    /// # Errors
    /// Read-only persistent grants bind the root-validated RPM installation and
    /// held code. No source approval, write grant, shell or user-selected context.
    pub fn preview_read_grant(
        &mut self,
        actor: &ExecutionHandle,
        path: &str,
        resources: Vec<SecurityReference>,
        revision: u64,
    ) -> Result<WorkflowPreview, WorkflowError> {
        self.actor_check(actor)?;
        self.expire();
        let lease = self.lease(revision)?;
        let deadline = lease.deadline;
        let (code, identity) = self.installed(path, actor, deadline)?;
        let tool_profile = Some(
            crate::ReviewedToolProfile::select(path, code.generation())
                .ok_or(WorkflowError::Unavailable)?,
        );
        if self.store.desired_policy()?.grants.len() >= 16 {
            return Err(WorkflowError::Unavailable);
        }
        self.store.reconcile_provider(
            self.binding.uid,
            identity.provider,
            vec![identity.clone()],
            false,
            self.store.inventory_revision()?,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| WorkflowError::Unavailable)?
                .as_secs(),
        )?;
        let grant = AccessGrant {
            grant_ref: reference("grant")?,
            owner_uid: self.binding.uid,
            installation_ref: identity.installation_ref.clone(),
            generation: identity.generation.clone(),
            resources: resources.clone(),
            access: vec![ResourceAccess::Read],
            lifetime: GrantLifetime::Persistent,
            policy_revision: revision.checked_add(1).ok_or(WorkflowError::Unavailable)?,
        };
        let grant_ref = grant.grant_ref.clone();
        let summary = PolicyChangePreview {
            operation_ref: lease.operation_ref.clone(),
            installation_ref: identity.installation_ref,
            generation: identity.generation.clone(),
            resource_refs: resources,
            risks: vec![
                PolicyRisk::RawCredentialAccess,
                PolicyRisk::InProcessExtensionsShareAccess,
                PolicyRisk::RestartRequiredForRevocation,
            ],
            expected_revision: revision,
            expires_after_ms: 100_000,
        };
        let review = PolicyIntentReview::propose_profiled_grant(
            &self.store,
            actor,
            grant,
            lease,
            tool_profile,
        )?;
        self.table()?
            .prepare(actor.identity().clone(), summary.clone(), Instant::now())?;
        self.pending.insert(
            summary.operation_ref.clone(),
            PendingReview {
                actor: actor.identity().clone(),
                review,
                generation: Some(identity.generation),
                change: Change::Grant {
                    reference: grant_ref.clone(),
                    code,
                },
                deadline,
            },
        );
        Ok(WorkflowPreview::Grant {
            grant_ref,
            tool_profile: "openssh-key-inspection/v1".into(),
            review: summary,
        })
    }

    /// # Errors
    /// Revoke an owned root-recorded grant even after its executable is updated
    /// or removed. The compatibility path parameter never authorizes code.
    pub fn preview_revoke(
        &mut self,
        actor: &ExecutionHandle,
        grant_ref: &SecurityReference,
        _path: &str,
        revision: u64,
    ) -> Result<WorkflowPreview, WorkflowError> {
        self.actor_check(actor)?;
        self.expire();
        let lease = self.lease(revision)?;
        let deadline = lease.deadline;
        let grant = crate::managed_grant::RecordedReadAccess::prepare(
            &self.store,
            actor,
            grant_ref,
            deadline,
        )?;
        let state = self.store.desired_policy()?;
        let record = state
            .grants
            .iter()
            .find(|r| &r.proposal().grant_ref == grant_ref)
            .ok_or(WorkflowError::Unavailable)?;
        let summary = PolicyChangePreview {
            operation_ref: lease.operation_ref.clone(),
            installation_ref: record.proposal().installation_ref.clone(),
            generation: record.proposal().generation.clone(),
            resource_refs: record.proposal().resources.clone(),
            risks: vec![PolicyRisk::RestartRequiredForRevocation],
            expected_revision: revision,
            expires_after_ms: 100_000,
        };
        let review =
            PolicyIntentReview::revoke_grant(&self.store, actor, grant_ref.clone(), lease)?;
        self.table()?
            .prepare(actor.identity().clone(), summary.clone(), Instant::now())?;
        self.pending.insert(
            summary.operation_ref.clone(),
            PendingReview {
                actor: actor.identity().clone(),
                review,
                generation: Some(summary.generation.clone()),
                change: Change::Revocation {
                    grant: Box::new(grant),
                },
                deadline,
            },
        );
        Ok(WorkflowPreview::Revocation(summary))
    }

    /// # Errors
    /// Single-transfer review, exact live peer, fresh owner authorization and
    /// kernel/object readback. Provider failure retains the actual committed
    /// revision, while the operation reports failure and coverage stays UNKNOWN.
    pub fn apply(
        &mut self,
        actor: &ExecutionHandle,
        sender: &BusName<'_>,
        operation: &SecurityReference,
        interactive: bool,
    ) -> Result<OperationResult, WorkflowError> {
        self.actor_check(actor)?;
        if self
            .pending
            .get(operation)
            .is_none_or(|p| p.actor != *actor.identity())
        {
            return Err(WorkflowError::Unavailable);
        }
        let pending = self
            .pending
            .remove(operation)
            .ok_or(WorkflowError::Unavailable)?;
        let revision = self.store.desired_policy()?.revision;
        if let Some(generation) = &pending.generation {
            self.table()?.begin(
                operation,
                actor.identity(),
                revision,
                generation,
                Instant::now(),
            )?;
        } else {
            self.table()?.begin_registration(
                operation,
                actor.identity(),
                revision,
                Instant::now(),
            )?;
        }
        let outcome = (|| -> Result<(), WorkflowError> {
            if let Change::Grant { code, .. } = &pending.change {
                code.revalidate()?;
            }
            let mut commit = pending.review.commit(
                &mut self.store,
                actor,
                sender,
                &self.authority,
                interactive,
            )?;
            let revision = commit.revision;
            self.table()?
                .committed(operation, revision, Instant::now())?;
            match pending.change {
                Change::Registration => {
                    let registration = commit
                        .take_registration()
                        .ok_or(WorkflowError::Unavailable)?;
                    self.provider
                        .as_ref()
                        .ok_or(WorkflowError::Unavailable)?
                        .register(registration, &mut self.store, actor, pending.deadline)?;
                }
                Change::Grant { reference, code } => {
                    self.provider
                        .as_ref()
                        .ok_or(WorkflowError::Unavailable)?
                        .activate_read_grant(
                            &self.store,
                            actor,
                            &reference,
                            &code,
                            pending.deadline,
                        )?;
                }
                Change::Revocation { grant } => {
                    self.provider
                        .as_ref()
                        .ok_or(WorkflowError::Unavailable)?
                        .revoke_recorded_read_grant(
                            commit,
                            &self.store,
                            actor,
                            &grant,
                            pending.deadline,
                        )?;
                }
            }
            self.table()?
                .verified(operation, revision, true, Instant::now())?;
            Ok(())
        })();
        if let Err(error) = outcome {
            let failure = match error {
                WorkflowError::Intent(PolicyIntentError::Authorization(_)) => {
                    OperationFailure::AuthorizationRequired
                }
                WorkflowError::Store(StoreError::StaleRevision) => OperationFailure::StaleRevision,
                _ => OperationFailure::ReadbackFailed,
            };
            let _ = self.table()?.failed(operation, actor.identity(), failure);
        }
        Ok(self.table()?.get(operation, actor.identity())?)
    }

    /// # Errors
    /// Prepared immutable code is bound to the caller, grant and revision, not
    /// an application name or caller-supplied root command. No fallback launch.
    pub fn prepare_launch(
        &mut self,
        actor: &ExecutionHandle,
        grant: &SecurityReference,
        path: &str,
        arguments: Vec<String>,
    ) -> Result<SecurityReference, WorkflowError> {
        self.actor_check(actor)?;
        self.expire();
        if self.launches.len() >= MAX_PENDING {
            return Err(WorkflowError::Capacity);
        }
        let deadline = Instant::now() + Duration::from_secs(110);
        let (code, identity) = self.installed(path, actor, deadline)?;
        let cache = ManagedCodeStore::open_bound(&self.binding)?;
        let prepared = if identity.provider == ApplicationProvider::Rpm {
            PreparedReviewedLaunch::prepare_rpm(
                &self.store,
                actor,
                grant,
                code,
                &cache,
                arguments,
                deadline,
            )?
        } else {
            PreparedReviewedLaunch::prepare(
                &self.store,
                actor,
                grant,
                code,
                &cache,
                arguments,
                deadline,
            )?
        };
        let reference = reference("launch")?;
        self.launches.insert(
            reference.clone(),
            PendingLaunch {
                actor: actor.identity().clone(),
                prepared: PreparedWorkload::Reviewed(Box::new(prepared)),
                deadline,
            },
        );
        Ok(reference)
    }

    /// # Errors
    /// Only a held ordinary-code descriptor, the enrolled caller and required
    /// isolation primitives can prepare an untrusted ELF. No grant is created.
    pub fn prepare_isolated(
        &mut self,
        actor: &ExecutionHandle,
        descriptor: OwnedFd,
        arguments: Vec<String>,
    ) -> Result<SecurityReference, WorkflowError> {
        self.prepare_payload(actor, descriptor, arguments, false, None)
    }
    /// # Errors
    /// Private display construction must succeed before execution is offered.
    pub fn prepare_graphical(
        &mut self,
        actor: &ExecutionHandle,
        descriptor: OwnedFd,
        arguments: Vec<String>,
    ) -> Result<SecurityReference, WorkflowError> {
        self.prepare_payload(actor, descriptor, arguments, true, None)
    }
    /// # Errors
    /// Ordinary descriptor-bound documents only, never generic protected exports.
    pub fn prepare_document(
        &mut self,
        actor: &ExecutionHandle,
        descriptor: OwnedFd,
        handler: &str,
        arguments: Vec<String>,
        graphical: bool,
    ) -> Result<SecurityReference, WorkflowError> {
        self.prepare_payload(actor, descriptor, arguments, graphical, Some(handler))
    }
    fn prepare_payload(
        &mut self,
        actor: &ExecutionHandle,
        descriptor: OwnedFd,
        arguments: Vec<String>,
        graphical: bool,
        document_handler: Option<&str>,
    ) -> Result<SecurityReference, WorkflowError> {
        if !self.binding.permits_isolation_actor(actor) {
            return Err(WorkflowError::Unavailable);
        }
        self.expire();
        if self.launches.len() >= MAX_PENDING {
            return Err(WorkflowError::Capacity);
        }
        let deadline = Instant::now() + Duration::from_secs(110);
        let display_name = if let Some(handler) = document_handler {
            std::path::PathBuf::from(handler)
        } else {
            std::fs::read_link(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&descriptor)
            ))
            .unwrap_or_default()
        }
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control))
        .map(str::to_owned);
        let prepared = if let Some(handler) = document_handler {
            PreparedIsolatedLaunch::prepare_document_bound(
                &self.binding,
                actor,
                descriptor,
                handler,
                arguments,
                deadline,
            )?
        } else {
            PreparedIsolatedLaunch::prepare_bound(
                self.binding.clone(),
                actor,
                descriptor,
                arguments,
                deadline,
            )?
        };
        let prepared = if graphical {
            prepared.with_graphical()?
        } else {
            prepared
        };
        let provider = match prepared.kind() {
            crate::PayloadKind::Script(_) => ApplicationProvider::Script,
            crate::PayloadKind::AppImage { .. } => ApplicationProvider::AppImage,
            _ => ApplicationProvider::Manual,
        };
        let mut identity = IdentitySeed {
            provider,
            owner_uid: actor.identity().owner_uid,
            logical_id: prepared.generation().as_str().into(),
            installation_id: "managed-content".into(),
            source_id: "selected-unverified-content".into(),
        }
        .identity(prepared.identity_generation()?)?;
        identity.display_name = display_name;
        self.store.reconcile_provider(
            actor.identity().owner_uid,
            provider,
            vec![identity],
            false,
            self.store.inventory_revision()?,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| WorkflowError::Unavailable)?
                .as_secs(),
        )?;
        let reference = reference("launch")?;
        self.launches.insert(
            reference.clone(),
            PendingLaunch {
                actor: actor.identity().clone(),
                prepared: PreparedWorkload::Isolated(Box::new(prepared)),
                deadline,
            },
        );
        Ok(reference)
    }

    /// # Errors
    /// Only the exact authenticated execution can consume its prepared handle.
    pub fn start_launch(
        &mut self,
        actor: &ExecutionHandle,
        reference: &SecurityReference,
    ) -> Result<RunningWorkload, WorkflowError> {
        if !self.binding.permits_isolation_actor(actor) {
            return Err(WorkflowError::Unavailable);
        }
        if self
            .launches
            .get(reference)
            .is_none_or(|p| p.actor != *actor.identity())
        {
            return Err(WorkflowError::Unavailable);
        }
        let pending = self
            .launches
            .remove(reference)
            .ok_or(WorkflowError::Unavailable)?;
        Ok(match pending.prepared {
            PreparedWorkload::Reviewed(prepared) => {
                RunningWorkload::Reviewed(Box::new(prepared.spawn(&self.store, actor)?))
            }
            PreparedWorkload::Isolated(prepared) => {
                RunningWorkload::Isolated(Box::new(prepared.spawn(actor)?))
            }
        })
    }

    /// Drops expired/cancelled selections and prepared FDs. Running work is not
    /// called cancelled by a UI timeout; the worker owns its real deadline.
    pub fn expire(&mut self) {
        let now = Instant::now();
        if let Ok(mut table) = self.operations.lock() {
            table.expire(now);
        }
        self.pending.retain(|reference, p| {
            p.deadline > now
                && self
                    .operations
                    .lock()
                    .ok()
                    .and_then(|t| t.get(reference, &p.actor).ok())
                    .is_some_and(|r| r.outcome == OperationOutcome::Pending)
        });
        self.launches.retain(|_, p| p.deadline > now);
    }
}
