//! Application protection is an evidence projection, never a user-supplied flag.
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const APPLICATION_SECURITY_SCHEMA: &str = "greyward.application-security/v1";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApplicationSecurityError {
    #[error("Invalid opaque reference")]
    InvalidReference,
    #[error("Invalid content generation")]
    InvalidGeneration,
    #[error("Invalid canonical installed executable path")]
    InvalidInstalledPath,
    #[error("Protection profile contradicts enforcement evidence")]
    InvalidProtection,
    #[error("Invalid execution identity")]
    InvalidExecution,
    #[error("Invalid protected resource")]
    InvalidResource,
    #[error("Invalid access grant")]
    InvalidGrant,
    #[error("Invalid operation result")]
    InvalidOperation,
}

/// References do not authorize access. The broker must also validate ownership.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecurityReference(String);

impl SecurityReference {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn namespace(&self) -> &str {
        self.0
            .split_once('_')
            .map_or("", |(namespace, _)| namespace)
    }
}

impl TryFrom<String> for SecurityReference {
    type Error = ApplicationSecurityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let Some((namespace, digest)) = value.split_once('_') else {
            return Err(ApplicationSecurityError::InvalidReference);
        };
        if ![
            "application",
            "installation",
            "execution",
            "resource",
            "grant",
            "operation",
            "launch",
        ]
        .contains(&namespace)
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ApplicationSecurityError::InvalidReference);
        }
        Ok(Self(value))
    }
}

impl From<SecurityReference> for String {
    fn from(value: SecurityReference) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentGeneration(String);

/// Validated metadata query selector, never application/grant authority.
/// No serialization or frontend command accepts this as an installed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledExecutablePath(String);

impl InstalledExecutablePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for InstalledExecutablePath {
    type Error = ApplicationSecurityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.starts_with("/usr/")
            || value.len() > 4096
            || value[1..].split('/').count() > 32
            || value[1..].split('/').any(|part| {
                part.is_empty() || part == "." || part == ".." || part.chars().any(char::is_control)
            })
        {
            return Err(ApplicationSecurityError::InvalidInstalledPath);
        }
        Ok(Self(value.to_owned()))
    }
}

impl ContentGeneration {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ContentGeneration {
    type Error = ApplicationSecurityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ApplicationSecurityError::InvalidGeneration);
        }
        Ok(Self(value))
    }
}

impl From<ContentGeneration> for String {
    fn from(value: ContentGeneration) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationProvider {
    Rpm,
    Flatpak,
    AppImage,
    Manual,
    Script,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProvenanceState {
    Verified,
    Unverified,
    Unavailable,
    #[default]
    Unknown,
}

/// A verified receipt is provenance evidence, never evidence of harmlessness.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceSnapshot {
    pub state: ProvenanceState,
    pub source_receipt: Option<ContentGeneration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionProfile {
    Protected,
    Isolated,
    Trusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementHealth {
    Available,
    Unavailable,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent verified gates, not mutually exclusive states.
pub struct SessionCoverage {
    pub graphical_session: bool,
    pub user_manager: bool,
    pub direct_exec: bool,
    pub services_and_scheduled_jobs: bool,
    pub enrolled_remote_sessions: bool,
    pub protected_resource_labels: bool,
    /// True only with independent deputy/portal evidence. False means not verified.
    /// This optional capability is excluded from the registered-resource baseline.
    pub deputies_and_portals: bool,
}

impl SessionCoverage {
    pub fn complete(&self) -> bool {
        self.graphical_session
            && self.user_manager
            && self.direct_exec
            && self.services_and_scheduled_jobs
            && self.enrolled_remote_sessions
            && self.protected_resource_labels
        // Optional portal/deputy isolation is not established by baseline coverage.
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Every independently established restriction is required.
pub struct IsolationEvidence {
    pub private_home: bool,
    pub filesystem_scope: bool,
    pub namespaces: bool,
    pub landlock: bool,
    pub seccomp: bool,
    pub network_denied: bool,
    pub display_required: bool,
    pub private_display: bool,
}

impl IsolationEvidence {
    pub fn complete(&self) -> bool {
        self.private_home
            && self.filesystem_scope
            && self.namespaces
            && self.landlock
            && self.seccomp
            && self.network_denied
            && (!self.display_required || self.private_display)
    }
}

/// Constructed by collectors/broker, never accepted as an authorization input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnforcementEvidence {
    pub selinux_enforcing: Option<bool>,
    pub production_policy_loaded: Option<bool>,
    pub subject_confined: Option<bool>,
    pub coverage: SessionCoverage,
    pub isolation: IsolationEvidence,
    pub reviewed_exception: bool,
    pub policy_revision: u64,
    /// Age computed from a broker-held monotonic observation, never client time.
    pub evidence_age_ms: Option<u64>,
}

pub const APPLICATION_ENFORCEMENT_LEASE_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionSnapshot {
    pub requested_profile: ProtectionProfile,
    pub effective_profile: Option<ProtectionProfile>,
    pub health: EnforcementHealth,
    pub coverage: SessionCoverage,
    pub isolation: IsolationEvidence,
    pub reviewed_exception: bool,
    pub policy_revision: u64,
    pub evidence_age_ms: Option<u64>,
}

impl ProtectionSnapshot {
    pub fn from_evidence(requested: ProtectionProfile, evidence: &EnforcementEvidence) -> Self {
        let required = [
            evidence.selinux_enforcing,
            evidence.production_policy_loaded,
            evidence.subject_confined,
        ];
        let health = if required.contains(&Some(false)) {
            EnforcementHealth::Unavailable
        } else if required.contains(&None) || evidence.evidence_age_ms.is_none() {
            EnforcementHealth::Unknown
        } else if evidence
            .evidence_age_ms
            .is_some_and(|age| age > APPLICATION_ENFORCEMENT_LEASE_MS)
            || !evidence.coverage.complete()
            || evidence.policy_revision == 0
            || (requested == ProtectionProfile::Isolated && !evidence.isolation.complete())
            || (requested == ProtectionProfile::Trusted && !evidence.reviewed_exception)
        {
            EnforcementHealth::Degraded
        } else {
            EnforcementHealth::Available
        };
        Self {
            requested_profile: requested,
            effective_profile: (health == EnforcementHealth::Available).then_some(requested),
            health,
            coverage: evidence.coverage.clone(),
            isolation: evidence.isolation.clone(),
            reviewed_exception: evidence.reviewed_exception,
            policy_revision: evidence.policy_revision,
            evidence_age_ms: evidence.evidence_age_ms,
        }
    }

    /// Reject contradictory wire projections before presenting a protection badge.
    /// # Errors
    /// Rejects any claimed profile without complete available enforcement.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        let available = self.health == EnforcementHealth::Available;
        if available != self.effective_profile.is_some()
            || (available
                && (!self.coverage.complete()
                    || self
                        .evidence_age_ms
                        .is_none_or(|age| age > APPLICATION_ENFORCEMENT_LEASE_MS)
                    || self.policy_revision == 0
                    || self.effective_profile != Some(self.requested_profile)
                    || (self.requested_profile == ProtectionProfile::Isolated
                        && !self.isolation.complete())
                    || (self.requested_profile == ProtectionProfile::Trusted
                        && !self.reviewed_exception)))
        {
            return Err(ApplicationSecurityError::InvalidProtection);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationIdentity {
    /// Presentation metadata only; never an authorization or attribution key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub application_ref: SecurityReference,
    pub installation_ref: SecurityReference,
    pub generation: ContentGeneration,
    pub provider: ApplicationProvider,
    pub owner_uid: u32,
    pub provenance: ProvenanceSnapshot,
}

/// Shared read contracts. Records/provenance alone establish no enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationInventoryRecord {
    pub identity: ApplicationIdentity,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReadDetails {
    pub record: ApplicationInventoryRecord,
    pub protection: ProtectionSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationInventoryPage {
    pub schema: String,
    pub inventory_revision: u64,
    pub inventory_health: EnforcementHealth,
    pub applications: Vec<ApplicationReadDetails>,
    pub next_cursor: Option<SecurityReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationLookup {
    pub schema: String,
    pub application: Option<ApplicationReadDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationCoverage {
    pub schema: String,
    pub inventory_health: EnforcementHealth,
    pub protection: ProtectionSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationReadAvailability {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReadSource {
    pub state: ApplicationReadAvailability,
    pub reason: Option<String>,
}

/// A short presentation lease, not a policy/authorization token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReadEnvelope<T> {
    pub schema: String,
    pub source_state: ApplicationReadSource,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub fresh_until: chrono::DateTime<chrono::Utc>,
    pub projection: Option<T>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionCapability {
    Filesystem,
    Network,
    Camera,
    Microphone,
    ScreenCapture,
    Clipboard,
    ProtectedResource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionDecision {
    Allowed,
    Denied,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionLayer {
    Manifest,
    SystemGlobal,
    SystemApplication,
    UserGlobal,
    UserApplication,
    Portal,
    MandatoryPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub capability: PermissionCapability,
    pub resource_ref: Option<SecurityReference>,
    pub decision: PermissionDecision,
    pub provider: ApplicationProvider,
    pub sources: Vec<PermissionLayer>,
    pub health: EnforcementHealth,
    pub policy_revision: u64,
}

impl PermissionSnapshot {
    /// # Errors
    /// Rejects a definitive permission decision from partial/missing evidence.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        if self.sources.len() > 7
            || self
                .resource_ref
                .as_ref()
                .is_some_and(|reference| reference.namespace() != "resource")
            || (matches!(
                self.decision,
                PermissionDecision::Allowed | PermissionDecision::Denied
            ) && (self.health != EnforcementHealth::Available || self.sources.is_empty()))
        {
            return Err(ApplicationSecurityError::InvalidProtection);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum GrantLifetime {
    ThisRun { execution_ref: SecurityReference },
    Persistent,
}

/// Policy data is not authorization. The broker checks peer identity and fresh
/// authorization separately before committing or using any grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessGrant {
    pub grant_ref: SecurityReference,
    pub owner_uid: u32,
    pub installation_ref: SecurityReference,
    pub generation: ContentGeneration,
    pub resources: Vec<SecurityReference>,
    pub access: Vec<ResourceAccess>,
    pub lifetime: GrantLifetime,
    pub policy_revision: u64,
}

impl AccessGrant {
    /// # Errors
    /// Rejects broad/unversioned grants, duplicates and wrong object namespaces.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        let resources: std::collections::BTreeSet<_> = self.resources.iter().collect();
        if self.grant_ref.namespace() != "grant"
            || self.installation_ref.namespace() != "installation"
            || self.resources.is_empty()
            || self.resources.len() > 64
            || resources.len() != self.resources.len()
            || self
                .resources
                .iter()
                .any(|reference| reference.namespace() != "resource")
            || self.access.is_empty()
            || self.access.len() > 2
            || (self.access.len() == 2 && self.access[0] == self.access[1])
            || self.policy_revision == 0
            || matches!(&self.lifetime, GrantLifetime::ThisRun { execution_ref } if execution_ref.namespace() != "execution")
        {
            return Err(ApplicationSecurityError::InvalidGrant);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationOutcome {
    Pending,
    Running,
    CancelRequested,
    Verifying,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationFailure {
    AuthorizationRequired,
    StaleRevision,
    IdentityChanged,
    ProviderUnavailable,
    EnforcementUnavailable,
    ReadbackFailed,
    DeadlineExceeded,
    WorkerFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyRisk {
    RawCredentialAccess,
    InProcessExtensionsShareAccess,
    RestartRequiredForRevocation,
    BroaderOrdinaryFileAccess,
    BroaderNetworkAccess,
}

/// A bounded preview summary. Policy payload and authorization remain in the
/// broker; presentation sends back only the operation reference and revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChangePreview {
    pub operation_ref: SecurityReference,
    pub installation_ref: SecurityReference,
    pub generation: ContentGeneration,
    pub resource_refs: Vec<SecurityReference>,
    pub risks: Vec<PolicyRisk>,
    pub expected_revision: u64,
    pub expires_after_ms: u32,
}

/// Descriptor selection is a resource review, not an application identity.
/// The object handle and proposed policy stay in the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRegistrationPreview {
    pub operation_ref: SecurityReference,
    pub resource: ProtectedResource,
    pub expected_revision: u64,
    pub expires_after_ms: u32,
}

/// Presentation-only review. Descriptors and authorization stay in the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "preview",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum WorkflowPreview {
    Registration(ResourceRegistrationPreview),
    Grant {
        grant_ref: SecurityReference,
        tool_profile: String,
        review: PolicyChangePreview,
    },
    Revocation(PolicyChangePreview),
}
impl WorkflowPreview {
    pub fn operation_ref(&self) -> &SecurityReference {
        match self {
            Self::Registration(p) => &p.operation_ref,
            Self::Grant { review, .. } | Self::Revocation(review) => &review.operation_ref,
        }
    }
    /// # Errors
    /// Rejects unbounded reviews and raw grants without the required disclosures.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        match self {
            Self::Registration(p) => p.validate(),
            Self::Grant {
                grant_ref,
                tool_profile,
                review,
            } => {
                review.validate()?;
                if grant_ref.namespace() != "grant"
                    || tool_profile != "openssh-key-inspection/v1"
                    || review.resource_refs.is_empty()
                    || !review.risks.contains(&PolicyRisk::RawCredentialAccess)
                    || !review
                        .risks
                        .contains(&PolicyRisk::InProcessExtensionsShareAccess)
                {
                    return Err(ApplicationSecurityError::InvalidGrant);
                }
                Ok(())
            }
            Self::Revocation(p) => p.validate(),
        }
    }
}

impl ResourceRegistrationPreview {
    /// # Errors
    /// Refuses fabricated effective coverage and unbounded/unversioned leases.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        self.resource.validate()?;
        if self.operation_ref.namespace() != "operation"
            || self.expected_revision == 0
            || self.expected_revision.checked_add(1) != Some(self.resource.policy_revision)
            || self.resource.coverage != ResourceCoverage::Unknown
            || !(1..=120_000).contains(&self.expires_after_ms)
        {
            return Err(ApplicationSecurityError::InvalidOperation);
        }
        Ok(())
    }
}

impl PolicyChangePreview {
    /// # Errors
    /// Rejects unbounded, unversioned or wrongly scoped preview summaries.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        if self.operation_ref.namespace() != "operation"
            || self.installation_ref.namespace() != "installation"
            || self.resource_refs.len() > 64
            || self.risks.len() > 5
            || self
                .resource_refs
                .iter()
                .any(|reference| reference.namespace() != "resource")
            || self.expected_revision == 0
            || self.expires_after_ms == 0
            || self.expires_after_ms > 120_000
        {
            return Err(ApplicationSecurityError::InvalidOperation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationResult {
    pub operation_ref: SecurityReference,
    pub outcome: OperationOutcome,
    pub committed_revision: Option<u64>,
    pub verified_readback: bool,
    pub failure: Option<OperationFailure>,
}

impl OperationResult {
    /// # Errors
    /// Rejects completed claims without readback, or incomplete failure results.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        let completed = self.outcome == OperationOutcome::Completed;
        if self.operation_ref.namespace() != "operation"
            || (completed
                && (!self.verified_readback
                    || self.committed_revision.is_none_or(|revision| revision == 0)
                    || self.failure.is_some()))
            || (self.verified_readback && !completed)
            || (matches!(
                self.outcome,
                OperationOutcome::Failed | OperationOutcome::Expired
            ) && self.failure.is_none())
        {
            return Err(ApplicationSecurityError::InvalidOperation);
        }
        Ok(())
    }
}

impl ApplicationIdentity {
    /// # Errors
    /// Rejects references belonging to another object namespace.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        if self.application_ref.namespace() != "application"
            || self
                .display_name
                .as_ref()
                .is_some_and(|name| !display_name_valid(name))
            || self.installation_ref.namespace() != "installation"
            || (self.provenance.state == ProvenanceState::Verified
                && self.provenance.source_receipt.is_none())
        {
            return Err(ApplicationSecurityError::InvalidReference);
        }
        Ok(())
    }
}
fn display_name_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIdentity {
    pub execution_ref: SecurityReference,
    pub installation_ref: Option<SecurityReference>,
    pub owner_uid: u32,
    pub boot_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub selinux_context: String,
}

impl ExecutionIdentity {
    /// # Errors
    /// Rejects missing process generations, malformed boot IDs and context data.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        let boot_valid = self.boot_id.len() == 36
            && self.boot_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                }
            });
        if self.execution_ref.namespace() != "execution"
            || self
                .installation_ref
                .as_ref()
                .is_some_and(|reference| reference.namespace() != "installation")
            || self.pid == 0
            || self.start_ticks == 0
            || !boot_valid
            || self.selinux_context.len() > 1024
            || self.selinux_context.split(':').count() < 4
            || !self
                .selinux_context
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_:.,-".contains(&byte))
        {
            return Err(ApplicationSecurityError::InvalidExecution);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedCategory {
    Credentials,
    Cloud,
    Development,
    BrowserSession,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceCoverage {
    Protected,
    NotPresent,
    Unavailable,
    Unknown,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResource {
    pub resource_ref: SecurityReference,
    pub owner_uid: u32,
    pub category: ProtectedCategory,
    pub label: String,
    pub coverage: ResourceCoverage,
    pub policy_revision: u64,
}

/// Registered policy metadata. The live coverage field remains independent of
/// whether a root record or a label journal exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResourcePage {
    pub schema: String,
    pub policy_revision: u64,
    pub inventory_health: EnforcementHealth,
    pub resources: Vec<ProtectedResource>,
    pub next_cursor: Option<SecurityReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResourceLookup {
    pub schema: String,
    pub policy_revision: u64,
    pub resource: Option<ProtectedResource>,
}

impl ProtectedResource {
    /// # Errors
    /// Rejects invalid references, unbounded labels and unversioned protection.
    pub fn validate(&self) -> Result<(), ApplicationSecurityError> {
        if self.resource_ref.namespace() != "resource"
            || self.label.is_empty()
            || self.label.len() > 256
            || self.label.chars().any(char::is_control)
            || (self.coverage == ResourceCoverage::Protected && self.policy_revision == 0)
        {
            return Err(ApplicationSecurityError::InvalidResource);
        }
        Ok(())
    }
}
