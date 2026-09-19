use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

pub const SNAPSHOT_V1_SCHEMA: &str = "greyward.security.snapshot/v1";
pub const CURRENT_EVALUATOR_VERSION: &str = "1";

macro_rules! closed_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum $name { $($variant),+ }
    };
}

closed_enum!(Domain {
    System,
    Applications,
    Network,
    Data,
    Devices,
    Privacy
});
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PostureState {
    Secure,
    #[serde(alias = "ATTENTION")]
    ReviewNeeded,
    Protected,
    ActionRequired,
    Unknown,
    Unavailable,
    NotApplicable,
}
impl<'de> Deserialize<'de> for PostureState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "SECURE" => Ok(Self::Secure),
            "REVIEW_NEEDED" | "ATTENTION" => Ok(Self::ReviewNeeded),
            "PROTECTED" => Ok(Self::Protected),
            "ACTION_REQUIRED" => Ok(Self::ActionRequired),
            "UNKNOWN" => Ok(Self::Unknown),
            "UNAVAILABLE" => Ok(Self::Unavailable),
            "NOT_APPLICABLE" => Ok(Self::NotApplicable),
            _ => Err(serde::de::Error::custom("unknown posture state")),
        }
    }
}
closed_enum!(Requiredness {
    Required,
    Recommended,
    Informational
});
closed_enum!(CapabilityMaturity {
    Verified,
    Candidate,
    PrototypeRequired,
    HardwareValidationRequired,
    Deferred,
    NotGenerallyEnforceable,
});
closed_enum!(RuntimeAvailability {
    Available,
    Absent,
    Unsupported,
    Denied,
    Failed,
    VersionMismatch,
});
closed_enum!(EvidenceKind {
    Boolean,
    Integer,
    Text,
    Object
});
closed_enum!(Sensitivity {
    Public,
    Device,
    User,
    Secret
});
closed_enum!(DisplayPolicy {
    Full,
    Redacted,
    SummaryOnly,
    NeverExport
});
closed_enum!(CollectionIssueCategory {
    Absent,
    Denied,
    Timeout,
    Malformed,
    Stale,
    Version,
    Internal,
});
closed_enum!(RemediationMode {
    Recommendation,
    Handoff,
    UserApi,
    UpstreamPolkit,
    GreywardHelper,
});
closed_enum!(Reversibility {
    Reversible,
    PartiallyReversible,
    Irreversible
});
closed_enum!(Confirmation {
    None,
    Standard,
    HighRisk
});

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CheckId(String);

impl CheckId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CheckId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CheckId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        // Snapshot v1's only approved migration alias. New aliases must be explicit.
        let canonical = match value.as_str() {
            "system.selinux" => "system.selinux.mode".to_owned(),
            _ => value,
        };
        Ok(Self(canonical))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedMessage {
    pub key: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, ScalarValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScalarValue {
    Boolean(bool),
    Integer(i64),
    Text(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceValue {
    Boolean(bool),
    Integer(i64),
    Text(String),
    Object(BTreeMap<String, ScalarValue>),
}

impl EvidenceValue {
    pub const fn kind(&self) -> EvidenceKind {
        match self {
            Self::Boolean(_) => EvidenceKind::Boolean,
            Self::Integer(_) => EvidenceKind::Integer,
            Self::Text(_) => EvidenceKind::Text,
            Self::Object(_) => EvidenceKind::Object,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSource {
    pub backend_id: String,
    pub interface: String,
    pub object: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub backend_version: String,
    pub interface_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub evidence_id: String,
    pub source: EvidenceSource,
    pub kind: EvidenceKind,
    pub value: EvidenceValue,
    pub sensitivity: Sensitivity,
    pub display_policy: DisplayPolicy,
    pub observed_at: DateTime<Utc>,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityStatus {
    pub maturity: CapabilityMaturity,
    pub runtime: RuntimeAvailability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    pub applies: bool,
    pub reason_code: String,
    #[serde(default)]
    pub facts: BTreeMap<String, ScalarValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedEffect {
    pub predicate_id: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, ScalarValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationDescriptor {
    pub action_id: String,
    pub mode: RemediationMode,
    pub title: LocalizedMessage,
    pub consequence: LocalizedMessage,
    pub reversibility: Reversibility,
    pub confirmation: Confirmation,
    pub availability: RuntimeAvailability,
    pub expected_effect: ExpectedEffect,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub check_id: CheckId,
    pub definition_version: u32,
    pub domain: Domain,
    pub state: PostureState,
    pub reason_code: String,
    pub summary: LocalizedMessage,
    pub explanation: LocalizedMessage,
    pub observed_at: DateTime<Utc>,
    pub fresh_until: DateTime<Utc>,
    pub applicability: Applicability,
    pub requiredness: Requiredness,
    pub capability_status: CapabilityStatus,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    pub remediation: Option<RemediationDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainResult {
    pub domain: Domain,
    pub state: PostureState,
    #[serde(default)]
    pub check_ids: Vec<CheckId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionIssue {
    pub backend_id: String,
    pub category: CollectionIssueCategory,
    pub safe_message: LocalizedMessage,
    pub observed_at: DateTime<Utc>,
    pub retryable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostureSnapshot {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub boot_id: Option<String>,
    pub evaluator_version: String,
    pub policy_profile: String,
    #[serde(default)]
    pub domains: Vec<DomainResult>,
    #[serde(default)]
    pub checks: Vec<CheckResult>,
    #[serde(default)]
    pub collection_issues: Vec<CollectionIssue>,
    /// Bounded check IDs the user explicitly accepted as deviations.
    #[serde(default)]
    pub accepted_deviations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicabilityRule {
    Always {
        reason_code: String,
    },
    Never {
        reason_code: String,
    },
    FactPresent {
        key: String,
        reason_code: String,
    },
    FactEquals {
        key: String,
        value: ScalarValue,
        reason_code: String,
    },
}
