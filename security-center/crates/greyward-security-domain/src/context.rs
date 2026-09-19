use crate::PostureState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub const SECURITY_CONTEXT_V1_SCHEMA: &str = "greyward.security.context/v1";
pub const MAX_CONTEXT_EVENTS: usize = 64;
pub const CONTEXT_RETENTION_DAYS: i64 = 30;
macro_rules! context_enum { ($name:ident { $($variant:ident),+ $(,)? }) => { #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)] #[serde(rename_all = "SCREAMING_SNAKE_CASE")] pub enum $name { $($variant),+ } }; }
context_enum!(SecurityEventKind {
    UsbDeviceBlocked,
    UsbDeviceAllowed,
    UsbScanResult,
    MicrophoneStarted,
    MicrophoneStopped,
    CameraStarted,
    CameraStopped,
    AppConnectionBlocked,
    InboundAttackActivity,
    PublicIpExposed,
    PublicIpProtected,
    SecurityUpdateAvailable,
    PostureChanged,
    PrivacyProfileChanged,
    PersistenceChangeDetected,
    SafeOpenResult
});
context_enum!(NotificationClass {
    Immediate,
    ActionRequired,
    OngoingState,
    HistoryOnly,
    Aggregatable
});
context_enum!(SecurityLiveStateKind {
    Protected,
    PublicIpExposed,
    MicrophoneActive,
    CameraActive,
    ReviewNeeded,
    Travel,
    Posture
});
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityContextEvent {
    pub event_id: String,
    pub kind: SecurityEventKind,
    pub notification: NotificationClass,
    pub occurred_at: DateTime<Utc>,
    pub title: String,
    pub detail: String,
    pub source: String,
    #[serde(default)]
    pub file_ref: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub detection_name: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub scan_context: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityLiveState {
    pub kind: SecurityLiveStateKind,
    pub state: PostureState,
    pub detail: String,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClamAvStatus {
    pub engine_version: Option<String>,
    pub database_timestamp: Option<DateTime<Utc>>,
    pub database_age_seconds: Option<u64>,
    pub last_successful_update: Option<DateTime<Utc>>,
    pub update_failure_state: Option<String>,
    pub database_version: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityContextSummary {
    pub schema: String,
    pub state: PostureState,
    pub generated_at: DateTime<Utc>,
    pub fresh_until: DateTime<Utc>,
    #[serde(alias = "attention_count")]
    pub review_count: u32,
    #[serde(default)]
    pub accepted_deviations: Vec<String>,
    pub live_states: Vec<SecurityLiveState>,
    pub recent_events: Vec<SecurityContextEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clamav: Option<ClamAvStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
}
