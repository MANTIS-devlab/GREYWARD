#![allow(clippy::missing_errors_doc)]
use chrono::{DateTime, Duration, Utc};
use dbus::blocking::Connection;
use greyward_security_domain::PostureSnapshot;
use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const MAX_ACTIVITY_ITEMS: usize = 64;
pub const RETENTION_DAYS: i64 = 30;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActivityCategory {
    Posture,
    Action,
    Evidence,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActivitySeverity {
    Information,
    Review,
    Important,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityItem {
    pub event_id: String,
    pub category: ActivityCategory,
    pub severity: ActivitySeverity,
    pub occurred_at: DateTime<Utc>,
    pub title: String,
    pub detail: String,
    pub related_check_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityEnvelope {
    schema: String,
    state: String,
    items: Option<Vec<ActivityItem>>,
}

fn decode_activity(payload: &str) -> Result<Vec<ActivityItem>, PrivacyError> {
    if payload.len() > 256 * 1024 {
        return Err(PrivacyError::Read);
    }
    let value: ActivityEnvelope = serde_json::from_str(payload).map_err(|_| PrivacyError::Read)?;
    if value.schema != "greyward.local-activity/v1" || value.state != "AVAILABLE" {
        return Err(PrivacyError::Read);
    }
    let items = value.items.ok_or(PrivacyError::Read)?;
    if items.len() > MAX_ACTIVITY_ITEMS
        || items.iter().any(|item| {
            item.event_id.is_empty()
                || item.event_id.len() > 64
                || !item
                    .event_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                || item.title.chars().count() > 160
                || item.detail.chars().count() > 320
                || item
                    .title
                    .chars()
                    .chain(item.detail.chars())
                    .any(char::is_control)
                || item.occurred_at > Utc::now() + Duration::minutes(1)
                || item.related_check_id.as_ref().is_some_and(|reference| {
                    reference.is_empty()
                        || reference.len() > 96
                        || !reference
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                })
        })
    {
        return Err(PrivacyError::Read);
    }
    Ok(retain_activity(items, Utc::now()))
}

#[derive(Clone, Copy)]
enum LocalActivityCall<'a> {
    Read,
    Record(&'a str),
    Clear,
}

fn local_activity_call(request: LocalActivityCall<'_>) -> Result<Vec<ActivityItem>, PrivacyError> {
    let connection = Connection::new_session().map_err(|_| PrivacyError::Read)?;
    let proxy = connection.with_proxy(
        "systems.mantis.greyward.SecurityContext1",
        "/systems/mantis/greyward/SecurityContext1",
        std::time::Duration::from_secs(4),
    );
    let response: Result<(String,), _> = match request {
        LocalActivityCall::Read => proxy.method_call(
            "systems.mantis.greyward.SecurityContext1",
            "GetLocalActivity",
            (),
        ),
        LocalActivityCall::Record(payload) => proxy.method_call(
            "systems.mantis.greyward.SecurityContext1",
            "RecordLocalActivity",
            (payload,),
        ),
        LocalActivityCall::Clear => proxy.method_call(
            "systems.mantis.greyward.SecurityContext1",
            "ClearLocalActivity",
            (),
        ),
    };
    let (payload,) = response.map_err(|_| PrivacyError::Read)?;
    decode_activity(&payload)
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalServiceDisclosure {
    pub component: String,
    pub purpose: String,
    pub endpoints: Vec<String>,
    pub trigger: String,
    pub data_disclosed: String,
    pub retention: String,
    pub local_only: bool,
    pub disable_route: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SafeExportCheck {
    pub check_id: String,
    pub domain: String,
    pub state: String,
    pub reason_code: String,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SafeExport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub policy_profile: String,
    pub checks: Vec<SafeExportCheck>,
    pub external_services: Vec<ExternalServiceDisclosure>,
    pub activity_count: usize,
    pub retention_days: i64,
}
#[derive(Debug, thiserror::Error)]
pub enum PrivacyError {
    #[error("state directory unavailable")]
    StateDirectory,
    #[error("state read failed")]
    Read,
    #[error("state write failed")]
    Write,
    #[error("export serialization failed")]
    Serialize,
}

pub fn external_service_manifest() -> Vec<ExternalServiceDisclosure> {
    vec![
        ExternalServiceDisclosure {
            component: "DMS greywardPublicIp plugin".into(),
            purpose: "Public and local network-identity display".into(),
            endpoints: vec!["https://ipapi.co/json/".into(), "https://ipwho.is/".into()],
            trigger: "Enabled startup, network changes, and approximately 20-minute refresh; no provider request while the persistent pill switch is off".into(),
            data_disclosed: "Public source IP, request time, TLS metadata, and curl user-agent; public IP and country code response. The displayed local IP is resolved locally and is not sent by the plugin".into(),
            retention: "Current public identity in memory only; persistent on/off preference; no IP history or cache".into(),
            local_only: false,
            disable_route: "GREYWARD Network Identity pill: turn off Public IP check".into(),
        },
        ExternalServiceDisclosure {
            component: "GREYWARD Security Center".into(),
            purpose: "Local posture collection, explanation, bounded activity, and export".into(),
            endpoints: Vec::new(),
            trigger: "Explicit local launch/refresh/action only".into(),
            data_disclosed: "None; no account, telemetry, upload, or public-IP request".into(),
            retention: "One bounded snapshot and up to 64 normalized activity items for 30 days".into(),
            local_only: true,
            disable_route: "Not applicable; local-only by design".into(),
        },
    ]
}

pub fn state_directory() -> Result<PathBuf, PrivacyError> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .ok_or(PrivacyError::StateDirectory)?;
    Ok(base.join("greyward/security-center"))
}

fn bounded_text(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

pub fn retain_activity(mut items: Vec<ActivityItem>, now: DateTime<Utc>) -> Vec<ActivityItem> {
    let cutoff = now - Duration::days(RETENTION_DAYS);
    items.retain(|item| item.occurred_at >= cutoff);
    for item in &mut items {
        item.event_id = bounded_text(&item.event_id, 64);
        item.title = bounded_text(&item.title, 160);
        item.detail = bounded_text(&item.detail, 320);
        item.related_check_id = item.related_check_id.take().map(|v| bounded_text(&v, 96));
    }
    items.sort_by_key(|item| item.occurred_at);
    if items.len() > MAX_ACTIVITY_ITEMS {
        items.split_off(items.len() - MAX_ACTIVITY_ITEMS)
    } else {
        items
    }
}

pub fn record_activity(item: ActivityItem) -> Result<(), PrivacyError> {
    let value = ActivityItem {
        event_id: bounded_text(&item.event_id, 64),
        category: item.category,
        severity: item.severity,
        occurred_at: item.occurred_at,
        title: bounded_text(&item.title, 160),
        detail: bounded_text(&item.detail, 320),
        related_check_id: item.related_check_id.map(|v| bounded_text(&v, 96)),
    };
    let payload = serde_json::to_string(&value).map_err(|_| PrivacyError::Serialize)?;
    if payload.len() > 4096 || !local_activity_call(LocalActivityCall::Record(&payload))?.is_empty()
    {
        return Err(PrivacyError::Write);
    }
    Ok(())
}

pub fn load_activity() -> Result<Vec<ActivityItem>, PrivacyError> {
    local_activity_call(LocalActivityCall::Read)
}

pub fn clear_activity() -> Result<(), PrivacyError> {
    if !local_activity_call(LocalActivityCall::Clear)?.is_empty() {
        return Err(PrivacyError::Write);
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), PrivacyError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|_| PrivacyError::Write)?;
    secure_file(&tmp)?;
    fs::rename(tmp, path).map_err(|_| PrivacyError::Write)?;
    secure_file(path)
}
fn secure_directory(path: &Path) -> Result<(), PrivacyError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| PrivacyError::Write)?;
    Ok(())
}
fn secure_file(path: &Path) -> Result<(), PrivacyError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| PrivacyError::Write)?;
    Ok(())
}
pub fn build_safe_export(snapshot: &PostureSnapshot, activity_count: usize) -> SafeExport {
    SafeExport {
        schema: "greyward.security.export/v1".into(),
        generated_at: snapshot.generated_at,
        policy_profile: snapshot.policy_profile.clone(),
        checks: snapshot
            .checks
            .iter()
            .map(|c| SafeExportCheck {
                check_id: c.check_id.as_str().into(),
                domain: format!("{:?}", c.domain),
                state: format!("{:?}", c.state),
                reason_code: c.reason_code.clone(),
                observed_at: c.observed_at,
            })
            .collect(),
        external_services: external_service_manifest(),
        activity_count: activity_count.min(MAX_ACTIVITY_ITEMS),
        retention_days: RETENTION_DAYS,
    }
}

pub fn write_safe_export(snapshot: &PostureSnapshot) -> Result<PathBuf, PrivacyError> {
    let path = state_directory()?.join("exports/posture-latest.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| PrivacyError::Write)?;
        secure_directory(parent)?;
    }
    let count = load_activity()?.len();
    let bytes = serde_json::to_vec_pretty(&build_safe_export(snapshot, count))
        .map_err(|_| PrivacyError::Serialize)?;
    atomic_write(&path, &bytes)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_is_bounded_and_redacts_control_text() {
        let now = Utc::now();
        let mut items = vec![ActivityItem {
            event_id: "old".into(),
            category: ActivityCategory::Posture,
            severity: ActivitySeverity::Information,
            occurred_at: now - Duration::days(31),
            title: "old".into(),
            detail: "old".into(),
            related_check_id: None,
        }];
        for i in 0..(MAX_ACTIVITY_ITEMS + 5) {
            items.push(ActivityItem {
                event_id: i.to_string(),
                category: ActivityCategory::Action,
                severity: ActivitySeverity::Review,
                occurred_at: now,
                title: "ok\n".into(),
                detail: "safe\t".into(),
                related_check_id: None,
            });
        }
        let kept = retain_activity(items, now);
        assert_eq!(kept.len(), MAX_ACTIVITY_ITEMS);
        assert!(!kept[0].title.contains('\n'));
    }
    #[test]
    fn local_history_failure_and_forged_metadata_are_not_safe_emptiness() {
        let valid = serde_json::json!({"schema":"greyward.local-activity/v1","state":"AVAILABLE","items":[{
            "event_id":"action-1","category":"Action","severity":"Information","occurred_at":Utc::now(),
            "title":"Local action","detail":"Presentation only","related_check_id":null
        }]});
        assert_eq!(decode_activity(&valid.to_string()).unwrap().len(), 1);
        for value in [
            serde_json::json!({"schema":"greyward.local-activity/v1","state":"UNAVAILABLE","items":null}),
            serde_json::json!({"schema":"greyward.local-activity/v1","state":"AVAILABLE","items":null}),
            serde_json::json!({"schema":"other","state":"AVAILABLE","items":[]}),
        ] {
            assert!(decode_activity(&value.to_string()).is_err());
        }
        let mut forged = valid.clone();
        forged["items"][0]["decision"] = "BLOCKED".into();
        assert!(decode_activity(&forged.to_string()).is_err());
        forged = valid.clone();
        forged["items"][0]["category"] = "APPLICATION_SECURITY".into();
        assert!(decode_activity(&forged.to_string()).is_err());
        forged = valid.clone();
        forged["items"][0]["related_check_id"] = "/home/alice/private".into();
        assert!(decode_activity(&forged.to_string()).is_err());
        forged = valid.clone();
        forged["items"] = serde_json::Value::Array(vec![valid["items"][0].clone(); 65]);
        assert!(decode_activity(&forged.to_string()).is_err());
    }
    #[test]
    fn manifest_is_local_and_endpoint_allowlisted() {
        let manifest = external_service_manifest();
        assert_eq!(manifest.len(), 2);
        assert!(manifest[1].local_only);
        assert!(
            manifest[0]
                .endpoints
                .iter()
                .all(|e| e.starts_with("https://"))
        );
        assert!(manifest[0].trigger.contains("no provider request"));
        assert!(manifest[0].trigger.contains("persistent pill switch"));
        assert!(manifest[0].retention.contains("memory only"));
        assert!(manifest[0].retention.contains("no IP history or cache"));
    }
}
