#![allow(clippy::missing_errors_doc)]
use chrono::{DateTime, Duration, Utc};
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
pub struct ActivityItem {
    pub event_id: String,
    pub category: ActivityCategory,
    pub severity: ActivitySeverity,
    pub occurred_at: DateTime<Utc>,
    pub title: String,
    pub detail: String,
    pub related_check_id: Option<String>,
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

pub fn load_activity_from(path: &Path) -> Result<Vec<ActivityItem>, PrivacyError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path).map_err(|_| PrivacyError::Read)?;
    let items: Vec<ActivityItem> =
        serde_json::from_slice(&bytes).map_err(|_| PrivacyError::Read)?;
    Ok(retain_activity(items, Utc::now()))
}

pub fn record_activity(item: ActivityItem) -> Result<(), PrivacyError> {
    let dir = state_directory()?;
    fs::create_dir_all(&dir).map_err(|_| PrivacyError::Write)?;
    secure_directory(&dir)?;
    let path = dir.join("activity.json");
    let mut items = load_activity_from(&path).unwrap_or_default();
    items.push(ActivityItem {
        event_id: bounded_text(&item.event_id, 64),
        category: item.category,
        severity: item.severity,
        occurred_at: item.occurred_at,
        title: bounded_text(&item.title, 160),
        detail: bounded_text(&item.detail, 320),
        related_check_id: item.related_check_id.map(|v| bounded_text(&v, 96)),
    });
    atomic_write(
        &path,
        &serde_json::to_vec(&retain_activity(items, Utc::now()))
            .map_err(|_| PrivacyError::Serialize)?,
    )
}

pub fn load_activity() -> Result<Vec<ActivityItem>, PrivacyError> {
    state_directory().and_then(|dir| load_activity_from(&dir.join("activity.json")))
}

pub fn clear_activity() -> Result<(), PrivacyError> {
    let path = state_directory()?.join("activity.json");
    if path.exists() {
        fs::remove_file(path).map_err(|_| PrivacyError::Write)?;
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
    let count = load_activity().map_or(0, |v| v.len());
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
