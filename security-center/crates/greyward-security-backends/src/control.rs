#![allow(clippy::missing_errors_doc)]
use crate::adapters::bounded_output;
use crate::facts::TrustZone;
#[derive(Debug, thiserror::Error)]
pub enum TrustZoneError {
    #[error("unsupported trust zone")]
    UnsupportedZone,
    #[error("active interface changed")]
    StateChanged,
    #[error("authorization or firewall command failed")]
    CommandFailed,
    #[error("verification failed")]
    VerificationFailed,
}
pub fn change_active_trust_zone(
    interface: &str,
    expected: TrustZone,
    target: TrustZone,
) -> Result<TrustZone, TrustZoneError> {
    if !interface
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(TrustZoneError::CommandFailed);
    }
    if matches!(target, TrustZone::Unknown) || matches!(expected, TrustZone::Unknown) {
        return Err(TrustZoneError::UnsupportedZone);
    }
    let current = crate::adapters::collect_network_facts();
    if current.interface.as_deref() != Some(interface) || current.trust_zone != expected {
        return Err(TrustZoneError::StateChanged);
    }
    let zone = target
        .firewall_name()
        .ok_or(TrustZoneError::UnsupportedZone)?;
    // Keep the native operation as a fixed-argument call. firewalld/Polkit
    // remains the authority boundary; no shell or user-controlled sudo rule
    // is introduced here.
    let output = bounded_output(
        "firewall-cmd",
        &[
            &format!("--zone={zone}"),
            &format!("--change-interface={interface}"),
        ],
    )
    .map_err(|_| TrustZoneError::CommandFailed)?;
    if !output.status.success() {
        return Err(TrustZoneError::CommandFailed);
    }
    let verified = crate::adapters::collect_network_facts();
    if verified.interface.as_deref() != Some(interface) || verified.trust_zone != target {
        return Err(TrustZoneError::VerificationFailed);
    }
    Ok(verified.trust_zone)
}
pub fn rollback_active_trust_zone(
    interface: &str,
    expected: TrustZone,
    target: TrustZone,
) -> Result<TrustZone, TrustZoneError> {
    change_active_trust_zone(interface, expected, target)
}
impl TrustZone {
    pub(crate) fn firewall_name(self) -> Option<&'static str> {
        Some(match self {
            Self::Public => "public",
            Self::Trusted => "trusted",
            Self::Home => "home",
            Self::Work => "work",
            Self::Drop => "drop",
            Self::Block => "block",
            Self::External => "external",
            Self::Dmz => "dmz",
            Self::Unknown => return None,
        })
    }
}
#[derive(Debug, thiserror::Error)]
pub enum FlatpakPermissionError {
    #[error("invalid application id")]
    InvalidAppId,
    #[error("permission state changed")]
    StateChanged,
    #[error("flatpak unavailable or command failed")]
    CommandFailed,
    #[error("permission verification failed")]
    VerificationFailed,
}
pub fn change_home_filesystem_permission(
    app_id: &str,
    expected: bool,
    target: bool,
) -> Result<bool, FlatpakPermissionError> {
    if !valid_app_id(app_id) {
        return Err(FlatpakPermissionError::InvalidAppId);
    }
    let current = read_home_override(app_id).ok_or(FlatpakPermissionError::CommandFailed)?;
    if current != expected {
        return Err(FlatpakPermissionError::StateChanged);
    }
    let flag = if target {
        "--filesystem=home"
    } else {
        "--nofilesystem=home"
    };
    let output = bounded_output("flatpak", &["override", "--user", flag, app_id])
        .map_err(|_| FlatpakPermissionError::CommandFailed)?;
    if !output.status.success() {
        return Err(FlatpakPermissionError::CommandFailed);
    }
    let verified = read_home_override(app_id).ok_or(FlatpakPermissionError::VerificationFailed)?;
    if verified != target {
        return Err(FlatpakPermissionError::VerificationFailed);
    }
    Ok(verified)
}
pub fn restore_home_filesystem_permission(
    app_id: &str,
    expected: bool,
    captured: bool,
) -> Result<bool, FlatpakPermissionError> {
    change_home_filesystem_permission(app_id, expected, captured)
}
fn valid_app_id(app_id: &str) -> bool {
    !app_id.is_empty()
        && app_id.len() <= 128
        && app_id.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
fn read_home_override(app_id: &str) -> Option<bool> {
    let output = bounded_output("flatpak", &["override", "--user", "--show", app_id]).ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Some(text.lines().any(|line| {
        line.trim_start().starts_with("filesystems=")
            && line
                .split_once('=')
                .is_some_and(|(_, v)| v.split(';').any(|x| x.trim() == "home"))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permission_control_rejects_unbounded_ids() {
        assert!(!valid_app_id("bad id"));
        assert!(valid_app_id("org.example.Safe"));
    }
}
