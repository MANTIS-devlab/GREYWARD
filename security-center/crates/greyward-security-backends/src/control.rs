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
