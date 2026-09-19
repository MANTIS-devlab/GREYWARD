//! Transactional privacy profiles over `NetworkManager` and firewalld.
//!
//! The profile is inferred from observed native state. No requested profile is
//! treated as successful until both `NetworkManager` and firewalld report it.

use crate::adapters::{bounded_output, collect_network_facts};
use crate::facts::TrustZone;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PrivacyProfile {
    Standard,
    Private,
    Travel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum MacPolicy {
    Stable,
    RandomOnReconnect,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrivacyState {
    pub profile: Option<PrivacyProfile>,
    pub interface: Option<String>,
    pub connection: Option<String>,
    pub mac_policy: MacPolicy,
    pub actual_mac: Option<String>,
    pub firewall_zone: TrustZone,
    pub vpn_active: Option<bool>,
    pub public_ip_expectation: String,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ProfileError {
    #[error("no active NetworkManager connection")]
    NoActiveConnection,
    #[error("native interface unavailable")]
    NativeUnavailable,
    #[error("native command failed")]
    CommandFailed,
    #[error("profile state changed before mutation")]
    StateChanged,
    #[error("profile verification failed")]
    VerificationFailed,
    #[error("profile rollback failed")]
    RollbackFailed,
    #[error("unsupported connection type")]
    UnsupportedConnection,
}

impl PrivacyProfile {
    /// Parses a user-facing privacy profile name.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnsupportedConnection`] for an unrecognized
    /// profile name.
    pub fn parse(value: &str) -> Result<Self, ProfileError> {
        match value.to_ascii_lowercase().as_str() {
            "standard" => Ok(Self::Standard),
            "private" => Ok(Self::Private),
            "travel" => Ok(Self::Travel),
            _ => Err(ProfileError::UnsupportedConnection),
        }
    }
    pub fn mac_policy(self) -> MacPolicy {
        if self == Self::Travel {
            MacPolicy::RandomOnReconnect
        } else {
            MacPolicy::Stable
        }
    }
    pub fn firewall_zone(self) -> TrustZone {
        if self == Self::Standard {
            TrustZone::Public
        } else {
            TrustZone::Drop
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Private => "Private",
            Self::Travel => "Travel",
        }
    }
}

pub trait NativeProfileOps {
    /// Reads the currently observed native privacy state.
    ///
    /// # Errors
    ///
    /// Returns a profile error when the native state cannot be read or the
    /// active connection has changed.
    fn read_state(&mut self) -> Result<PrivacyState, ProfileError>;

    /// Changes the native MAC-address policy.
    ///
    /// # Errors
    ///
    /// Returns a profile error when the requested policy is unsupported or the
    /// native operation fails.
    fn set_mac_policy(&mut self, policy: MacPolicy) -> Result<(), ProfileError>;

    /// Changes the native firewall zone.
    ///
    /// # Errors
    ///
    /// Returns a profile error when the requested zone is unsupported or the
    /// native operation fails.
    fn set_firewall_zone(&mut self, zone: TrustZone) -> Result<(), ProfileError>;
}

/// Applies and verifies a privacy profile, rolling back partial changes.
///
/// # Errors
///
/// Returns a profile error when the current state is unavailable, a native
/// operation fails, verification fails, or rollback cannot restore the prior
/// state.
pub fn apply_profile<O: NativeProfileOps>(
    ops: &mut O,
    target: PrivacyProfile,
) -> Result<PrivacyState, ProfileError> {
    let before = ops.read_state()?;
    if before.interface.is_none() || before.connection.is_none() {
        return Err(ProfileError::NoActiveConnection);
    }
    let target_mac = target.mac_policy();
    let target_zone = target.firewall_zone();
    let mut mac_changed = false;
    let mut zone_changed = false;
    let result = (|| {
        if before.mac_policy != target_mac {
            // Treat a failed native call as potentially partial.  The
            // NetworkManager API is a separate mutation boundary, so the
            // outer transaction must still attempt its compensating action.
            mac_changed = true;
            ops.set_mac_policy(target_mac)?;
        }
        if before.firewall_zone != target_zone {
            // Treat a failed native call as potentially partial. The
            // firewalld and NetworkManager operations are separate mutation
            // boundaries, so the outer transaction must still compensate.
            zone_changed = true;
            ops.set_firewall_zone(target_zone)?;
        }
        let verified = ops.read_state()?;
        if verified.mac_policy != target_mac || verified.firewall_zone != target_zone {
            return Err(ProfileError::VerificationFailed);
        }
        Ok(verified)
    })();
    match result {
        Ok(state) => Ok(state),
        Err(error) => {
            let mut rollback_ok = true;
            if zone_changed {
                rollback_ok &= ops.set_firewall_zone(before.firewall_zone).is_ok();
            }
            if mac_changed {
                rollback_ok &= ops.set_mac_policy(before.mac_policy).is_ok();
            }
            if !rollback_ok {
                return Err(ProfileError::RollbackFailed);
            }
            let recovered = ops.read_state().map_err(|_| ProfileError::RollbackFailed)?;
            if recovered.mac_policy != before.mac_policy
                || recovered.firewall_zone != before.firewall_zone
            {
                return Err(ProfileError::RollbackFailed);
            }
            Err(error)
        }
    }
}

pub struct SystemProfileOps {
    interface: String,
    connection: String,
    connection_type: String,
}

impl SystemProfileOps {
    /// Creates native profile operations from the active connection.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::NoActiveConnection`] when no active interface or
    /// connection is available, or [`ProfileError::UnsupportedConnection`] when
    /// the connection type is unavailable.
    pub fn from_active() -> Result<Self, ProfileError> {
        let facts = collect_network_facts();
        Ok(Self {
            interface: facts.interface.ok_or(ProfileError::NoActiveConnection)?,
            connection: facts
                .active_connection
                .ok_or(ProfileError::NoActiveConnection)?,
            connection_type: facts
                .connection_type
                .ok_or(ProfileError::UnsupportedConnection)?,
        })
    }
    fn mac_field(&self) -> &'static str {
        if self
            .connection_type
            .to_ascii_lowercase()
            .contains("wireless")
        {
            "802-11-wireless.cloned-mac-address"
        } else {
            "802-3-ethernet.cloned-mac-address"
        }
    }
    fn nm(args: &[&str]) -> Result<String, ProfileError> {
        let output = bounded_output("nmcli", args).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProfileError::NativeUnavailable
            } else {
                ProfileError::CommandFailed
            }
        })?;
        if !output.status.success() {
            return Err(ProfileError::CommandFailed);
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
    fn read_mac_policy(&self) -> MacPolicy {
        match Self::nm(&[
            "-g",
            self.mac_field(),
            "connection",
            "show",
            &self.connection,
        ])
        .ok()
        .as_deref()
        {
            Some(value) if value.eq_ignore_ascii_case("stable") => MacPolicy::Stable,
            Some(value) if value.eq_ignore_ascii_case("random") => MacPolicy::RandomOnReconnect,
            _ => MacPolicy::Unknown,
        }
    }

    fn read_vpn_active() -> Option<bool> {
        let output = bounded_output(
            "nmcli",
            &["-t", "-f", "TYPE,STATE", "connection", "show", "--active"],
        )
        .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
            let mut fields = line.split(':');
            matches!(fields.next(), Some(value) if value.eq_ignore_ascii_case("vpn"))
                && matches!(fields.next(), Some(value) if value.eq_ignore_ascii_case("activated"))
        }))
    }
}

impl NativeProfileOps for SystemProfileOps {
    fn read_state(&mut self) -> Result<PrivacyState, ProfileError> {
        let facts = collect_network_facts();
        if facts.interface.as_deref() != Some(self.interface.as_str())
            || facts.active_connection.as_deref() != Some(self.connection.as_str())
        {
            return Err(ProfileError::StateChanged);
        }
        let mac = Self::nm(&["-g", "GENERAL.HWADDR", "device", "show", &self.interface]).ok();
        let policy = self.read_mac_policy();
        let profile = [
            PrivacyProfile::Standard,
            PrivacyProfile::Private,
            PrivacyProfile::Travel,
        ]
        .into_iter()
        .find(|p| p.mac_policy() == policy && p.firewall_zone() == facts.trust_zone);
        Ok(PrivacyState {
            profile,
            interface: facts.interface,
            connection: facts.active_connection,
            mac_policy: policy,
            actual_mac: mac,
            firewall_zone: facts.trust_zone,
            vpn_active: Self::read_vpn_active(),
            public_ip_expectation: "Not assessed in the local posture path".into(),
        })
    }
    fn set_mac_policy(&mut self, policy: MacPolicy) -> Result<(), ProfileError> {
        let value = match policy {
            MacPolicy::Stable => "stable",
            MacPolicy::RandomOnReconnect => "random",
            MacPolicy::Unknown => return Err(ProfileError::UnsupportedConnection),
        };
        Self::nm(&[
            "connection",
            "modify",
            &self.connection,
            self.mac_field(),
            value,
        ])
        .map(|_| ())
    }
    fn set_firewall_zone(&mut self, zone: TrustZone) -> Result<(), ProfileError> {
        let name = match zone {
            TrustZone::Public => "public",
            TrustZone::Drop => "drop",
            _ => return Err(ProfileError::UnsupportedConnection),
        };
        // Apply firewalld first.  NetworkManager's connection profile is only
        // changed after the privileged active-interface operation succeeds;
        // this prevents an authorization failure from stranding a persistent
        // connection.zone value that was never effective.
        let output = bounded_output(
            "firewall-cmd",
            &[
                &format!("--zone={name}"),
                &format!("--change-interface={}", self.interface),
            ],
        )
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProfileError::NativeUnavailable
            } else {
                ProfileError::CommandFailed
            }
        })?;
        if !output.status.success() {
            return Err(ProfileError::CommandFailed);
        }
        Self::nm(&[
            "connection",
            "modify",
            &self.connection,
            "connection.zone",
            name,
        ])
        .map(|_| ())
    }
}

/// Reads and verifies the current native privacy state.
///
/// # Errors
///
/// Returns a profile error when no active connection is available or native
/// state cannot be read or verified.
pub fn read_actual_state() -> Result<PrivacyState, ProfileError> {
    let mut ops = SystemProfileOps::from_active()?;
    ops.read_state()
}

/// Applies a privacy profile through the native system controls.
///
/// # Errors
///
/// Returns a profile error when the active connection is unavailable, a native
/// operation fails, verification fails, or rollback cannot restore prior state.
pub fn apply_native_profile(profile: PrivacyProfile) -> Result<PrivacyState, ProfileError> {
    let mut ops = SystemProfileOps::from_active()?;
    apply_profile(&mut ops, profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        state: PrivacyState,
        fail_zone_once: bool,
    }
    impl NativeProfileOps for Fake {
        fn read_state(&mut self) -> Result<PrivacyState, ProfileError> {
            Ok(self.state.clone())
        }
        fn set_mac_policy(&mut self, policy: MacPolicy) -> Result<(), ProfileError> {
            self.state.mac_policy = policy;
            Ok(())
        }
        fn set_firewall_zone(&mut self, zone: TrustZone) -> Result<(), ProfileError> {
            if self.fail_zone_once {
                self.fail_zone_once = false;
                return Err(ProfileError::CommandFailed);
            }
            self.state.firewall_zone = zone;
            Ok(())
        }
    }
    fn fake() -> Fake {
        Fake {
            state: PrivacyState {
                profile: Some(PrivacyProfile::Standard),
                interface: Some("wlan0".into()),
                connection: Some("wifi".into()),
                mac_policy: MacPolicy::Stable,
                actual_mac: Some("AA:BB:CC:DD:EE:FF".into()),
                firewall_zone: TrustZone::Public,
                vpn_active: Some(false),
                public_ip_expectation: "fixture".into(),
            },
            fail_zone_once: false,
        }
    }
    #[test]
    fn standard_private_travel_targets_are_coherent() {
        assert_eq!(PrivacyProfile::Standard.mac_policy(), MacPolicy::Stable);
        assert_eq!(PrivacyProfile::Private.firewall_zone(), TrustZone::Drop);
        assert_eq!(
            PrivacyProfile::Travel.mac_policy(),
            MacPolicy::RandomOnReconnect
        );
    }
    #[test]
    fn transitions_are_transactional() {
        let mut f = fake();
        let state = apply_profile(&mut f, PrivacyProfile::Private).unwrap();
        assert_eq!(state.firewall_zone, TrustZone::Drop);
        assert_eq!(state.mac_policy, MacPolicy::Stable);
        let state = apply_profile(&mut f, PrivacyProfile::Travel).unwrap();
        assert_eq!(state.mac_policy, MacPolicy::RandomOnReconnect);
    }
    #[test]
    fn injected_failure_rolls_back_previous_state() {
        let mut f = fake();
        f.fail_zone_once = true;
        assert_eq!(
            apply_profile(&mut f, PrivacyProfile::Private),
            Err(ProfileError::CommandFailed)
        );
        assert_eq!(f.state.mac_policy, MacPolicy::Stable);
        assert_eq!(f.state.firewall_zone, TrustZone::Public);
    }
}
