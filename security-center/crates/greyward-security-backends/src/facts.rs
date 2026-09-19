use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SelinuxMode {
    Enforcing,
    Permissive,
    Disabled,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SelinuxFacts {
    pub mode: SelinuxMode,
    pub kernel_supported: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FirmwareMode {
    Uefi,
    Legacy,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SecureBootState {
    Enabled,
    Disabled,
    Unknown,
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootFacts {
    pub firmware: FirmwareMode,
    pub secure_boot: SecureBootState,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EncryptionState {
    Encrypted,
    Plain,
    Unknown,
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageFacts {
    pub root: EncryptionState,
    pub home: EncryptionState,
    pub swap: EncryptionState,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TpmCapability {
    Available,
    Missing,
    Unusable,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TpmFacts {
    pub capability: TpmCapability,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AdapterFacts {
    Selinux(SelinuxFacts),
    Boot(BootFacts),
    Storage(StorageFacts),
    Tpm(TpmFacts),
    Firmware(FirmwareFacts),
    SecurityUpdates(SecurityUpdatesFacts),
    Network(NetworkFacts),
    Flatpak(FlatpakFacts),
    Portal(PortalFacts),
    Usb(UsbFacts),
    Recovery(RecoveryFacts),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FirmwareSecurityState {
    Secure,
    Insecure,
    Unavailable,
    Unsupported,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FirmwareUpdateState {
    Available,
    NoneKnown,
    Unavailable,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FirmwareFacts {
    pub fwupd_available: bool,
    pub security: FirmwareSecurityState,
    pub updates: FirmwareUpdateState,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UpdateBackendState {
    Operational,
    Unavailable,
    Error,
    Stale,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityUpdatesFacts {
    pub backend: UpdateBackendState,
    pub available_count: Option<u32>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FirewallState {
    Available,
    Unavailable,
    Error,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrustZone {
    Public,
    Trusted,
    Home,
    Work,
    Drop,
    Block,
    External,
    Dmz,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkFacts {
    pub active_connection: Option<String>,
    pub interface: Option<String>,
    pub connection_type: Option<String>,
    pub firewall: FirewallState,
    pub trust_zone: TrustZone,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FlatpakAvailability {
    Available,
    Partial,
    Unavailable,
    Error,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlatpakApp {
    pub app_id: String,
    pub name: String,
    pub scope: String,
    pub origin: Option<String>,
    pub version: Option<String>,
    pub arch: Option<String>,
    pub branch: Option<String>,
    pub runtime: Option<String>,
    pub permissions: Vec<String>,
    pub overrides: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlatpakFacts {
    pub availability: FlatpakAvailability,
    pub apps: Vec<FlatpakApp>,
    pub broad_permission_apps: u32,
}

/// Product-facing access categories derived from Flatpak's effective context.
///
/// The raw manifest and local override records stay on `FlatpakApp` for the
/// technical disclosure. Product status and review decisions must use this
/// normalized model so a negating override cannot be presented as an active
/// permission.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum FlatpakAccessCategory {
    Scoped,
    Network,
    PersonalFiles,
    HostFiles,
    Devices,
    AllDevices,
    DesktopServices,
}

impl FlatpakAccessCategory {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Scoped => "SCOPED",
            Self::Network => "NETWORK",
            Self::PersonalFiles => "PERSONAL_FILES",
            Self::HostFiles => "HOST_FILES",
            Self::Devices => "DEVICES",
            Self::AllDevices => "ALL_DEVICES",
            Self::DesktopServices => "DESKTOP_SERVICES",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectiveFlatpakAccess {
    pub categories: Vec<FlatpakAccessCategory>,
    pub review_reasons: Vec<FlatpakAccessCategory>,
}

impl EffectiveFlatpakAccess {
    pub const fn needs_review(&self) -> bool {
        !self.review_reasons.is_empty()
    }
}

/// Resolve a Flatpak application's effective access from its manifest and
/// local overrides. Override entries are applied after manifest entries and
/// support the `!permission` form emitted by `flatpak override --show`.
pub fn resolve_flatpak_access(app: &FlatpakApp) -> EffectiveFlatpakAccess {
    let mut filesystems = BTreeSet::new();
    let mut devices = BTreeSet::new();
    let mut shares = BTreeSet::new();
    let mut desktop_services = false;

    for records in [&app.permissions, &app.overrides] {
        let mut section = "";
        for record in records {
            let record = record.trim();
            if record.starts_with('[') && record.ends_with(']') {
                section = record.trim_matches(['[', ']']).trim();
                continue;
            }
            let Some((raw_key, raw_values)) = record.split_once('=') else {
                continue;
            };
            let key = raw_key.trim().trim_start_matches('-').to_ascii_lowercase();
            let values = raw_values
                .split([';', ','])
                .map(str::trim)
                .filter(|value| !value.is_empty());
            match key.as_str() {
                "filesystem" | "filesystems" => {
                    apply_permission_values(&mut filesystems, values, false);
                }
                "nofilesystem" | "nofilesystems" => {
                    apply_permission_values(&mut filesystems, values, true);
                }
                "device" | "devices" => {
                    apply_permission_values(&mut devices, values, false);
                }
                "nodevice" | "nodevices" => {
                    apply_permission_values(&mut devices, values, true);
                }
                "share" | "shared" => {
                    apply_permission_values(&mut shares, values, false);
                }
                "unshare" | "unshared" => {
                    apply_permission_values(&mut shares, values, true);
                }
                "talk-name" | "own-name" | "system-talk-name" | "system-own-name" => {
                    desktop_services = true;
                }
                _ if section.eq_ignore_ascii_case("Session Bus Policy")
                    || section.eq_ignore_ascii_case("System Bus Policy") =>
                {
                    desktop_services = true;
                }
                _ => {}
            }
        }
    }

    let mut categories = Vec::new();
    let mut review_reasons = Vec::new();
    if shares.contains("network") {
        categories.push(FlatpakAccessCategory::Network);
    }
    if filesystems.iter().any(|value| is_host_filesystem(value)) {
        categories.push(FlatpakAccessCategory::HostFiles);
        review_reasons.push(FlatpakAccessCategory::HostFiles);
    } else if filesystems
        .iter()
        .any(|value| is_personal_filesystem(value))
    {
        categories.push(FlatpakAccessCategory::PersonalFiles);
        review_reasons.push(FlatpakAccessCategory::PersonalFiles);
    }
    if devices.contains("all") {
        categories.push(FlatpakAccessCategory::AllDevices);
        review_reasons.push(FlatpakAccessCategory::AllDevices);
    } else if !devices.is_empty() {
        categories.push(FlatpakAccessCategory::Devices);
    }
    if desktop_services {
        categories.push(FlatpakAccessCategory::DesktopServices);
    }
    if categories.is_empty() {
        categories.push(FlatpakAccessCategory::Scoped);
    }
    EffectiveFlatpakAccess {
        categories,
        review_reasons,
    }
}

fn apply_permission_values<'a>(
    values: &mut BTreeSet<String>,
    entries: impl Iterator<Item = &'a str>,
    remove: bool,
) {
    for raw_entry in entries {
        let entry = raw_entry.trim().to_ascii_lowercase();
        let negated = entry.starts_with('!');
        let normalized = entry
            .trim_start_matches('!')
            .split(':')
            .next()
            .unwrap_or_default()
            .trim();
        if normalized.is_empty() {
            continue;
        }
        if remove || negated {
            values.remove(normalized);
        } else {
            values.insert(normalized.to_owned());
        }
    }
}

fn is_host_filesystem(value: &str) -> bool {
    matches!(value, "host" | "host-os" | "host-etc")
}

fn is_personal_filesystem(value: &str) -> bool {
    value == "home" || value == "~" || value.starts_with("~/") || value.starts_with("xdg-")
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PortalHealth {
    Healthy,
    Degraded,
    Unavailable,
    Unsupported,
    ConfigurationError,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortalFacts {
    pub health: PortalHealth,
    pub owner: Option<String>,
    pub version: Option<String>,
    pub documents: bool,
    pub permission_store: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UsbGuardAvailability {
    Available,
    Unavailable,
    Error,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UsbGuardPolicy {
    Running,
    Stopped,
    Unconfigured,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsbFacts {
    pub availability: UsbGuardAvailability,
    pub policy: UsbGuardPolicy,
    pub connected_devices: u32,
    pub authorized_devices: u32,
    pub unknown_devices: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryReadiness {
    Ready,
    Partial,
    Unavailable,
    Unknown,
    Error,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryFacts {
    pub readiness: RecoveryReadiness,
    pub rescue_kernel: bool,
    pub uefi: bool,
    pub secure_boot: SecureBootState,
    pub encryption: EncryptionState,
    pub firmware_updates: FirmwareUpdateState,
    pub tpm: TpmCapability,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(permissions: &[&str], overrides: &[&str]) -> FlatpakApp {
        FlatpakApp {
            app_id: "org.example.App".into(),
            name: "Example".into(),
            scope: "user".into(),
            origin: None,
            version: None,
            arch: None,
            branch: None,
            runtime: None,
            permissions: permissions.iter().map(|value| (*value).into()).collect(),
            overrides: overrides.iter().map(|value| (*value).into()).collect(),
        }
    }

    #[test]
    fn resolves_plural_context_permissions_into_product_categories() {
        let access = resolve_flatpak_access(&app(
            &[
                "[Context]",
                "shared=network;ipc;",
                "filesystems=xdg-download:ro;",
                "devices=all;",
                "[Session Bus Policy]",
                "org.freedesktop.Notifications=talk",
            ],
            &[],
        ));
        assert_eq!(
            access.categories,
            vec![
                FlatpakAccessCategory::Network,
                FlatpakAccessCategory::PersonalFiles,
                FlatpakAccessCategory::AllDevices,
                FlatpakAccessCategory::DesktopServices,
            ]
        );
        assert_eq!(
            access.review_reasons,
            vec![
                FlatpakAccessCategory::PersonalFiles,
                FlatpakAccessCategory::AllDevices,
            ]
        );
    }

    #[test]
    fn negating_override_removes_a_manifest_grant_before_review() {
        let access = resolve_flatpak_access(&app(
            &["[Context]", "filesystems=home;", "devices=all;"],
            &["[Context]", "filesystems=!home;", "devices=!all;"],
        ));
        assert_eq!(access.categories, vec![FlatpakAccessCategory::Scoped]);
        assert!(access.review_reasons.is_empty());
    }

    #[test]
    fn host_files_take_precedence_over_less_broad_personal_paths() {
        let access = resolve_flatpak_access(&app(&["[Context]", "filesystems=home;host:ro;"], &[]));
        assert_eq!(access.categories, vec![FlatpakAccessCategory::HostFiles]);
        assert_eq!(
            access.review_reasons,
            vec![FlatpakAccessCategory::HostFiles]
        );
    }
}
