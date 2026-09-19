mod adapters;
mod context;
mod control;
mod facts;
mod framework;
mod policy;
mod presentation;
mod privacy;
mod profiles;
pub use adapters::{
    collect_core_facts, collect_device_facts, collect_flatpak_facts, collect_network_facts,
    collect_portal_facts, collect_recovery_facts, collect_usb_facts,
};
use chrono::Utc;
pub use context::{
    OPENSNITCH_CONTEXT_SUMMARY_PATH, context_summary, load_opensnitch_context_summary,
    notification_class, retain_context_events,
};
pub use control::{
    FlatpakPermissionError, TrustZoneError, change_active_trust_zone,
    change_home_filesystem_permission, restore_home_filesystem_permission,
    rollback_active_trust_zone,
};
pub use facts::{
    AdapterFacts, BootFacts, EffectiveFlatpakAccess, FirmwareFacts, FlatpakAccessCategory,
    FlatpakApp, FlatpakAvailability, FlatpakFacts, NetworkFacts, PortalFacts, PortalHealth,
    RecoveryFacts, RecoveryReadiness, SecurityUpdatesFacts, SelinuxFacts, StorageFacts, TpmFacts,
    TrustZone, UsbFacts, UsbGuardAvailability, UsbGuardPolicy, resolve_flatpak_access,
};
pub use framework::{CollectionGeneration, Collector, collect_concurrently};
use greyward_security_domain::{CURRENT_EVALUATOR_VERSION, PostureSnapshot, SNAPSHOT_V1_SCHEMA};
pub use policy::{
    evaluate_facts, evaluate_facts_with_deviations, load_accepted_deviations,
    set_accepted_deviation,
};
pub use presentation::{
    EvidencePresentation, EvidenceRemediation, evidence_domain_key, evidence_domain_route,
    evidence_presentation,
};
pub use privacy::{
    ActivityCategory, ActivityItem, ActivitySeverity, ExternalServiceDisclosure,
    MAX_ACTIVITY_ITEMS, PrivacyError, RETENTION_DAYS, SafeExport, build_safe_export,
    clear_activity, external_service_manifest, load_activity, load_activity_from, record_activity,
    retain_activity, state_directory, write_safe_export,
};
pub use profiles::{
    MacPolicy, NativeProfileOps, PrivacyProfile, PrivacyState, ProfileError, apply_native_profile,
    apply_profile, read_actual_state,
};
#[derive(Clone)]
pub struct CoreCollection {
    pub snapshot: PostureSnapshot,
    pub usb: UsbFacts,
}

pub fn collect_core_collection() -> CoreCollection {
    let (facts, mut issues) = collect_core_facts();
    let mut s = evaluate_facts_with_deviations(&facts, &load_accepted_deviations());
    s.schema = SNAPSHOT_V1_SCHEMA.into();
    s.generated_at = Utc::now();
    s.evaluator_version = CURRENT_EVALUATOR_VERSION.into();
    s.collection_issues.append(&mut issues);
    let usb = facts
        .iter()
        .find_map(|item| match item {
            AdapterFacts::Usb(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap_or(UsbFacts {
            availability: UsbGuardAvailability::Unknown,
            policy: UsbGuardPolicy::Unknown,
            connected_devices: 0,
            authorized_devices: 0,
            unknown_devices: 0,
        });
    CoreCollection { snapshot: s, usb }
}

pub fn collect_device_snapshot() -> CoreCollection {
    let facts = collect_device_facts();
    let snapshot = evaluate_facts_with_deviations(&facts, &load_accepted_deviations());
    let usb = facts
        .iter()
        .find_map(|item| match item {
            AdapterFacts::Usb(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap_or(UsbFacts {
            availability: UsbGuardAvailability::Unknown,
            policy: UsbGuardPolicy::Unknown,
            connected_devices: 0,
            authorized_devices: 0,
            unknown_devices: 0,
        });
    CoreCollection { snapshot, usb }
}

pub fn collect_core_snapshot() -> PostureSnapshot {
    collect_core_collection().snapshot
}
#[cfg(test)]
mod tests {
    use super::*;
    use facts::*;
    #[test]
    fn snapshot_keeps_six_domains() {
        assert_eq!(collect_core_snapshot().domains.len(), 6);
    }
    #[test]
    fn unavailable_tpm_and_plain_root_are_distinct() {
        let s = evaluate_facts(&[
            AdapterFacts::Selinux(SelinuxFacts {
                mode: SelinuxMode::Enforcing,
                kernel_supported: true,
            }),
            AdapterFacts::Boot(BootFacts {
                firmware: FirmwareMode::Uefi,
                secure_boot: SecureBootState::Enabled,
            }),
            AdapterFacts::Storage(StorageFacts {
                root: EncryptionState::Plain,
                home: EncryptionState::Plain,
                swap: EncryptionState::Unknown,
            }),
            AdapterFacts::Tpm(TpmFacts {
                capability: TpmCapability::Missing,
            }),
        ]);
        assert_eq!(
            s.checks
                .iter()
                .find(|c| c.check_id.as_str() == "data.storage.root-encryption")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::ReviewNeeded
        );
        assert_eq!(
            s.checks
                .iter()
                .find(|c| c.check_id.as_str() == "devices.tpm.presence")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::Unavailable
        );
    }
    #[test]
    fn firmware_and_updates_preserve_unavailable_and_actionable_states() {
        let snapshot = evaluate_facts(&[
            AdapterFacts::Firmware(FirmwareFacts {
                fwupd_available: true,
                security: FirmwareSecurityState::Unavailable,
                updates: FirmwareUpdateState::NoneKnown,
            }),
            AdapterFacts::SecurityUpdates(SecurityUpdatesFacts {
                backend: UpdateBackendState::Operational,
                available_count: Some(5),
            }),
        ]);
        assert_eq!(
            snapshot
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "system.firmware.hsi")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::Unavailable
        );
        assert_eq!(
            snapshot
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "system.security-updates")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::ReviewNeeded
        );
    }
    #[test]
    fn network_posture_keeps_known_and_unavailable_distinct() {
        let known = evaluate_facts(&[AdapterFacts::Network(NetworkFacts {
            active_connection: Some("wired".into()),
            interface: Some("eth0".into()),
            connection_type: Some("ethernet".into()),
            firewall: FirewallState::Available,
            trust_zone: TrustZone::Public,
        })]);
        assert_eq!(
            known
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "network.active-connection")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::Secure
        );
        let unavailable = evaluate_facts(&[AdapterFacts::Network(NetworkFacts {
            active_connection: Some("wired".into()),
            interface: Some("eth0".into()),
            connection_type: Some("ethernet".into()),
            firewall: FirewallState::Unavailable,
            trust_zone: TrustZone::Unknown,
        })]);
        assert_eq!(
            unavailable
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "network.active-connection")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::Unavailable
        );
    }
    #[test]
    fn flatpak_and_portal_states_are_distinct() {
        let snapshot = evaluate_facts(&[
            AdapterFacts::Flatpak(FlatpakFacts {
                availability: FlatpakAvailability::Unavailable,
                apps: Vec::new(),
                broad_permission_apps: 0,
            }),
            AdapterFacts::Portal(PortalFacts {
                health: PortalHealth::Healthy,
                owner: Some("portal".into()),
                version: None,
                documents: true,
                permission_store: true,
            }),
        ]);
        assert_eq!(
            snapshot
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "applications.flatpak.posture")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::Unavailable
        );
        assert_eq!(
            snapshot
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "applications.portal-health")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::Secure
        );
    }
    #[test]
    fn usbguard_unavailable_and_recovery_partial_are_honest() {
        let snapshot = evaluate_facts(&[
            AdapterFacts::Usb(UsbFacts {
                availability: UsbGuardAvailability::Unavailable,
                policy: UsbGuardPolicy::Unknown,
                connected_devices: 0,
                authorized_devices: 0,
                unknown_devices: 0,
            }),
            AdapterFacts::Recovery(RecoveryFacts {
                readiness: RecoveryReadiness::Partial,
                rescue_kernel: true,
                uefi: true,
                secure_boot: SecureBootState::Enabled,
                encryption: EncryptionState::Plain,
                firmware_updates: FirmwareUpdateState::NoneKnown,
                tpm: TpmCapability::Missing,
            }),
        ]);
        assert_eq!(
            snapshot
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "devices.usbguard.posture")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::Unavailable
        );
        assert_eq!(
            snapshot
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "recovery.readiness")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::ReviewNeeded
        );
    }

    #[test]
    fn usbguard_installed_but_stopped_is_review_needed_not_protected() {
        let snapshot = evaluate_facts(&[AdapterFacts::Usb(UsbFacts {
            availability: UsbGuardAvailability::Available,
            policy: UsbGuardPolicy::Stopped,
            connected_devices: 0,
            authorized_devices: 0,
            unknown_devices: 0,
        })]);
        assert_eq!(
            snapshot
                .checks
                .iter()
                .find(|c| c.check_id.as_str() == "devices.usbguard.posture")
                .unwrap()
                .state,
            greyward_security_domain::PostureState::ReviewNeeded
        );
    }

    #[test]
    fn accepted_deviation_resolves_required_secure_boot_failure() {
        let snapshot = evaluate_facts_with_deviations(
            &[AdapterFacts::Boot(BootFacts {
                firmware: FirmwareMode::Uefi,
                secure_boot: SecureBootState::Disabled,
            })],
            &["system.boot.secure-boot".into()],
        );
        let check = snapshot
            .checks
            .iter()
            .find(|check| check.check_id.as_str() == "system.boot.secure-boot")
            .expect("secure boot check");
        assert_eq!(
            check.state,
            greyward_security_domain::PostureState::Protected
        );
        assert_eq!(check.reason_code, "accepted-deviation");
        assert_eq!(
            snapshot.accepted_deviations,
            vec!["system.boot.secure-boot"]
        );
    }

    #[test]
    fn ignored_missing_tpm_resolves_unavailable_recommendation() {
        let snapshot = evaluate_facts_with_deviations(
            &[AdapterFacts::Tpm(TpmFacts {
                capability: TpmCapability::Missing,
            })],
            &["devices.tpm.presence".into()],
        );
        let check = snapshot
            .checks
            .iter()
            .find(|check| check.check_id.as_str() == "devices.tpm.presence")
            .expect("TPM presence check");
        assert_eq!(
            check.state,
            greyward_security_domain::PostureState::Protected
        );
        assert_eq!(check.reason_code, "accepted-deviation");
    }

    #[test]
    fn ignored_unavailable_recovery_resolves_recovery_card() {
        let snapshot = evaluate_facts_with_deviations(
            &[AdapterFacts::Recovery(RecoveryFacts {
                readiness: RecoveryReadiness::Unavailable,
                rescue_kernel: false,
                uefi: true,
                secure_boot: SecureBootState::Enabled,
                encryption: EncryptionState::Encrypted,
                firmware_updates: FirmwareUpdateState::NoneKnown,
                tpm: TpmCapability::Missing,
            })],
            &["recovery.readiness".into()],
        );
        let check = snapshot
            .checks
            .iter()
            .find(|check| check.check_id.as_str() == "recovery.readiness")
            .expect("recovery readiness check");
        assert_eq!(
            check.state,
            greyward_security_domain::PostureState::Protected
        );
        assert_eq!(check.reason_code, "accepted-deviation");
    }
}
