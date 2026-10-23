#![allow(
    clippy::wildcard_imports,
    clippy::default_trait_access,
    clippy::map_unwrap_or
)]
use crate::facts::*;
use chrono::Utc;
use greyward_security_domain::{CollectionIssue, CollectionIssueCategory, LocalizedMessage};
use std::fs;

use std::thread;
use std::time::{Duration, Instant};

fn startup_provider_trace<T>(name: &str, provider: impl FnOnce() -> T) -> T {
    let trace_enabled = std::env::var_os("GREYWARD_STARTUP_TRACE").is_some()
        || std::path::Path::new("/tmp/greyward-startup-trace.enable").exists();
    let started = trace_enabled.then(Instant::now);
    let value = provider();
    if let Some(started) = started {
        eprintln!(
            "GREYWARD_PROVIDER provider={name} elapsed_ms={:.2}",
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    value
}

pub(crate) use crate::provider_process::bounded_output;
pub fn collect_core_facts() -> (Vec<AdapterFacts>, Vec<CollectionIssue>) {
    let now = Utc::now();
    let mut issues = Vec::new();
    let mode = match fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(v) if v.trim() == "1" => SelinuxMode::Enforcing,
        Ok(v) if v.trim() == "0" => SelinuxMode::Permissive,
        Ok(_) => SelinuxMode::Unknown,
        Err(_) => SelinuxMode::Disabled,
    };
    let boot = BootFacts {
        firmware: if fs::metadata("/sys/firmware/efi").is_ok() {
            FirmwareMode::Uefi
        } else {
            FirmwareMode::Legacy
        },
        secure_boot: secure_boot(),
    };
    let storage = StorageFacts {
        root: mount_state("/"),
        home: mount_state("/home"),
        swap: EncryptionState::Unknown,
    };
    let tpm = TpmFacts {
        capability: if fs::metadata("/dev/tpmrm0").is_ok() {
            TpmCapability::Available
        } else if fs::metadata("/sys/class/tpm").is_ok() {
            TpmCapability::Unusable
        } else {
            TpmCapability::Missing
        },
    };
    // These probes are read-only and independent. Running them together keeps
    // the snapshot bounded by the slowest local provider instead of the sum of
    // multiple command launches, without broadening the collection surface.
    let (firmware, updates, network, flatpak, portal, usb) = thread::scope(|scope| {
        let firmware = scope.spawn(|| startup_provider_trace("firmware", collect_firmware));
        let updates = scope.spawn(|| startup_provider_trace("updates", collect_security_updates));
        let network = scope.spawn(|| startup_provider_trace("network", collect_network_facts));
        let flatpak = scope.spawn(|| startup_provider_trace("flatpak", collect_flatpak_facts));
        let portal = scope.spawn(|| startup_provider_trace("portal", collect_portal_facts));
        let usb = scope.spawn(|| startup_provider_trace("usb", collect_usb_facts));
        (
            firmware.join().unwrap_or_else(|_| collect_firmware()),
            updates
                .join()
                .unwrap_or_else(|_| collect_security_updates()),
            network.join().unwrap_or_else(|_| collect_network_facts()),
            flatpak.join().unwrap_or_else(|_| collect_flatpak_facts()),
            portal.join().unwrap_or_else(|_| collect_portal_facts()),
            usb.join().unwrap_or_else(|_| collect_usb_facts()),
        )
    });
    let recovery = startup_provider_trace("recovery", || {
        collect_recovery_facts(&boot, &storage, &tpm, &firmware)
    });
    if matches!(mode, SelinuxMode::Unknown) {
        issues.push(CollectionIssue {
            backend_id: "selinux".into(),
            category: CollectionIssueCategory::Internal,
            safe_message: LocalizedMessage {
                key: "collection.failed".into(),
                parameters: Default::default(),
            },
            observed_at: now,
            retryable: true,
        });
    }
    (
        vec![
            AdapterFacts::Selinux(SelinuxFacts {
                mode,
                kernel_supported: fs::metadata("/sys/fs/selinux").is_ok(),
            }),
            AdapterFacts::Boot(boot),
            AdapterFacts::Storage(storage),
            AdapterFacts::Tpm(tpm),
            AdapterFacts::Firmware(firmware),
            AdapterFacts::SecurityUpdates(updates),
            AdapterFacts::Network(network),
            AdapterFacts::Flatpak(flatpak),
            AdapterFacts::Portal(portal),
            AdapterFacts::Usb(usb),
            AdapterFacts::Recovery(recovery),
        ],
        issues,
    )
}

/// Collect only the local facts required by the Devices surface. This keeps a
/// device page read from paying for firmware, package, Flatpak, portal, and
/// network providers that belong to the full posture graph.
pub fn collect_device_facts() -> Vec<AdapterFacts> {
    let boot = BootFacts {
        firmware: if fs::metadata("/sys/firmware/efi").is_ok() {
            FirmwareMode::Uefi
        } else {
            FirmwareMode::Legacy
        },
        secure_boot: secure_boot(),
    };
    let storage = StorageFacts {
        root: mount_state("/"),
        home: mount_state("/home"),
        swap: EncryptionState::Unknown,
    };
    let tpm = TpmFacts {
        capability: if fs::metadata("/dev/tpmrm0").is_ok() {
            TpmCapability::Available
        } else if fs::metadata("/sys/class/tpm").is_ok() {
            TpmCapability::Unusable
        } else {
            TpmCapability::Missing
        },
    };
    let usb = collect_usb_facts();
    let recovery = collect_recovery_facts(
        &boot,
        &storage,
        &tpm,
        &FirmwareFacts {
            fwupd_available: false,
            security: FirmwareSecurityState::Unknown,
            security_attributes: Vec::new(),
            updates: FirmwareUpdateState::Unknown,
        },
    );
    vec![
        AdapterFacts::Boot(boot),
        AdapterFacts::Storage(storage),
        AdapterFacts::Tpm(tpm),
        AdapterFacts::Usb(usb),
        AdapterFacts::Recovery(recovery),
    ]
}
fn secure_boot() -> SecureBootState {
    match fs::read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c") {
        Ok(v) if v.len() >= 5 => {
            if v[4] == 1 {
                SecureBootState::Enabled
            } else {
                SecureBootState::Disabled
            }
        }
        Ok(_) => SecureBootState::Unknown,
        Err(_) => SecureBootState::Unsupported,
    }
}
fn mount_state(m: &str) -> EncryptionState {
    let s = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    match s.lines().find(|l| {
        l.split(" - ")
            .next()
            .map(|x| x.split_whitespace().any(|p| p == m))
            .unwrap_or(false)
    }) {
        Some(l) if l.contains("/dev/mapper") || l.contains("crypt") => EncryptionState::Encrypted,
        Some(_) => EncryptionState::Plain,
        None => EncryptionState::Unknown,
    }
}
fn collect_firmware() -> FirmwareFacts {
    let fwupd = bounded_output("fwupdmgr", &["--version"]);
    if !fwupd.as_ref().is_ok_and(|output| output.status.success()) {
        return FirmwareFacts {
            fwupd_available: false,
            security: FirmwareSecurityState::Unsupported,
            security_attributes: Vec::new(),
            updates: FirmwareUpdateState::Unavailable,
        };
    }
    // The human `fwupdmgr security` and `get-updates` text formats are not
    // stable evidence contracts. Until the planned libfwupd binding exists,
    // use only the client's structured JSON output and fail closed when its
    // schema is absent or changes.
    let (security_state, security_attributes) =
        match bounded_output("fwupdmgr", &["security", "--json"]) {
            Ok(output) if output.status.success() => {
                serde_json::from_slice::<serde_json::Value>(&output.stdout)
                    .map(|value| firmware_security_report_from_json(&value))
                    .unwrap_or((FirmwareSecurityState::Unknown, Vec::new()))
            }
            Ok(_) => (FirmwareSecurityState::Unavailable, Vec::new()),
            Err(_) => (FirmwareSecurityState::Unknown, Vec::new()),
        };
    let update_state = match bounded_output("fwupdmgr", &["get-updates", "--json"]) {
        Ok(output) if output.status.success() => {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .map(|value| firmware_updates_from_json(&value))
                .unwrap_or(FirmwareUpdateState::Unknown)
        }
        Ok(_) | Err(_) => FirmwareUpdateState::Unknown,
    };
    FirmwareFacts {
        fwupd_available: true,
        security: security_state,
        security_attributes,
        updates: update_state,
    }
}
fn json_array_presence(value: &serde_json::Value, keys: &[&str]) -> (bool, bool) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if keys
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
                {
                    if let Some(items) = child.as_array() {
                        return (true, !items.is_empty());
                    }
                }
                let (seen, nonempty) = json_array_presence(child, keys);
                if seen {
                    return (seen, nonempty);
                }
            }
            (false, false)
        }
        serde_json::Value::Array(items) => {
            for item in items {
                let (seen, nonempty) = json_array_presence(item, keys);
                if seen {
                    return (seen, nonempty);
                }
            }
            (false, false)
        }
        _ => (false, false),
    }
}
fn bounded_json_string(value: &serde_json::Value, key: &str, max_chars: usize) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .chars()
        .take(max_chars)
        .collect()
}

fn firmware_security_report_from_json(
    value: &serde_json::Value,
) -> (FirmwareSecurityState, Vec<FirmwareSecurityAttribute>) {
    // Only SecurityAttributes describe the current measured posture.
    // SecurityEvents is historical and can contain prior boot results.
    let attributes: Vec<FirmwareSecurityAttribute> = value
        .get("SecurityAttributes")
        .or_else(|| value.get("Attributes"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(64)
        .filter_map(|attribute| {
            if !attribute.is_object() {
                return None;
            }
            let flags = attribute
                .get("Flags")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .filter(|flag| flag.len() <= 48 && flag.starts_with("action-"))
                .take(8)
                .map(str::to_owned)
                .collect();
            Some(FirmwareSecurityAttribute {
                id: bounded_json_string(attribute, "AppstreamId", 160),
                name: bounded_json_string(attribute, "Name", 120),
                result: bounded_json_string(attribute, "HsiResult", 64).to_ascii_lowercase(),
                expected: bounded_json_string(attribute, "HsiResultSuccess", 64)
                    .to_ascii_lowercase(),
                summary: bounded_json_string(attribute, "Summary", 240),
                description: bounded_json_string(attribute, "Description", 480),
                flags,
            })
        })
        .collect();
    if attributes.is_empty() {
        return (FirmwareSecurityState::Unknown, attributes);
    }

    let mut unsupported = false;
    let mut unknown = false;
    let mut insecure = false;
    for attribute in &attributes {
        if attribute.result.is_empty() || attribute.expected.is_empty() {
            unknown = true;
        } else if attribute.result != attribute.expected {
            if matches!(attribute.result.as_str(), "not-supported" | "unsupported") {
                unsupported = true;
            } else {
                insecure = true;
            }
        }
    }
    let state = if insecure {
        FirmwareSecurityState::Insecure
    } else if unknown {
        FirmwareSecurityState::Unknown
    } else if unsupported {
        FirmwareSecurityState::Unsupported
    } else {
        FirmwareSecurityState::Secure
    };
    (state, attributes)
}

#[cfg(test)]
fn firmware_security_from_json(value: &serde_json::Value) -> FirmwareSecurityState {
    firmware_security_report_from_json(value).0
}
fn firmware_updates_from_json(value: &serde_json::Value) -> FirmwareUpdateState {
    let (release_seen, release_nonempty) = json_array_presence(value, &["Releases", "releases"]);
    if release_seen {
        return if release_nonempty {
            FirmwareUpdateState::Available
        } else {
            FirmwareUpdateState::NoneKnown
        };
    }
    let (device_seen, device_nonempty) = json_array_presence(value, &["Devices", "devices"]);
    match (device_seen, device_nonempty) {
        (true, false) => FirmwareUpdateState::NoneKnown,
        _ => FirmwareUpdateState::Unknown,
    }
}
fn collect_security_updates() -> SecurityUpdatesFacts {
    match bounded_output("dnf5", &["check-upgrade", "--json", "--security"]) {
        Ok(output) => {
            let exit_code = output.status.code();
            let backend_operational = matches!(exit_code, Some(0 | 100));
            let count = security_update_count(exit_code, &output.stdout);
            let backend = if backend_operational && count.is_some() {
                UpdateBackendState::Operational
            } else {
                UpdateBackendState::Error
            };
            SecurityUpdatesFacts {
                backend,
                available_count: if backend_operational { count } else { None },
            }
        }
        Err(_) => SecurityUpdatesFacts {
            backend: UpdateBackendState::Unavailable,
            available_count: None,
        },
    }
}

fn security_update_count(exit_code: Option<i32>, stdout: &[u8]) -> Option<u32> {
    let value = serde_json::from_slice::<serde_json::Value>(stdout).ok()?;
    if let Some(upgrades) = value.get("upgrades").and_then(serde_json::Value::as_array) {
        return u32::try_from(upgrades.len()).ok();
    }

    // DNF5 5.4 emits an empty object when a successful security-only query
    // finds no matching upgrades. Accept only that exact empty response and
    // only for exit status 0; a missing schema on other statuses remains an
    // error instead of being mistaken for a clean system.
    if exit_code == Some(0) && value.as_object().is_some_and(serde_json::Map::is_empty) {
        return Some(0);
    }

    None
}
pub fn collect_network_facts() -> NetworkFacts {
    collect_network_facts_with(bounded_output, collect_firewall_state)
}

fn collect_firewall_state() -> FirewallState {
    let Ok(bus) = dbus::blocking::Connection::new_system() else {
        return FirewallState::Unavailable;
    };
    let proxy = bus.with_proxy(
        "systems.mantis.greyward.OpenSnitchPolicy1",
        "/systems/mantis/greyward/OpenSnitchPolicy1",
        Duration::from_secs(3),
    );
    let reply: Result<(String,), _> = proxy.method_call(
        "systems.mantis.greyward.OpenSnitchPolicy1",
        "GetFirewallState",
        (),
    );
    match reply.as_ref().map(|(state,)| state.as_str()) {
        Ok("running") => FirewallState::Available,
        Ok("not-running") => FirewallState::Error,
        _ => FirewallState::Unavailable,
    }
}

fn collect_network_facts_with(
    mut read: impl FnMut(&str, &[&str]) -> std::io::Result<std::process::Output>,
    mut firewall_state: impl FnMut() -> FirewallState,
) -> NetworkFacts {
    let active = read(
        "nmcli",
        &[
            "-t",
            "-e",
            "no",
            "-f",
            "NAME,DEVICE,TYPE,STATE",
            "connection",
            "show",
            "--active",
        ],
    );
    let mut active_connection = None;
    let mut interface = None;
    let mut connection_type = None;
    let mut disconnected = false;
    if let Ok(output) = &active
        && output.status.success()
        && let Ok(text) = std::str::from_utf8(&output.stdout)
    {
        disconnected = true;
        for line in text.lines().filter(|line| !line.is_empty()) {
            // NAME may contain colons. The three trailing fields are fixed.
            let fields: Vec<_> = line.rsplitn(4, ':').collect();
            if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
                disconnected = false;
                break;
            }
            if fields[2] == "lo" {
                continue;
            }
            disconnected = false;
            if fields[0] == "activated" {
                active_connection = Some(fields[3].to_owned());
                interface = Some(fields[2].to_owned());
                connection_type = Some(fields[1].to_owned());
            }
            break;
        }
    }
    let Some(iface) = interface.as_deref() else {
        // Offline is a connection state, not evidence that local protection
        // vanished. Still require a live firewall reply; never trust no output.
        // Do not use firewall-cmd --state here: firewalld's property read
        // requests CONFIG authorization and can prompt on every refresh.
        let firewall = firewall_state();
        return NetworkFacts {
            active_connection,
            interface,
            connection_type,
            disconnected,
            firewall,
            trust_zone: TrustZone::Unknown,
        };
    };
    let zone_output = read("firewall-cmd", &["--get-zone-of-interface", iface]);
    let (firewall, trust_zone) = match zone_output {
        Ok(output) if output.status.success() => (
            FirewallState::Available,
            parse_zone(String::from_utf8_lossy(&output.stdout).trim()),
        ),
        Ok(_) => (FirewallState::Error, TrustZone::Unknown),
        Err(_) => (FirewallState::Unavailable, TrustZone::Unknown),
    };
    NetworkFacts {
        active_connection,
        interface,
        connection_type,
        disconnected,
        firewall,
        trust_zone,
    }
}
fn parse_zone(zone: &str) -> TrustZone {
    match zone {
        "public" => TrustZone::Public,
        "trusted" => TrustZone::Trusted,
        "home" => TrustZone::Home,
        "work" => TrustZone::Work,
        "drop" => TrustZone::Drop,
        "block" => TrustZone::Block,
        "external" => TrustZone::External,
        "dmz" => TrustZone::Dmz,
        _ => TrustZone::Unknown,
    }
}

#[cfg(all(test, unix))]
mod network_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    #[test]
    fn collector_distinguishes_offline_from_failed_or_malformed_reads() {
        for (text, status, offline) in [
            ("", 0, true),
            ("lo:lo:loopback:activated\n", 0, true),
            ("", 1, false),
            ("invalid\n", 0, false),
            ("wifi:wlan0:802-11-wireless:activating\n", 0, false),
            ("Office: LAN:eth0:802-3-ethernet:activated\n", 0, false),
        ] {
            let mut commands = Vec::new();
            let facts = collect_network_facts_with(
                |program, args| {
                    commands.push((program.to_owned(), args.join(" ")));
                    let (code, stdout) = if program == "nmcli" {
                        (status, text)
                    } else {
                        assert_eq!(args, ["--get-zone-of-interface", "eth0"]);
                        (0, "public\n")
                    };
                    Ok(Output {
                        status: ExitStatus::from_raw(code << 8),
                        stdout: stdout.as_bytes().to_vec(),
                        stderr: Vec::new(),
                    })
                },
                || FirewallState::Available,
            );
            assert_eq!(facts.disconnected, offline);
            assert_eq!(facts.firewall, FirewallState::Available);
            assert_eq!(
                commands.len(),
                if facts.interface.is_some() { 2 } else { 1 }
            );
            assert!(!commands.iter().any(|(_, args)| args == "--state"));
            if text.starts_with("Office:") {
                assert_eq!(facts.active_connection.as_deref(), Some("Office: LAN"));
                assert_eq!(facts.interface.as_deref(), Some("eth0"));
            }
        }
        for state in [FirewallState::Error, FirewallState::Unavailable] {
            let facts = collect_network_facts_with(
                |program, _| {
                    assert_eq!(program, "nmcli");
                    Ok(Output {
                        status: ExitStatus::from_raw(0),
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    })
                },
                || state.clone(),
            );
            assert!(facts.disconnected);
            assert_ne!(facts.firewall, FirewallState::Available);
        }
    }
}

pub fn collect_flatpak_facts() -> FlatpakFacts {
    let deadline = Instant::now() + Duration::from_secs(8);
    let version =
        crate::provider_process::bounded_output_until("/usr/bin/flatpak", &["--version"], deadline);
    if version
        .as_ref()
        .map(|output| !output.status.success())
        .unwrap_or(true)
    {
        return FlatpakFacts {
            availability: FlatpakAvailability::Unavailable,
            apps: Vec::new(),
            broad_permission_apps: 0,
        };
    }
    let mut failed_scopes = 0u8;
    let mut inspected_scopes = 0u8;
    // Named system installations need the new registry provider. Until then,
    // this compatibility view must disclose incomplete discovery instead of
    // claiming the default system/user scopes are the complete installation set.
    let default_installation_only = crate::provider_process::bounded_output_until(
        "/usr/bin/flatpak",
        &["--installations"],
        deadline,
    )
    .ok()
    .filter(|output| output.status.success())
    .and_then(|output| String::from_utf8(output.stdout).ok())
    .is_some_and(|text| {
        text.lines()
            .filter(|line| !line.is_empty())
            .eq(["/var/lib/flatpak"])
    });
    let (user, system) = thread::scope(|scope| {
        let user = scope.spawn(|| collect_flatpak_scope("user", deadline));
        let system = scope.spawn(|| collect_flatpak_scope("system", deadline));
        (
            user.join().unwrap_or(Err(())),
            system.join().unwrap_or(Err(())),
        )
    });
    let mut apps = Vec::new();
    for result in [user, system] {
        match result {
            Ok(mut values) => {
                inspected_scopes += 1;
                apps.append(&mut values);
            }
            Err(()) => failed_scopes += 1,
        }
    }
    let broad_permission_apps = apps
        .iter()
        .filter(|app| resolve_flatpak_access(app).needs_review())
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    FlatpakFacts {
        availability: match (inspected_scopes, failed_scopes) {
            (0, _) => FlatpakAvailability::Error,
            (_, 0)
                if default_installation_only
                    && apps
                        .iter()
                        .all(|app| app.permissions_state == FlatpakAvailability::Available) =>
            {
                FlatpakAvailability::Available
            }
            _ => FlatpakAvailability::Partial,
        },
        apps,
        broad_permission_apps,
    }
}
fn collect_flatpak_scope(scope: &str, deadline: Instant) -> Result<Vec<FlatpakApp>, ()> {
    let scope_flag = format!("--{scope}");
    let output = crate::provider_process::bounded_output_until(
        "/usr/bin/flatpak",
        &[
            "list",
            "--app",
            scope_flag.as_str(),
            "--json",
            "--columns=application,name,version,origin,arch,branch,runtime",
        ],
        deadline,
    )
    .map_err(|_| ())?;
    if !output.status.success() {
        return Err(());
    }
    let descriptors = crate::flatpak_inventory::installed_records(&output.stdout)?;
    let mut apps = Vec::with_capacity(descriptors.len());
    // Flatpak has no supported bulk permission endpoint here. Keep the
    // authoritative per-app reads, but bound parallelism to four workers so
    // larger inventories do not create an unbounded process burst.
    for batch in descriptors.chunks(4) {
        let batch = batch.to_vec();
        let scope_name = scope.to_owned();
        let results = thread::scope(|scope| {
            let handles = batch
                .into_iter()
                .map(|descriptor| {
                    let scope_flag = format!("--{scope_name}");
                    let app_scope = scope_name.clone();
                    scope.spawn(move || {
                        let reference = descriptor.reference();
                        let before = flatpak_commit(&reference, &scope_flag, deadline);
                        let (mut permissions, mut permissions_state) =
                            flatpak_permissions(&reference, scope_flag.as_str(), deadline);
                        let overrides =
                            flatpak_overrides(&descriptor.application_id, &scope_flag, deadline);
                        let after = flatpak_commit(&reference, &scope_flag, deadline);
                        let (deployment_commit, identity_state) = match (before, after) {
                            (Some(first), Some(second)) if first == second => {
                                (Some(first), FlatpakAvailability::Available)
                            }
                            _ => {
                                permissions.clear();
                                permissions_state = FlatpakAvailability::Unavailable;
                                (None, FlatpakAvailability::Unavailable)
                            }
                        };
                        FlatpakApp {
                            permissions,
                            permissions_state,
                            deployment_commit,
                            identity_state,
                            overrides,
                            app_id: descriptor.application_id.clone(),
                            name: descriptor.name.unwrap_or(descriptor.application_id),
                            scope: app_scope,
                            origin: descriptor.origin,
                            version: descriptor.version,
                            arch: Some(descriptor.arch),
                            branch: Some(descriptor.branch),
                            runtime: descriptor.runtime,
                        }
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().map_err(|_| ()))
                .collect::<Result<Vec<_>, _>>()
        });
        apps.extend(results?);
    }
    Ok(apps)
}
fn flatpak_commit(
    reference: &str,
    scope_flag: &str,
    deadline: Instant,
) -> Option<greyward_security_domain::ContentGeneration> {
    crate::provider_process::bounded_output_until(
        "/usr/bin/flatpak",
        &["info", scope_flag, "--show-commit", reference],
        deadline,
    )
    .ok()
    .filter(|output| output.status.success())
    .and_then(|output| crate::flatpak_inventory::deployment_commit(&output.stdout).ok())
}

fn flatpak_permissions(
    app_id: &str,
    scope_flag: &str,
    deadline: Instant,
) -> (Vec<String>, FlatpakAvailability) {
    let result = crate::provider_process::bounded_output_until(
        "/usr/bin/flatpak",
        &["info", scope_flag, "--show-permissions", app_id],
        deadline,
    )
    .ok()
    .filter(|output| output.status.success())
    .ok_or(FlatpakAvailability::Unavailable)
    .and_then(|output| crate::flatpak_permissions::permission_records(&output.stdout));
    match result {
        Ok(records) => (records, FlatpakAvailability::Available),
        Err(state) => (Vec::new(), state),
    }
}
fn flatpak_overrides(app_id: &str, scope_flag: &str, deadline: Instant) -> Vec<String> {
    crate::provider_process::bounded_output_until(
        "/usr/bin/flatpak",
        &["override", scope_flag, "--show", app_id],
        deadline,
    )
    .ok()
    .filter(|output| output.status.success())
    .and_then(|output| crate::flatpak_permissions::permission_records(&output.stdout).ok())
    .unwrap_or_default()
}
pub fn collect_portal_facts() -> PortalFacts {
    let (desktop, documents, permission_store) = thread::scope(|scope| {
        let desktop = scope.spawn(|| portal_status("org.freedesktop.portal.Desktop"));
        let documents = scope.spawn(|| portal_status("org.freedesktop.portal.Documents"));
        let permission_store =
            scope.spawn(|| portal_status("org.freedesktop.impl.portal.PermissionStore"));
        (
            desktop.join().unwrap_or(false),
            documents.join().unwrap_or(false),
            permission_store.join().unwrap_or(false),
        )
    });
    let health = if !desktop {
        PortalHealth::Unavailable
    } else if documents && permission_store {
        PortalHealth::Healthy
    } else {
        PortalHealth::Degraded
    };
    PortalFacts {
        health,
        owner: desktop.then(|| "org.freedesktop.portal.Desktop".into()),
        version: None,
        documents,
        permission_store,
    }
}
fn portal_status(name: &str) -> bool {
    bounded_output("busctl", &["--user", "--no-pager", "status", name])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn collect_usb_facts() -> UsbFacts {
    let package = bounded_output("rpm", &["-q", "usbguard"]);
    let availability = match package {
        Ok(output) if output.status.success() => UsbGuardAvailability::Available,
        Ok(_) => UsbGuardAvailability::Unavailable,
        Err(_) => UsbGuardAvailability::Unknown,
    };
    if matches!(
        availability,
        UsbGuardAvailability::Unavailable | UsbGuardAvailability::Unknown
    ) {
        return UsbFacts {
            availability,
            policy: UsbGuardPolicy::Unknown,
            connected_devices: 0,
            authorized_devices: 0,
            unknown_devices: 0,
        };
    }
    let policy = match bounded_output("systemctl", &["is-active", "usbguard"]) {
        Ok(output) if output.status.success() => UsbGuardPolicy::Running,
        Ok(_) => UsbGuardPolicy::Stopped,
        Err(_) => UsbGuardPolicy::Unknown,
    };
    let mut connected_devices = 0_u32;
    let mut authorized_devices = 0_u32;
    let mut unknown_devices = 0_u32;
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten().take(128) {
            let path = entry.path();
            if path.join("idVendor").is_file() {
                connected_devices = connected_devices.saturating_add(1);
                match fs::read_to_string(path.join("authorized")).map(|v| v.trim() == "1") {
                    Ok(true) => authorized_devices = authorized_devices.saturating_add(1),
                    Ok(false) => {}
                    Err(_) => unknown_devices = unknown_devices.saturating_add(1),
                }
            }
        }
    }
    UsbFacts {
        availability,
        policy,
        connected_devices,
        authorized_devices,
        unknown_devices,
    }
}

pub fn collect_recovery_facts(
    boot: &BootFacts,
    storage: &StorageFacts,
    tpm: &TpmFacts,
    firmware: &FirmwareFacts,
) -> RecoveryFacts {
    let rescue_kernel = fs::read_dir("/boot")
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains("vmlinuz-0-rescue"))
        })
        .unwrap_or(false);
    let uefi = matches!(boot.firmware, FirmwareMode::Uefi);
    let readiness = if !rescue_kernel {
        RecoveryReadiness::Unavailable
    } else if uefi
        && matches!(boot.secure_boot, SecureBootState::Enabled)
        && matches!(storage.root, EncryptionState::Encrypted)
        && matches!(tpm.capability, TpmCapability::Available)
    {
        RecoveryReadiness::Ready
    } else if uefi || rescue_kernel {
        RecoveryReadiness::Partial
    } else {
        RecoveryReadiness::Unknown
    };
    RecoveryFacts {
        readiness,
        rescue_kernel,
        uefi,
        secure_boot: boot.secure_boot.clone(),
        encryption: storage.root.clone(),
        firmware_updates: firmware.updates.clone(),
        tpm: tpm.capability.clone(),
    }
}

#[cfg(test)]
mod firmware_tests {
    use super::*;

    #[test]
    fn successful_empty_dnf5_security_result_means_no_updates() {
        assert_eq!(security_update_count(Some(0), b"{}"), Some(0));
        assert_eq!(
            security_update_count(Some(0), br#"{"upgrades":[]}"#),
            Some(0)
        );
        assert_eq!(
            security_update_count(Some(100), br#"{"upgrades":[{},{}]}"#),
            Some(2)
        );
        assert_eq!(security_update_count(Some(100), b"{}"), None);
        assert_eq!(security_update_count(Some(1), b"{}"), None);
        assert_eq!(security_update_count(Some(0), b"not-json"), None);
        assert_eq!(
            security_update_count(Some(0), br#"{"message":"no updates"}"#),
            None
        );
    }

    #[test]
    fn structured_hsi_results_are_conservative() {
        let valid = serde_json::json!({
            "SecurityAttributes": [
                {"AppstreamId":"org.fwupd.hsi.Uefi.SecureBoot", "Name":"UEFI Secure Boot", "HsiResult":"enabled", "HsiResultSuccess":"enabled"},
                {"AppstreamId":"org.fwupd.hsi.Kernel.Tainted", "Name":"Linux kernel", "HsiResult":"not-tainted", "HsiResultSuccess":"not-tainted"},
                {"AppstreamId":"org.fwupd.hsi.Kernel.Swap", "Name":"Linux swap", "HsiResult":"encrypted", "HsiResultSuccess":"encrypted"}
            ],
            "SecurityEvents": [{"HsiResult":"not-valid"}]
        });
        assert_eq!(
            firmware_security_from_json(&valid),
            FirmwareSecurityState::Secure
        );

        let failed = serde_json::json!({
            "SecurityAttributes": [
                {"AppstreamId":"org.fwupd.hsi.Uefi.Db", "Name":"UEFI db", "HsiResult":"not-valid", "HsiResultSuccess":"valid", "Summary":"UEFI db", "Description":"The trusted EFI certificate database.", "Flags":["runtime-issue", "action-config-fw"]},
                {"AppstreamId":"org.fwupd.hsi.EncryptedRam", "Name":"Encrypted RAM", "HsiResult":"not-supported", "HsiResultSuccess":"encrypted", "Flags":["action-config-fw"]}
            ]
        });
        assert_eq!(
            firmware_security_from_json(&failed),
            FirmwareSecurityState::Insecure
        );
        let (_, attributes) = firmware_security_report_from_json(&failed);
        assert_eq!(attributes.len(), 2);
        assert_eq!(attributes[0].name, "UEFI db");
        assert_eq!(attributes[0].flags, vec!["action-config-fw".to_string()]);
        assert_eq!(
            firmware_security_from_json(&serde_json::json!({})),
            FirmwareSecurityState::Unknown
        );
    }

    #[test]
    fn hsi_requires_a_current_report_and_a_matching_expected_result() {
        assert_eq!(
            firmware_security_from_json(&serde_json::json!({
                "SecurityAttributes": [{"HsiResult":"not-valid","HsiResultSuccess":"valid"}],
                "SecurityEvents": [{"HsiResult":"valid"}]
            })),
            FirmwareSecurityState::Insecure
        );
        assert_eq!(
            firmware_security_from_json(&serde_json::json!({
                "SecurityAttributes": [{"HsiResult":"not-supported","HsiResultSuccess":"encrypted"}]
            })),
            FirmwareSecurityState::Unsupported
        );
        assert_eq!(
            firmware_security_from_json(&serde_json::json!({
                "SecurityAttributes": [{"HsiResult":"valid"}]
            })),
            FirmwareSecurityState::Unknown
        );
    }

    #[test]
    fn structured_update_results_do_not_infer_from_unrelated_text() {
        assert_eq!(
            firmware_updates_from_json(&serde_json::json!({
                "Devices": [{"Releases": [{"Version": "1.2"}]}]
            })),
            FirmwareUpdateState::Available
        );
        assert_eq!(
            firmware_updates_from_json(&serde_json::json!({"Devices": [{"Name": "device"}]})),
            FirmwareUpdateState::Unknown
        );
        assert_eq!(
            firmware_updates_from_json(&serde_json::json!({"Devices": []})),
            FirmwareUpdateState::NoneKnown
        );
        assert_eq!(
            firmware_updates_from_json(&serde_json::json!({"message": "available"})),
            FirmwareUpdateState::Unknown
        );
    }
}
