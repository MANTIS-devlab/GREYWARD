#![allow(
    clippy::wildcard_imports,
    clippy::default_trait_access,
    clippy::map_unwrap_or
)]
use crate::facts::*;
use chrono::Utc;
use greyward_security_domain::{CollectionIssue, CollectionIssueCategory, LocalizedMessage};
use std::fs;
use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);

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

/// Run one fixed provider command with a hard deadline.  A provider that is
/// missing, wedged, or waiting on an unavailable system service must become a
/// typed degraded fact instead of holding the whole Security Center request.
pub(crate) fn bounded_output(program: &str, args: &[&str]) -> io::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("provider stdout was not captured"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("provider stderr was not captured"))?;
    // Drain both pipes while the process runs. Waiting for the child before
    // reading can deadlock when a provider emits more than a pipe buffer.
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_reader.join().unwrap_or_default();
                let stderr = stderr_reader.join().unwrap_or_default();
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "provider command timed out",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}
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
            updates: FirmwareUpdateState::Unavailable,
        };
    }
    // The human `fwupdmgr security` and `get-updates` text formats are not
    // stable evidence contracts. Until the planned libfwupd binding exists,
    // use only the client's structured JSON output and fail closed when its
    // schema is absent or changes.
    let security_state = match bounded_output("fwupdmgr", &["security", "--json"]) {
        Ok(output) if output.status.success() => {
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .map(|value| firmware_security_from_json(&value))
                .unwrap_or(FirmwareSecurityState::Unknown)
        }
        Ok(_) => FirmwareSecurityState::Unavailable,
        Err(_) => FirmwareSecurityState::Unknown,
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
        updates: update_state,
    }
}
fn json_strings_for_keys(value: &serde_json::Value, keys: &[&str], output: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if keys
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
                {
                    if let Some(text) = child.as_str() {
                        output.push(text.to_ascii_lowercase());
                    }
                }
                json_strings_for_keys(child, keys, output);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                json_strings_for_keys(item, keys, output);
            }
        }
        _ => {}
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
fn firmware_security_from_json(value: &serde_json::Value) -> FirmwareSecurityState {
    let mut results = Vec::new();
    json_strings_for_keys(
        value,
        &["HsiResult", "Result", "ResultFallback"],
        &mut results,
    );
    if results
        .iter()
        .any(|result| matches!(result.as_str(), "invalid" | "not-valid" | "failed" | "fail"))
    {
        return FirmwareSecurityState::Insecure;
    }
    if !results.is_empty()
        && results
            .iter()
            .all(|result| matches!(result.as_str(), "valid" | "success" | "passed" | "pass"))
    {
        return FirmwareSecurityState::Secure;
    }
    if results
        .iter()
        .any(|result| matches!(result.as_str(), "not-supported" | "unsupported"))
    {
        return FirmwareSecurityState::Unsupported;
    }
    FirmwareSecurityState::Unknown
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
    match bounded_output("dnf5", &["-q", "check-update", "--security"]) {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            let count = text
                .lines()
                .filter(|line| {
                    !line.trim().is_empty()
                        && !line.starts_with("Last metadata")
                        && !line.starts_with("Upgrades")
                })
                .count();
            let count = u32::try_from(count).unwrap_or(u32::MAX);
            let backend = match output.status.code() {
                Some(0 | 100) => UpdateBackendState::Operational,
                _ => UpdateBackendState::Error,
            };
            SecurityUpdatesFacts {
                backend,
                available_count: Some(count),
            }
        }
        Err(_) => SecurityUpdatesFacts {
            backend: UpdateBackendState::Unavailable,
            available_count: None,
        },
    }
}
pub fn collect_network_facts() -> NetworkFacts {
    let active = bounded_output(
        "nmcli",
        &[
            "-t",
            "-f",
            "NAME,DEVICE,TYPE,STATE",
            "connection",
            "show",
            "--active",
        ],
    );
    let (active_connection, interface, connection_type) = match active {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 4 && fields[3] == "activated" && fields[1] != "lo" {
                    Some((
                        Some(fields[0].to_owned()),
                        Some(fields[1].to_owned()),
                        Some(fields[2].to_owned()),
                    ))
                } else {
                    None
                }
            })
            .unwrap_or((None, None, None)),
        _ => (None, None, None),
    };
    let Some(iface) = interface.as_deref() else {
        return NetworkFacts {
            active_connection,
            interface,
            connection_type,
            firewall: FirewallState::Unknown,
            trust_zone: TrustZone::Unknown,
        };
    };
    let zone_output = bounded_output("firewall-cmd", &["--get-zone-of-interface", iface]);
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

pub fn collect_flatpak_facts() -> FlatpakFacts {
    let version = bounded_output("flatpak", &["--version"]);
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
    let (user, system) = thread::scope(|scope| {
        let user = scope.spawn(|| collect_flatpak_scope("user"));
        let system = scope.spawn(|| collect_flatpak_scope("system"));
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
            (_, 0) => FlatpakAvailability::Available,
            _ => FlatpakAvailability::Partial,
        },
        apps,
        broad_permission_apps,
    }
}
fn collect_flatpak_scope(scope: &str) -> Result<Vec<FlatpakApp>, ()> {
    let scope_flag = format!("--{scope}");
    let output = bounded_output(
        "flatpak",
        &[
            "list",
            "--app",
            scope_flag.as_str(),
            "--columns=application,name,version,origin,arch,branch,runtime",
        ],
    )
    .map_err(|_| ())?;
    if !output.status.success() {
        return Err(());
    }
    let descriptors = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let app_id = fields
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())?
                .to_owned();
            Some((
                app_id.clone(),
                fields.next().unwrap_or(app_id.as_str()).trim().to_owned(),
                fields
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned),
                fields
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned),
                fields
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned),
                fields
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned),
                fields
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned),
            ))
        })
        .collect::<Vec<_>>();
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
                .map(|(app_id, name, version, origin, arch, branch, runtime)| {
                    let scope_flag = format!("--{scope_name}");
                    let app_scope = scope_name.clone();
                    scope.spawn(move || FlatpakApp {
                        permissions: flatpak_permissions(&app_id, scope_flag.as_str()),
                        overrides: flatpak_overrides(&app_id, scope_flag.as_str()),
                        app_id,
                        name,
                        scope: app_scope,
                        origin,
                        version,
                        arch,
                        branch,
                        runtime,
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .filter_map(|handle| handle.join().ok())
                .collect::<Vec<_>>()
        });
        apps.extend(results);
    }
    Ok(apps)
}
fn flatpak_permissions(app_id: &str, scope_flag: &str) -> Vec<String> {
    bounded_output(
        "flatpak",
        &["info", scope_flag, "--show-permissions", app_id],
    )
    .ok()
    .filter(|output| output.status.success())
    .map(|output| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .take(64)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
    .unwrap_or_default()
}
fn flatpak_overrides(app_id: &str, scope_flag: &str) -> Vec<String> {
    bounded_output("flatpak", &["override", scope_flag, "--show", app_id])
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .take(64)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
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
    fn structured_hsi_results_are_conservative() {
        let valid = serde_json::json!({
            "Attributes": [{"HsiResult": "valid"}, {"HsiResult": "success"}]
        });
        assert_eq!(
            firmware_security_from_json(&valid),
            FirmwareSecurityState::Secure
        );

        let failed = serde_json::json!({
            "Attributes": [{"HsiResult": "valid"}, {"HsiResult": "not-valid"}]
        });
        assert_eq!(
            firmware_security_from_json(&failed),
            FirmwareSecurityState::Insecure
        );
        assert_eq!(
            firmware_security_from_json(&serde_json::json!({})),
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
