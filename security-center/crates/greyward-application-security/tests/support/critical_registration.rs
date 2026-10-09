//! The combined blocking flow. Only fixed synthetic objects and UID 1002.
use dbus::strings::BusName;
use greyward_application_security::*;
use greyward_security_domain::*;
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
const TOOL: &str = "/usr/local/libexec/greyward-application-security-reviewed-tool";
const SECRET: &str = "/home/greyward-guard-probe/registration-critical/synthetic";

pub fn transport_client() {
    let client = GuardClient::connect(true).unwrap();
    println!("AUTH_PEER={}", client.unique_name());
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
    let fd = rustix::fs::open(
        "/home/greyward-guard-probe/registration-critical",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let preview = client
        .preview_registration(fd.into(), "CUSTOM", "Synthetic descriptor registration", 1)
        .unwrap();
    let WorkflowPreview::Registration(summary) = &preview else {
        panic!("Wrong resource preview")
    };
    let resource = summary.resource.resource_ref.clone();
    client.apply(preview.operation_ref(), true).unwrap();
    let result = client
        .wait_operation(
            preview.operation_ref(),
            Instant::now() + Duration::from_secs(100),
        )
        .unwrap();
    assert_eq!(result.committed_revision, Some(2));
    assert!(result.verified_readback);
    println!("WORKFLOW_RESOURCE_REGISTERED={}", resource.as_str());
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
    context_checks(&["--preview-grant"]);
    let preview = client
        .preview_grant("/usr/bin/cat", std::slice::from_ref(&resource), 2)
        .unwrap();
    let WorkflowPreview::Grant {
        grant_ref, review, ..
    } = &preview
    else {
        panic!("Wrong native grant preview")
    };
    assert!(
        review
            .risks
            .contains(&PolicyRisk::InProcessExtensionsShareAccess)
    );
    let grant_ref = grant_ref.clone();
    client.apply(preview.operation_ref(), true).unwrap();
    let result = client
        .wait_operation(
            preview.operation_ref(),
            Instant::now() + Duration::from_secs(100),
        )
        .unwrap();
    assert_eq!(result.committed_revision, Some(3));
    let launch = client
        .prepare_launch(&grant_ref, "/usr/bin/cat", vec![SECRET.into()])
        .unwrap();
    assert_eq!(
        launch_output(&client, &launch),
        "synthetic registration data"
    );
    isolated_controls(&client);
    additional_grant(&client, &resource);
    context_checks(&[]);
    println!("WORKFLOW_REVIEWED_LAUNCH_ALLOWED={}", grant_ref.as_str());
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
    let preview = client
        .preview_revoke(&grant_ref, "", client.resources().unwrap().policy_revision)
        .unwrap();
    client.apply(preview.operation_ref(), true).unwrap();
    let result = client
        .wait_operation(
            preview.operation_ref(),
            Instant::now() + Duration::from_secs(100),
        )
        .unwrap();
    assert_eq!(result.committed_revision, Some(6));
    assert!(result.verified_readback);
    assert!(
        client
            .prepare_launch(&grant_ref, "/usr/bin/cat", vec![SECRET.into()])
            .is_err()
    );
    let coverage = client.coverage().unwrap();
    assert_eq!(coverage.protection.health, EnforcementHealth::Unknown);
    assert!(coverage.protection.effective_profile.is_none());
    println!("WORKFLOW_REVOKED");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
}
fn additional_grant(client: &GuardClient, resource: &SecurityReference) {
    let preview = client
        .preview_grant("/usr/bin/head", std::slice::from_ref(resource), 3)
        .unwrap();
    let WorkflowPreview::Grant { grant_ref, .. } = &preview else {
        panic!("Wrong additional grant");
    };
    client.apply(preview.operation_ref(), true).unwrap();
    assert!(
        client
            .wait_operation(
                preview.operation_ref(),
                Instant::now() + Duration::from_secs(100)
            )
            .unwrap()
            .verified_readback
    );
    let launch = client
        .prepare_launch(grant_ref, "/usr/bin/head", vec![SECRET.into()])
        .unwrap();
    assert_eq!(
        launch_output(client, &launch),
        "synthetic registration data"
    );
    let revoke = client.preview_revoke(grant_ref, "", 4).unwrap();
    client.apply(revoke.operation_ref(), true).unwrap();
    assert!(
        client
            .wait_operation(
                revoke.operation_ref(),
                Instant::now() + Duration::from_secs(100)
            )
            .unwrap()
            .verified_readback
    );
    assert!(
        client
            .prepare_launch(grant_ref, "/usr/bin/head", vec![SECRET.into()])
            .is_err()
    );
}
fn context_checks(arguments: &[&str]) {
    let context = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-B",
            "/usr/local/libexec/greyward-application-security-product-context.py",
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        context.status.success(),
        "{}",
        String::from_utf8_lossy(&context.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&context.stdout),
        "CONTEXT_WORKFLOW_PASS\n"
    );
}
fn isolated_controls(client: &GuardClient) {
    // Functional runner continuation only. The closed critical matrix is unchanged.
    for (selected, expected_exit) in [("/usr/lib/os-release", 0), (SECRET, 1)] {
        let candidate = rustix::fs::open(
            "/home/greyward-guard-probe/unknown-cat",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let launch = client
            .prepare_isolated(candidate.into(), vec![selected.into()])
            .unwrap();
        let (input, mut output, mut error) = client.start_launch(&launch).unwrap();
        drop(input);
        let mut result = String::new();
        output.read_to_string(&mut result).unwrap();
        let mut diagnostic = String::new();
        error.read_to_string(&mut diagnostic).unwrap();
        assert_eq!(
            client
                .wait_launch(&launch, Instant::now() + Duration::from_secs(110))
                .unwrap(),
            expected_exit,
            "{diagnostic}"
        );
        if expected_exit == 0 {
            assert!(result.contains("Fedora"));
        } else {
            assert!(result.is_empty());
        }
    }
    for file in ["guard-test.py", "guard-test.sh", "guard-test.AppImage"] {
        let fd = rustix::fs::open(
            format!("/home/greyward-guard-probe/{file}"),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let launch = client.prepare_isolated(fd.into(), vec![]).unwrap();
        assert_eq!(launch_output(client, &launch), "GUARD_PAYLOAD_OK\n");
    }
    let ordinary = rustix::fs::open(
        "/home/greyward-guard-probe/ordinary.txt",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let launch = client
        .prepare_document(
            ordinary.into(),
            "/usr/bin/cat",
            vec!["/run/guard-document".into()],
            false,
        )
        .unwrap();
    assert_eq!(launch_output(client, &launch), "ordinary\n");
    // Registered data cannot enter a generic selected-document launch, even
    // though the selected descriptor itself can be held by the confined peer.
    let protected = rustix::fs::open(
        SECRET,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    // SELinux can refuse SCM_RIGHTS at the system-bus boundary before the
    // provider sees the descriptor. Keep this negative connection independent.
    let refusal = GuardClient::connect(true).unwrap();
    assert!(
        refusal
            .prepare_document(
                protected.into(),
                "/usr/bin/cat",
                vec!["/run/guard-document".into()],
                false
            )
            .is_err()
    );
    let graphical = rustix::fs::open(
        "/home/greyward-guard-probe/guard-graphical.py",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let launch = client.prepare_graphical(graphical.into(), vec![]).unwrap();
    assert_eq!(launch_output(client, &launch), "");
}
fn launch_output(client: &GuardClient, launch: &SecurityReference) -> String {
    let (input, mut output, mut error) = client.start_launch(launch).unwrap();
    drop(input);
    let mut result = String::new();
    output.read_to_string(&mut result).unwrap();
    let mut diagnostic = String::new();
    error.read_to_string(&mut diagnostic).unwrap();
    assert_eq!(
        client
            .wait_launch(launch, Instant::now() + Duration::from_secs(110))
            .unwrap(),
        0,
        "{diagnostic}"
    );
    result
}

struct PrivateHost;
impl PrivateHost {
    fn start() -> Self {
        let runtime = std::path::Path::new("/run/user/1002");
        if !runtime.exists() {
            assert!(
                Command::new("/usr/bin/install")
                    .args([
                        "-d",
                        "-o",
                        "1002",
                        "-g",
                        "1002",
                        "-m",
                        "0700",
                        "/run/user/1002"
                    ])
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new("/usr/sbin/restorecon")
                    .arg(runtime)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert!(!runtime.join("wayland-0").exists());
        assert!(Command::new("/usr/bin/systemd-run").args(["--quiet","--collect","--unit=greyward-appsec-product-display","-p","User=1002","-p","Group=1002","-p","PAMName=login","-p","RuntimeMaxSec=90","-p","MemoryMax=256M","-p","TasksMax=64","-p","PrivateNetwork=yes","-p","SELinuxContext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0","-p","Environment=XDG_RUNTIME_DIR=/run/user/1002 WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_HEADLESS_OUTPUTS=1","--","/usr/bin/labwc","-C","/home/greyward-guard-probe/appsec-graphical","-S","/usr/bin/sleep 80"]).status().unwrap().success());
        for _ in 0..80 {
            if runtime.join("wayland-0").exists() {
                return Self;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("Private host display unavailable");
    }
}
impl Drop for PrivateHost {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/systemctl")
            .args(["stop", "greyward-appsec-product-display.service"])
            .status();
    }
}

fn marker(output: &mut impl BufRead, prefix: &str) -> String {
    for _ in 0..32 {
        let mut line = String::new();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        assert!(line.len() <= 4096);
        if let Some(value) = line.trim().strip_prefix(prefix) {
            return value.to_owned();
        }
    }
    panic!("Missing bounded transport marker");
}

pub fn run_transport(
    actor: &ExecutionHandle,
    child: &mut std::process::Child,
    output: &mut impl BufRead,
) {
    child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    let resource = marker(output, "WORKFLOW_RESOURCE_REGISTERED=");
    assert!(resource.starts_with("resource_"));
    ordinary_checks("greyward_guard_u:greyward_guard_r:greyward_guard_t:s0");
    let session = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "/usr/local/libexec/greyward-application-security-tty.py",
            "--critical",
        ])
        .output()
        .unwrap();
    assert!(
        session.status.success(),
        "{} {}",
        String::from_utf8_lossy(&session.stdout),
        String::from_utf8_lossy(&session.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&session.stdout).unwrap();
    assert_eq!(receipt["passed"], true);
    let private_host = PrivateHost::start();
    child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    let grant_ref =
        SecurityReference::try_from(marker(output, "WORKFLOW_REVIEWED_LAUNCH_ALLOWED=")).unwrap();
    drop(private_host);
    let recovery_account = std::env::var("GREYWARD_RECOVERY_ACCOUNT")
        .expect("Set the existing development recovery account explicitly");
    let graphical_ui = Command::new("/usr/sbin/runuser")
        .args([
            "-u",
            &recovery_account,
            "--",
            "/bin/bash",
            "/var/tmp/greyward-application-security-probe/application-security-ui-check.sh",
            "--workflow",
        ])
        .env("XDG_RUNTIME_DIR", "/run/user/1001")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1001/bus")
        .output()
        .unwrap();
    assert!(
        graphical_ui.status.success(),
        "{} {}",
        String::from_utf8_lossy(&graphical_ui.stdout),
        String::from_utf8_lossy(&graphical_ui.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(100);
    let store = PolicyStore::open_development_registration_probe().unwrap();
    let code = InstalledExecutable::capture("/usr/bin/cat", deadline).unwrap();
    let grant = ReviewedReadGrant::prepare_rpm(&store, actor, &grant_ref, &code, deadline).unwrap();
    grant.verify_active(&store, actor, &code).unwrap();
    assert!(
        !worker(
            "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0",
            "greyward-appsec-critical-bypass"
        )
        .args(["/usr/bin/runcon", grant.context(), "/usr/bin/cat", SECRET])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
    );
    ordinary_checks("greyward_guard_u:greyward_guard_r:greyward_guard_t:s0");
    let mut holder = worker(grant.context(), "greyward-appsec-critical-holder")
        .args([TOOL, "--held-revocation"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut held_output = std::io::BufReader::new(holder.stdout.take().unwrap());
    assert_eq!(marker(&mut held_output, "GRANT_"), "READY");
    child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    marker(output, "WORKFLOW_REVOKED");
    grant.verify_revoked(&store, actor).unwrap();
    holder.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    let mut held = String::new();
    held_output.read_to_string(&mut held).unwrap();
    assert!(holder.wait().unwrap().success(), "{held}");
    assert!(held.contains("HELD_DESCRIPTOR_REVOKED"));
    ordinary_checks("greyward_guard_u:greyward_guard_r:greyward_guard_t:s0");
    child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    assert!(child.wait().unwrap().success());
}
fn lease(n: u8, revision: u64) -> PolicyReviewLease {
    PolicyReviewLease {
        operation_ref: SecurityReference::try_from(format!("operation_{n:064x}")).unwrap(),
        expected_revision: revision,
        deadline: Instant::now() + Duration::from_secs(80),
    }
}
fn worker(context: &str, unit: &str) -> Command {
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .args(["--quiet", "--wait", "--pipe", "--collect"])
        .arg(format!("--unit={unit}"))
        .args([
            "-p",
            "User=greyward-guard-probe",
            "-p",
            "Group=greyward-guard-probe",
            "-p",
            "RuntimeMaxSec=75",
            "-p",
            "MemoryMax=64M",
            "-p",
            "TasksMax=16",
            "-p",
            "NoNewPrivileges=yes",
            "-p",
            "CapabilityBoundingSet=",
            "-p",
            "PrivateNetwork=yes",
        ])
        .arg("-p")
        .arg(format!("SELinuxContext={context}"));
    command
}
fn ordinary_checks(context: &str) {
    assert!(
        worker(context, "greyward-appsec-critical-control")
            .args(["/usr/bin/cat", "/home/greyward-guard-probe/ordinary.txt"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    for (unit, binary) in [
        ("greyward-appsec-critical-direct", "/usr/bin/cat"),
        (
            "greyward-appsec-critical-unknown",
            "/home/greyward-guard-probe/unknown-cat",
        ),
    ] {
        assert!(
            !worker(context, unit)
                .args([binary, SECRET])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
}
#[allow(clippy::too_many_lines)] // One ordered fixture retains the freshly authenticated peer through revocation.
pub fn run(
    store: &mut PolicyStore,
    actor: &ExecutionHandle,
    sender: &BusName<'_>,
    authorizer: &SystemAuthorizer,
    registration: ResourceRegistrationLease,
    program: &ResourceDenialProgram,
) {
    let provider = DevelopmentKernelProvider::open().unwrap();
    let labeled = provider
        .register(
            registration,
            store,
            actor,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
    let readback =
        DevelopmentDenialReadback::read(program, Instant::now() + Duration::from_secs(25)).unwrap();
    assert_eq!(labeled.objects_labeled(), 4);
    labeled
        .revalidate(store, actor, program, &readback)
        .unwrap();
    let resource = labeled.resource_ref().clone();
    ordinary_checks("greyward_guard_u:greyward_guard_r:greyward_guard_t:s0");
    let session = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "/usr/local/libexec/greyward-application-security-tty.py",
            "--critical",
        ])
        .output()
        .unwrap();
    assert!(
        session.status.success(),
        "Private session failed: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&session.stdout),
        String::from_utf8_lossy(&session.stderr)
    );
    let session_receipt: serde_json::Value = serde_json::from_slice(&session.stdout).unwrap();
    assert_eq!(session_receipt["passed"], true);
    assert_eq!(
        session_receipt["probe"]["checks"]["flatpak_ordinary_control_and_protected_denial"],
        true
    );
    assert_eq!(
        session_receipt["probe"]["checks"]["dms_labwc_startup"],
        true
    );
    let deadline = Instant::now() + Duration::from_secs(80);
    let code = InstalledExecutable::capture(TOOL, deadline).unwrap();
    let identity = IdentitySeed {
        provider: ApplicationProvider::Manual,
        logical_id: "critical-reviewed-tool".into(),
        installation_id: "root-owned-development".into(),
        source_id: "explicit-review".into(),
        owner_uid: 1002,
    }
    .identity(code.generation().clone())
    .unwrap();
    store
        .reconcile_applications(1002, vec![identity.clone()], 0, 1)
        .unwrap();
    let reference = SecurityReference::try_from(format!("grant_{}", "a".repeat(64))).unwrap();
    let proposal = AccessGrant {
        grant_ref: reference.clone(),
        owner_uid: 1002,
        installation_ref: identity.installation_ref,
        generation: identity.generation,
        resources: vec![resource],
        access: vec![ResourceAccess::Read],
        lifetime: GrantLifetime::Persistent,
        policy_revision: 3,
    };
    PolicyIntentReview::propose_persistent_grant(store, actor, proposal, lease(2, 2))
        .unwrap()
        .commit(store, actor, sender, authorizer, true)
        .unwrap();
    let grant = provider
        .activate_read_grant(store, actor, &reference, &code, deadline)
        .unwrap();
    grant.verify_active(store, actor, &code).unwrap();
    let cache = ManagedCodeStore::open_development_launch_probe().unwrap();
    let prepared = PreparedReviewedLaunch::prepare(
        store,
        actor,
        &reference,
        InstalledExecutable::capture(TOOL, deadline).unwrap(),
        &cache,
        vec!["--fixed-read".into()],
        deadline,
    )
    .unwrap();
    let mut launched = prepared.spawn(store, actor).unwrap();
    let mut stdout = String::new();
    launched
        .stdout()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let status = launched.wait().unwrap();
    let mut stderr = String::new();
    launched
        .stderr()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        status.success(),
        "Immutable reviewed launch failed: {stderr}"
    );
    assert!(
        stdout.contains("REVIEWED_READ_ALLOWED_CHILD_DENIED"),
        "Missing fixed proof marker: stdout={stdout:?}, stderr={stderr:?}"
    );
    drop(launched);
    drop(cache);
    // Ordinary execution of the same installed binary does not transition or
    // acquire its reviewed grants. Explicit role/context requests also refuse.
    assert!(
        !worker(
            "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0",
            "greyward-appsec-critical-bypass"
        )
        .args(["/usr/bin/runcon", grant.context(), "/usr/bin/cat", SECRET])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
    );
    ordinary_checks("greyward_guard_u:greyward_guard_r:greyward_guard_t:s0");
    grant.revalidate(store, actor, &code).unwrap();
    let mut child = worker(grant.context(), "greyward-appsec-critical-holder")
        .args([TOOL, "--held-revocation"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "GRANT_READY");
    let revoked = PolicyIntentReview::revoke_grant(store, actor, reference, lease(3, 3))
        .unwrap()
        .commit(store, actor, sender, authorizer, true)
        .unwrap();
    provider
        .revoke_read_grant(revoked, store, actor, &grant, deadline)
        .unwrap();
    grant.verify_revoked(store, actor).unwrap();
    assert!(grant.verify_active(store, actor, &code).is_err());
    child.stdin.take().unwrap().write_all(&[1]).unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "HELD_DESCRIPTOR_REVOKED");
    assert!(child.wait().unwrap().success());
    assert!(store.desired_policy().unwrap().grants.is_empty());
    assert_eq!(
        store.desired_policy().unwrap().resources[0]
            .resource()
            .coverage,
        ResourceCoverage::Unknown
    );
    println!("CRITICAL_LABEL_DENY_ALLOW_BYPASS_REVOKE_PASS_COVERAGE_UNKNOWN");
}
