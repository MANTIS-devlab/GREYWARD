//! Fixed separate-account integration driver for the runtime restriction core.
//! Never installed by the RPM or exposed as an application launch command.
use greyward_application_security::{
    NativeDescriptorRule, NativeRuleKind, restrict_native_disconnected,
};
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::process::{Command, Stdio};
fn verify_worker_environment() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::getuid().as_raw() != 1002
        || std::env::args().collect::<Vec<_>>().as_slice()
            != [std::env::args().next().unwrap(), "--fixed-probe".to_owned()]
    {
        return Err("Only the separate fixed development subject is supported".into());
    }
    let context = fs::read_to_string("/proc/self/attr/current")?;
    if context.split(':').nth(2) != Some("greyward_guard_t") {
        return Err("Mandatory subject domain is missing".into());
    }
    // Independent kernel observations: systemd properties alone are not evidence.
    if rustix::process::getpid().as_raw_nonzero().get() != 1 {
        return Err("Private PID namespace is missing".into());
    }
    for namespace in ["mnt", "pid", "net", "user"] {
        let expected_host =
            std::env::var(format!("GREYWARD_HOST_NS_{}", namespace.to_uppercase()))?;
        let actual = fs::read_link(format!("/proc/self/ns/{namespace}"))?;
        if actual.to_str() == Some(expected_host.as_str()) || expected_host.is_empty() {
            return Err("Required private namespace is missing".into());
        }
    }
    let uid_map = fs::read_to_string("/proc/self/uid_map")?;
    if uid_map
        .lines()
        .any(|line| line.split_whitespace().last() != Some("1"))
    {
        return Err("Broad user namespace mapping is refused".into());
    }
    Ok(())
}

fn probe() -> Result<(), Box<dyn std::error::Error>> {
    verify_worker_environment()?;
    let mut status_file = File::open("/proc/self/status")?;
    let mut status = String::new();
    status_file.read_to_string(&mut status)?;
    if !status
        .lines()
        .any(|line| line == "CapEff:\t0000000000000000")
    {
        return Err("Effective capabilities remain".into());
    }
    // Positive/negative baselines before the additional restrictions. This is
    // synthetic metadata only, not an inspection of user secrets.
    assert!(File::open("/ordinary-outside").is_ok());
    assert_eq!(
        File::open("/protected-test").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    drop(std::net::TcpListener::bind("0.0.0.0:0")?);
    // Bind-target placeholders must not masquerade as a selected input.
    if fs::metadata("/selected-document")?.len() != 28 {
        return Err("Required synthetic document is missing".into());
    }
    let selected = |path: &str, kind| {
        NativeDescriptorRule::capture(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )?,
            kind,
        )
    };
    let evidence = restrict_native_disconnected(
        "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0",
        vec![
            selected("/usr", NativeRuleKind::ReadCodeTree)?,
            selected("/work", NativeRuleKind::PrivateScratch)?,
            selected("/selected-document", NativeRuleKind::SelectedReadFile)?,
            selected("/dev/null", NativeRuleKind::NullDevice)?,
        ],
    )?;
    assert_eq!(evidence.landlock_abi, 9);
    assert!(evidence.seccomp && evidence.no_new_privileges);
    assert_eq!(std::thread::spawn(|| 42).join().unwrap(), 42);
    assert!(
        !Command::new("/usr/bin/unshare")
            .args(["--user", "/usr/bin/true"])
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success()
    );
    status_file.rewind()?;
    status.clear();
    status_file.read_to_string(&mut status)?;
    if !status.lines().any(|line| line == "Seccomp:\t2")
        || !status.lines().any(|line| line == "NoNewPrivs:\t1")
    {
        return Err("Required seccomp/privilege state is missing".into());
    }
    drop(status_file);
    assert_eq!(
        File::open("/ordinary-outside").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        File::open("/protected-test").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let mut document = String::new();
    File::open("/selected-document")?.read_to_string(&mut document)?;
    assert_eq!(document, "synthetic selected document\n");
    fs::write("/work/inside.txt", b"synthetic output\n")?;
    assert_eq!(fs::read("/work/inside.txt")?, b"synthetic output\n");
    assert_eq!(
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM)
    );
    // Fixed child executables and fixed synthetic paths only. Verify restrictions
    // survive exec; neither a worker start nor a scope alone proves inheritance.
    let child = |path: &str| {
        Command::new("/usr/bin/cat")
            .arg(path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
    assert!(child("/selected-document")?.success());
    assert!(!child("/ordinary-outside")?.success());
    assert!(!child("/protected-test")?.success());
    fs::write(
        "/work/application-started",
        b"synthetic launch established\n",
    )?;
    println!(
        "{{\"schema\":\"greyward.application-security.native-restrictions-probe/v1\",\"passed\":true,\"profile_claimed\":false,\"requested_landlock_abi\":9,\"private_namespaces_verified\":true,\"child_exec_denials_verified\":true}}"
    );
    Ok(())
}

fn main() {
    if let Err(error) = probe() {
        eprintln!("Native worker probe unavailable; execution refused: {error}");
        std::process::exit(1);
    }
}
