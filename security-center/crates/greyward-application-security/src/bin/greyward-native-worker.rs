//! Disposable disconnected worker. It has no root privileges and accepts only
//! the fixed private mount target established by the broker. Errors exit before
//! application execution; this command never enrolls a session or grants access.
use greyward_application_security::{
    NativeDescriptorRule, NativeRuleKind, restrict_native_disconnected,
    restrict_native_private_display,
};
use std::fs;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const CONTEXT: &str = "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0";
#[path = "support/graphical.rs"]
mod graphical;
fn verify_environment() -> Result<(), Box<dyn std::error::Error>> {
    for namespace in ["mnt", "pid", "net", "user"] {
        let host = std::env::var(format!("GREYWARD_HOST_NS_{}", namespace.to_uppercase()))?;
        if host.is_empty()
            || fs::read_link(format!("/proc/self/ns/{namespace}"))?.to_str() == Some(host.as_str())
        {
            return Err("Required private namespace is missing".into());
        }
    }
    if fs::read_to_string("/proc/self/uid_map")?
        .lines()
        .any(|line| line.split_whitespace().last() != Some("1"))
    {
        return Err("Broad user mapping is refused".into());
    }
    // PID 1 closes arbitrary service descriptors. Check that only stdio survives
    // before creating our own CLOEXEC rule descriptors. The directory iterator
    // closes before checking whether its temporary descriptor still exists.
    let descriptors: Vec<_> = fs::read_dir("/proc/self/fd")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<_, _>>()?;
    for name in descriptors {
        if name.to_string_lossy().parse::<u32>().is_ok_and(|fd| fd > 2)
            && fs::symlink_metadata(Path::new("/proc/self/fd").join(&name)).is_ok()
        {
            return Err("Unexpected inherited descriptor".into());
        }
    }
    Ok(())
}
fn install_restrictions(graphical: bool, kind: &str) -> Result<(), Box<dyn std::error::Error>> {
    let rule = |path: &str, kind| -> Result<NativeDescriptorRule, Box<dyn std::error::Error>> {
        let kind = match (graphical, kind) {
            (true, NativeRuleKind::ReadCodeTree) => NativeRuleKind::NamespaceCodeTree,
            (true, NativeRuleKind::ReadCodeFile) => NativeRuleKind::NamespaceCodeFile,
            (_, kind) => kind,
        };
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?;
        NativeDescriptorRule::capture(descriptor, kind).map_err(Into::into)
    };

    fs::DirBuilder::new().mode(0o700).create("/work/tmp")?;
    let selected_document =
        std::env::var("GREYWARD_SELECTED_DOCUMENT").ok().as_deref() == Some("1");
    let mut rules = vec![
        rule("/usr", NativeRuleKind::ReadCodeTree)?,
        rule("/work", NativeRuleKind::PrivateScratch)?,
        rule("/dev/null", NativeRuleKind::NullDevice)?,
    ];
    if matches!(kind, "PYTHON" | "SHELL") {
        rules.push(rule(
            "/run/guard-interpreter",
            NativeRuleKind::ReadCodeFile,
        )?);
    }
    if selected_document {
        rules.push(rule(
            "/run/guard-document",
            NativeRuleKind::SelectedReadFile,
        )?);
    }
    if graphical {
        rules.push(rule("/run/display", NativeRuleKind::PrivateScratch)?);
        rules.push(rule("/etc/fonts", NativeRuleKind::ReadCodeTree)?);
        rules.push(rule("/etc/passwd", NativeRuleKind::SelectedReadFile)?);
        rules.push(rule("/etc/group", NativeRuleKind::SelectedReadFile)?);
        if fs::metadata("/tmp/.X11-unix").is_ok() {
            rules.push(rule("/tmp/.X11-unix", NativeRuleKind::PrivateDisplay)?);
        }
    }
    let evidence = if graphical {
        restrict_native_private_display(CONTEXT, rules)?
    } else {
        restrict_native_disconnected(CONTEXT, rules)?
    };
    if evidence.landlock_abi != 9 || !evidence.seccomp || !evidence.no_new_privileges {
        return Err("Required restriction readback is missing".into());
    }
    Ok(())
}
fn payload_command(kind: &str) -> Result<Command, Box<dyn std::error::Error>> {
    let application = match kind {
        "ELF" => Command::new("/usr/libexec/greyward-guard-entry"),
        "PYTHON" | "SHELL" => {
            let mut command = Command::new("/run/guard-interpreter");
            if kind == "PYTHON" {
                command.args(["-I", "-B"]);
            }
            command.arg("/usr/libexec/greyward-guard-entry");
            command
        }
        value if value.starts_with("APPIMAGE:") => {
            let offset: u64 = value[9..].parse()?;
            if offset < 64 {
                return Err("Invalid prepared AppImage offset".into());
            }
            let extracted = Command::new("/usr/bin/unsquashfs")
                .args([
                    "-no-progress",
                    "-no-xattrs",
                    "-processors",
                    "1",
                    "-d",
                    "/work/app",
                    "-o",
                ])
                .arg(offset.to_string())
                .arg("/usr/libexec/greyward-guard-entry")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()?;
            if !extracted.success() {
                return Err("Confined AppImage extraction failed".into());
            }
            let entry = fs::canonicalize("/work/app/AppRun")?;
            if !entry.starts_with("/work/app") || !fs::metadata(&entry)?.is_file() {
                return Err("AppImage entrypoint escaped its private directory".into());
            }
            let mut command = Command::new(entry);
            command
                .env("APPDIR", "/work/app")
                .env("APPIMAGE", "/usr/libexec/greyward-guard-entry");
            command
        }
        _ => return Err("Unsupported prepared payload".into()),
    };
    Ok(application)
}
fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() == ["--prepared-graphical-entry"] {
        return graphical::entry();
    }
    let graphical = arguments.first().map(String::as_str) == Some("--prepared-graphical-client");
    if arguments.first().map(String::as_str) != Some("--prepared-isolation")
        && arguments.first().map(String::as_str) != Some("--prepared-graphical")
        && !graphical
    {
        return Err("Prepared worker mode missing".into());
    }
    if arguments.len() > 33
        || !(1000..60000).contains(&rustix::process::getuid().as_raw())
        || rustix::process::getpid().as_raw_nonzero().get() != 1
    {
        return Err("Prepared private worker prerequisites are missing".into());
    }
    if arguments.first().map(String::as_str) == Some("--prepared-graphical") {
        return graphical::supervise(&arguments[1..]);
    }
    if graphical {
        let mut prepared: Vec<String> =
            serde_json::from_str(&std::env::var("GREYWARD_APPLICATION_ARGS")?)?;
        if prepared.len() > 32 || prepared.iter().map(String::len).sum::<usize>() > 8192 {
            return Err("Invalid prepared arguments".into());
        }
        arguments.truncate(1);
        arguments.append(&mut prepared);
        for path in [
            "/run/guard-host-wayland",
            "/work/host",
            "/work/display",
            "/run/user",
        ] {
            if fs::symlink_metadata(path).is_ok() {
                return Err("Host display namespace exposure refused".into());
            }
        }
    }
    verify_environment()?;
    let kind = std::env::var("GREYWARD_PAYLOAD")?;
    install_restrictions(graphical, &kind)?;
    let mut application = payload_command(&kind)?;
    application
        .args(&arguments[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/work")
        .env("TMPDIR", "/work")
        .env("LANG", "C.UTF-8")
        .current_dir("/work");
    if kind.starts_with("APPIMAGE:") {
        application
            .env("APPDIR", "/work/app")
            .env("APPIMAGE", "/usr/libexec/greyward-guard-entry");
    }
    if graphical {
        application
            .env("XDG_RUNTIME_DIR", "/run/display")
            .env("WAYLAND_DISPLAY", std::env::var("WAYLAND_DISPLAY")?)
            .env("GDK_BACKEND", "wayland,x11")
            .env("QT_QPA_PLATFORM", "wayland;xcb")
            .env("GIO_USE_VFS", "local");
        if let Ok(display) = std::env::var("DISPLAY") {
            application.env("DISPLAY", display);
        }
        fs::write(
            "/work/.guard-client-ready",
            "PRIVATE_DISPLAY_ISOLATION_READY_V1\n",
        )?;
    }
    // Root reads this bounded first line before returning application streams.
    // Application output cannot forge readiness before this trusted worker exec.
    writeln!(std::io::stderr(), "GREYWARD_ISOLATED_WORKER_READY_V1")?;
    std::io::stderr().flush()?;
    let error = application.exec();
    Err(error.into())
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Native isolation unavailable: {error}");
            std::process::exit(125);
        }
    }
}
