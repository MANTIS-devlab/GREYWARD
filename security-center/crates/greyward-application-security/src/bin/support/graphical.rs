//! Trusted nested display supervisor. The application receives a separate
//! mount/PID/network namespace containing only the nested display endpoint.
use std::fs;
use std::io::{BufRead, Read};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn supervise(arguments: &[String]) -> Result<i32> {
    for name in ["scratch", "display", "host", "config", "tmp"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(format!("/work/{name}"))
            .map_err(|_| "Private display directory preparation failed")?;
    }
    // Explicit non-executing bindings prevent Labwc from loading launcher,
    // menu or terminal shortcuts into the trusted supervisor's namespace.
    fs::write(
        "/work/config/rc.xml",
        r#"<labwc_config>
<keyboard><keybind key="A-F4"><action name="Close"/></keybind></keyboard>
<mouse><context name="Titlebar"><mousebind button="Left" action="Drag"><action name="Move"/></mousebind></context><context name="Client"><mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind></context></mouse>
<core><decoration>server</decoration></core></labwc_config>"#,
    )?;
    fs::write("/work/config/menu.xml", "<openbox_menu/>\n")?;
    fs::write("/work/config/autostart", "#!/bin/sh\n")?;
    let mut helper = OwnedChild(
        Command::new("/usr/libexec/greyward-wayland-context")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Private display helper execution failed")?,
    );
    let mut readiness = String::new();
    std::io::BufReader::new(
        helper
            .0
            .stdout
            .take()
            .ok_or("Display helper pipe missing")?,
    )
    .take(128)
    .read_line(&mut readiness)?;
    if readiness != "GREYWARD_PRIVATE_DISPLAY_READY_V1\n" {
        return Err("Private display handoff failed".into());
    }
    let encoded = serde_json::to_string(arguments)?;
    let mut compositor = OwnedChild(
        Command::new("/usr/bin/labwc")
            .args([
                "-C",
                "/work/config",
                "-S",
                "/usr/libexec/greyward-native-worker --prepared-graphical-entry",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/work/scratch")
            .env("XDG_RUNTIME_DIR", "/work/display")
            .env("XDG_CONFIG_HOME", "/work/config")
            .env("WAYLAND_DISPLAY", "/work/host/context.sock")
            .env("WLR_BACKENDS", "wayland")
            .env("WLR_RENDERER", "pixman")
            .env("WLR_WL_OUTPUTS", "1")
            .env("LABWC_WL_WINDOW_TITLE", "GREYWARD — ISOLATED")
            .env("GREYWARD_APPLICATION_ARGS", encoded)
            .env("GREYWARD_PAYLOAD", std::env::var("GREYWARD_PAYLOAD")?)
            .env(
                "GREYWARD_SELECTED_DOCUMENT",
                std::env::var("GREYWARD_SELECTED_DOCUMENT").unwrap_or_default(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Private nested compositor execution failed")?,
    );
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if fs::read_to_string("/work/scratch/.guard-client-ready")
            .ok()
            .as_deref()
            == Some("PRIVATE_DISPLAY_ISOLATION_READY_V1\n")
        {
            break;
        }
        if compositor.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("Private application display readiness failed".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    println_stderr_ready()?;
    compositor.0.wait()?;
    let code: i32 = fs::read_to_string("/work/scratch/.guard-client-exit")?
        .trim()
        .parse()?;
    if !(0..=255).contains(&code) {
        return Err("Invalid application exit readback".into());
    }
    Ok(code)
}
fn println_stderr_ready() -> Result<()> {
    use std::io::Write;
    writeln!(std::io::stderr(), "GREYWARD_ISOLATED_WORKER_READY_V1")?;
    std::io::stderr().flush()?;
    Ok(())
}
pub fn entry() -> Result<i32> {
    if !(1000..60000).contains(&rustix::process::getuid().as_raw())
        || rustix::process::getuid() != rustix::process::geteuid()
        || fs::read_to_string("/proc/self/attr/current")?.trim_end_matches(['\n', '\0'])
            != super::CONTEXT
    {
        return Err("Prepared graphical entry is unavailable".into());
    }
    let display = std::env::var("WAYLAND_DISPLAY")?;
    if !display.starts_with("wayland-")
        || !display[8..].bytes().all(|b| b.is_ascii_digit())
        || display.len() > 32
    {
        return Err("Invalid private display name".into());
    }
    let socket = fs::symlink_metadata(format!("/work/display/{display}"))?;
    if !socket.file_type().is_socket() || socket.uid() != rustix::process::getuid().as_raw() {
        return Err("Private display socket missing".into());
    }
    let mut command = client_command(&display)?;
    let payload = std::env::var("GREYWARD_PAYLOAD")?;
    for (required, path) in [
        (
            matches!(payload.as_str(), "PYTHON" | "SHELL"),
            "/run/guard-interpreter",
        ),
        (
            std::env::var("GREYWARD_SELECTED_DOCUMENT").ok().as_deref() == Some("1"),
            "/run/guard-document",
        ),
    ] {
        if required {
            if fs::metadata(path)
                .map_err(|_| "Private interpreter/document mount missing")?
                .len()
                == 0
            {
                return Err("Private interpreter/document mount empty".into());
            }
            command.args(["--ro-bind", path, path]);
        }
    }
    // This directory is from the private supervisor namespace, never host X11.
    if let Ok(display) = std::env::var("DISPLAY") {
        if display.starts_with(':')
            && display[1..].bytes().all(|b| b.is_ascii_digit())
            && fs::symlink_metadata("/tmp/.X11-unix")
                .is_ok_and(|m| m.is_dir() && m.uid() == rustix::process::getuid().as_raw())
        {
            fs::set_permissions("/tmp/.X11-unix", fs::Permissions::from_mode(0o700))?;
            // A nested user namespace cannot remount its parent's tmpfs with
            // new read-only flags. This is the private nested server directory;
            // Landlock still bounds access and no host X11 endpoint is present.
            command.args([
                "--bind",
                "/tmp/.X11-unix",
                "/tmp/.X11-unix",
                "--setenv",
                "DISPLAY",
                &display,
            ]);
        }
    }
    let status = command
        .args([
            "--chdir",
            "/work",
            "--",
            "/usr/libexec/greyward-native-worker",
            "--prepared-graphical-client",
        ])
        .status()?;
    let code = status.code().unwrap_or(125);
    fs::write("/work/scratch/.guard-client-exit", code.to_string())?;
    Ok(code)
}

fn client_command(display: &str) -> Result<Command> {
    let mut command = Command::new("/usr/bin/bwrap");
    command
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--as-pid-1",
            "--cap-drop",
            "ALL",
            "--uid",
            &rustix::process::getuid().as_raw().to_string(),
            "--gid",
            &rustix::process::getgid().as_raw().to_string(),
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/run",
            "--dir",
            "/etc",
            "--ro-bind",
            "/etc/passwd",
            "/etc/passwd",
            "--ro-bind",
            "/etc/group",
            "/etc/group",
            "--ro-bind",
            "/etc/fonts",
            "/etc/fonts",
            "--bind",
            "/work/scratch",
            "/work",
            "--bind",
            "/work/display",
            "/run/display",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/work",
            "--setenv",
            "XDG_RUNTIME_DIR",
            "/run/display",
            "--setenv",
            "WAYLAND_DISPLAY",
        ])
        .arg(display);
    for name in [
        "GREYWARD_PAYLOAD",
        "GREYWARD_APPLICATION_ARGS",
        "GREYWARD_SELECTED_DOCUMENT",
    ] {
        let value = std::env::var(name).unwrap_or_default();
        command.args(["--setenv", name, &value]);
    }
    for namespace in ["mnt", "pid", "net", "user"] {
        let value = fs::read_link(format!("/proc/self/ns/{namespace}"))?;
        command.args([
            "--setenv",
            &format!("GREYWARD_HOST_NS_{}", namespace.to_uppercase()),
            value.to_str().ok_or("Invalid namespace")?,
        ]);
    }
    Ok(command)
}
