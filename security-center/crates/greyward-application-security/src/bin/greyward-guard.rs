//! User-side typed CLI. It cannot execute root commands or select contexts.
use greyward_application_security::{GuardClient, WorkflowPreview};
use greyward_security_domain::SecurityReference;
use std::io::{self, Write};
use std::time::{Duration, Instant};

fn reference(
    value: &str,
    namespace: &str,
) -> Result<SecurityReference, Box<dyn std::error::Error>> {
    let reference = SecurityReference::try_from(value.to_owned())?;
    if reference.namespace() != namespace {
        return Err("Wrong reference namespace".into());
    }
    Ok(reference)
}
fn apply(
    client: &GuardClient,
    preview: &WorkflowPreview,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(preview)?);
    if matches!(preview, WorkflowPreview::Grant { .. }) {
        println!(
            "This is persistent raw read access. Extensions and code running inside the tool share it. Revocation cannot recall already-read data."
        );
    }
    print!("Apply this reviewed change? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y") {
        return Err("Review declined; no policy change applied".into());
    }
    client.apply(preview.operation_ref(), true)?;
    let result = client.wait_operation(
        preview.operation_ref(),
        Instant::now() + Duration::from_secs(100),
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let development = arguments.first().is_some_and(|v| v == "--development");
    if development {
        arguments.remove(0);
    }
    if arguments.as_slice() == ["desktop-proxy"] && !development {
        // UWSM owns ordinary desktop services. This socket lifetime is only a
        // startup/shutdown signal; root kernel readback establishes protection.
        let uid = rustix::process::getuid().as_raw();
        let mut socket =
            std::os::unix::net::UnixStream::connect(format!("/run/user/{uid}/wayland-0"))?;
        if !std::process::Command::new("/usr/bin/uwsm")
            .arg("finalize")
            .args(["XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP"])
            .env("WAYLAND_DISPLAY", format!("/run/user/{uid}/wayland-0"))
            .env("XDG_CURRENT_DESKTOP", "GREYWARD:Labwc")
            .env("XDG_SESSION_DESKTOP", "greyward-labwc")
            .status()?
            .success()
        {
            return Err("Desktop startup failed".into());
        }
        let _ = std::io::copy(&mut socket, &mut std::io::sink());
        return Ok(0);
    }
    let client = GuardClient::connect(development)?;
    match arguments.as_slice() {
        [command] if command == "lock" && !development => { if !client.session_lock(true)? { return Err("Lock unavailable".into()); } }
        [command] if command == "lock-status" && !development => println!("{}", client.session_lock(false)?),
        [command] if command == "desktop-session" && !development => {
            client.start_desktop()?;
            let uid = rustix::process::getuid().as_raw();
            let status = std::process::Command::new("/usr/bin/uwsm")
                .args(["start", "-F", "-e", "-D", "GREYWARD:Labwc", "--", "/usr/bin/greyward-guard", "desktop-proxy"])
                .env("WAYLAND_DISPLAY", format!("/run/user/{uid}/wayland-0"))
                .env("XDG_SESSION_DESKTOP", "greyward-labwc").status()?;
            return Ok(status.code().unwrap_or(1));
        }
        [command] if command=="coverage"=>println!("{}",serde_json::to_string_pretty(&client.coverage()?)?),
        [command] if command=="resources"=>println!("{}",serde_json::to_string_pretty(&client.resources()?)?),
        [command,action,path] if command=="resource" && action=="register"=>{
            let descriptor=rustix::fs::open(path,rustix::fs::OFlags::PATH|rustix::fs::OFlags::DIRECTORY
                |rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::CLOEXEC,rustix::fs::Mode::empty())?;
            let revision=client.resources()?.policy_revision;
            let preview=client.preview_registration(descriptor.into(),"CUSTOM","Custom protected directory",revision)?;
            println!("Selected directory: {path}");apply(&client,&preview)?;
        }
        [command,action,path,resource] if command=="grant" && action=="review"=>{
            let resource=reference(resource,"resource")?;
            let preview=client.preview_grant(path,&[resource],client.resources()?.policy_revision)?;
            apply(&client,&preview)?;
        }
        [command,action,grant,path] if command=="grant" && action=="revoke"=>{
            let grant=reference(grant,"grant")?;
            let preview=client.preview_revoke(&grant,path,client.resources()?.policy_revision)?;
            apply(&client,&preview)?;
        }
        [command,separator,path,remaining @ ..] if command=="run" && separator=="--"=>{
            eprintln!("Isolated native/script/Type-2 AppImage launch: private home, network off, no Protected Data grant. No unrestricted fallback.");
            let descriptor=rustix::fs::open(path,rustix::fs::OFlags::PATH|rustix::fs::OFlags::NOFOLLOW
                |rustix::fs::OFlags::CLOEXEC,rustix::fs::Mode::empty())?;
            let launch=client.prepare_isolated(descriptor.into(),remaining.to_vec())?;
            return execute(&client,&launch);
        }
        [command,option,separator,path,remaining @ ..] if command=="run" && option=="--graphical" && separator=="--"=>{
            let descriptor=rustix::fs::open(path,rustix::fs::OFlags::PATH|rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::CLOEXEC,rustix::fs::Mode::empty())?;
            let launch=client.prepare_graphical(descriptor.into(),remaining.to_vec())?;
            return execute(&client,&launch);
        }
        [command,option,grant,separator,path,remaining @ ..] if command=="run" && option=="--grant" && separator=="--"=>{
            let grant=reference(grant,"grant")?;
            let launch=client.prepare_launch(&grant,path,remaining.to_vec())?;
            return execute(&client,&launch);
        }
        _=>return Err("Usage: greyward-guard [--development] coverage | resources | resource register DIR | grant review /usr/EXEC RESOURCE_REF | grant revoke GRANT_REF /usr/EXEC | run [--graphical] -- FILE [ARGS] | run --grant GRANT_REF -- /usr/EXEC [ARGS]".into()),
    }
    Ok(0)
}
fn execute(
    client: &GuardClient,
    launch: &SecurityReference,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (mut input, mut output, mut error) = client.start_launch(launch)?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin(), &mut input);
    });
    let stderr = std::thread::spawn(move || io::copy(&mut error, &mut io::stderr()));
    io::copy(&mut output, &mut io::stdout())?;
    stderr
        .join()
        .map_err(|_| "Application stderr transport failed")??;
    Ok(client.wait_launch(launch, Instant::now() + Duration::from_secs(3660))?)
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Guard: {error}");
            std::process::exit(1);
        }
    }
}
