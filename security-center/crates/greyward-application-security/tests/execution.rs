use greyward_application_security::{BusPeerCredentials, ExecutionHandle};
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn credentials(pid: u32) -> BusPeerCredentials {
    let process = Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
    BusPeerCredentials {
        uid: rustix::process::getuid().as_raw(),
        pid,
        selinux_label: std::fs::read_to_string(format!("/proc/{pid}/attr/current"))
            .unwrap()
            .trim_end_matches(['\0', '\n'])
            .to_owned(),
        process_fd: pidfd_open(process, PidfdFlags::NONBLOCK).unwrap(),
    }
}

struct ChildFixture(Child);
impl Drop for ChildFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_real_pidfd_resolves_the_live_peer_without_guessing_an_application() {
    let handle = ExecutionHandle::capture(credentials(std::process::id())).unwrap();
    assert_eq!(handle.identity().pid, std::process::id());
    assert!(handle.identity().installation_ref.is_none());
    handle.revalidate().unwrap();
}

#[test]
fn wrong_uid_context_pid_and_non_process_descriptors_are_refused() {
    let mut input = credentials(std::process::id());
    input.uid = input.uid.checked_add(1).unwrap();
    assert!(ExecutionHandle::capture(input).is_err());
    let mut input = credentials(std::process::id());
    input.selinux_label = "unconfined_u:unconfined_r:forged_t:s0".into();
    assert!(ExecutionHandle::capture(input).is_err());
    let mut input = credentials(std::process::id());
    input.pid = input.pid.checked_add(1).unwrap();
    assert!(ExecutionHandle::capture(input).is_err());
    let mut input = credentials(std::process::id());
    input.process_fd = File::open("/dev/null").unwrap().into();
    assert!(ExecutionHandle::capture(input).is_err());
}

#[test]
fn exit_invalidates_a_held_execution_and_stale_credentials() {
    let mut child = ChildFixture(Command::new("/usr/bin/sleep").arg("30").spawn().unwrap());
    let stale = credentials(child.0.id());
    let handle = ExecutionHandle::capture(credentials(child.0.id())).unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(handle.revalidate().is_err());
    assert!(ExecutionHandle::capture(stale).is_err());
}

#[test]
fn exec_to_another_object_invalidates_a_preview_peer() {
    let mut child = ChildFixture(
        Command::new("/bin/sh")
            .args([
                "-c",
                "printf 'ready\\n'; read -r step; exec /usr/bin/sleep 30",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "ready\n");
    let handle = ExecutionHandle::capture(credentials(child.0.id())).unwrap();
    writeln!(child.0.stdin.as_mut().unwrap(), "continue").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while handle.revalidate().is_ok() {
        assert!(
            Instant::now() < deadline,
            "Changed executable retained its peer identity"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
