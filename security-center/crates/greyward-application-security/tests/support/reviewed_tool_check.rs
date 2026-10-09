//! Fixed synthetic tool; never included in the runtime RPM or production UI.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
const RESOURCE: &str = "/home/greyward-guard-probe/registration-critical/synthetic";
fn main() {
    assert_eq!(rustix::process::getuid().as_raw(), 1002);
    let context = fs::read_to_string("/proc/self/attr/current").unwrap();
    let kind = context.split(':').nth(2).unwrap();
    assert!(kind.starts_with("greyward_as_grant_") && kind.ends_with("_t"));
    let status = fs::read_to_string("/proc/self/status").unwrap();
    assert!(
        status
            .lines()
            .any(|line| line == "CapEff:\t0000000000000000")
    );
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    let mut held = File::open(RESOURCE).unwrap();
    held.read_exact(&mut [0u8; 1]).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(RESOURCE).is_err());
    assert!(
        !Command::new("/usr/bin/cat")
            .arg(RESOURCE)
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    match std::env::args().nth(1).as_deref() {
        Some("--fixed-read") => println!("REVIEWED_READ_ALLOWED_CHILD_DENIED"),
        Some("--held-revocation") => {
            println!("GRANT_READY");
            std::io::stdout().flush().unwrap();
            std::io::stdin().read_exact(&mut [0u8; 1]).unwrap();
            assert_eq!(
                held.read(&mut [0u8; 1]).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                File::open(RESOURCE).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            println!("HELD_DESCRIPTOR_REVOKED");
        }
        _ => panic!("Only fixed development modes are supported"),
    }
}
