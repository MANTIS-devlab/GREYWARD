//! Fixed read-only entrypoint; no GUI initialization or arbitrary command input.
fn main() {
    let snapshot = greyward_security_backends::collect_core_snapshot();
    println!("{}", greyward_security_backends::posture_digest(&snapshot));
}
