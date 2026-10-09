//! Explicit opt-in development provider; no path/UID/context overrides.
fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(2);
    }
    if greyward_application_security::serve_development().is_err() {
        eprintln!("Application Security development provider unavailable; no fallback");
        std::process::exit(1);
    }
}
